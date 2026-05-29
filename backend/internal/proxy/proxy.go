// Package proxy implements an HTTP intercepting proxy that captures all
// requests and responses flowing through it, stores them for later analysis,
// and supports replaying any captured request with optional header and body
// overrides (à la Burp Suite Repeater).
//
// Architecture:
//   - Server.ServeHTTP handles both plain-HTTP forwarding and HTTPS CONNECT tunnelling.
//   - Plain HTTP requests are fully captured (request + response headers and bodies).
//   - HTTPS CONNECT tunnels are passed through transparently; only the tunnel
//     establishment is recorded (no decryption without a CA certificate).
//   - All captured requests are persisted through a Store interface; the
//     default implementation is Postgres-backed (storage.Postgres).
//   - Replay sends a new HTTP request to the original URL using the original
//     headers/body, optionally overridden by the caller.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"

	"github.com/google/uuid"
)

// maxCaptureBody is the maximum number of bytes retained from a request or
// response body for storage to keep persistence bounded. Bodies larger than
// this are forwarded in full to the destination but truncated for capture.
const maxCaptureBody = 128 * 1024

// maxForwardBody is the maximum number of bytes read into memory when
// forwarding a request or response body through the proxy. This bounds
// memory usage while still being large enough for typical web traffic.
const maxForwardBody = 50 * 1024 * 1024

// truncateForCapture returns up to maxCaptureBody bytes from b for storage.
func truncateForCapture(b []byte) []byte {
	if len(b) <= maxCaptureBody {
		return b
	}
	return b[:maxCaptureBody]
}

// Store is the persistence interface used by the proxy.
type Store interface {
	SaveProxyRequest(ctx context.Context, req *model.ProxyRequest) error
	ListProxyRequests(ctx context.Context) ([]*model.ProxyRequest, error)
	GetProxyRequest(ctx context.Context, id string) (*model.ProxyRequest, error)
	ClearProxyRequests(ctx context.Context) error
}

// Server is an HTTP intercepting proxy. It implements http.Handler so it can
// be plugged into any net/http server.
type Server struct {
	store        Store
	transport    *http.Transport
	ca           *CA
	mu           sync.Mutex
	passiveStore *PassiveScanStore
}

// NewServer creates a new intercepting proxy backed by the provided Store.
func NewServer(store Store) *Server {
	return NewServerWithCA(store, nil)
}

// NewServerWithCA creates a new intercepting proxy backed by the provided
// Store. When ca is non-nil, HTTPS CONNECT tunnels are intercepted ("MITM")
// so request and response bodies can be captured. When ca is nil, CONNECT
// tunnels are passed through transparently.
func NewServerWithCA(store Store, ca *CA) *Server {
	return &Server{
		store: store,
		ca:    ca,
		transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
	}
}

// CA returns the configured certificate authority, or nil when HTTPS
// interception is disabled.
func (s *Server) CA() *CA { return s.ca }

// MITMEnabled reports whether HTTPS CONNECT tunnels are intercepted.
func (s *Server) MITMEnabled() bool { return s != nil && s.ca != nil }

// Store returns the underlying persistence store.
func (s *Server) Store() Store {
	return s.store
}

// SetPassiveScanStore attaches a passive scan store to the proxy server.
// Every HTTP request captured by the server is analysed and any new
// deduplicated findings are recorded. Safe to call with nil to disable
// passive scanning.
func (s *Server) SetPassiveScanStore(store *PassiveScanStore) {
	s.passiveStore = store
}

// PassiveStore returns the passive scan store, or nil if none is configured.
func (s *Server) PassiveStore() *PassiveScanStore {
	return s.passiveStore
}

// AnalyzeResponse passively analyses a raw HTTP response and records any
// findings in the passive scan store. Intended for callers (e.g. the proxy
// browse endpoint) that record traffic via RecordingTransport rather than
// through handleHTTP. This method is nil-safe.
func (s *Server) AnalyzeResponse(rawURL string, status int, respHeader http.Header, respBody []byte) {
	if s == nil || s.passiveStore == nil {
		return
	}
	pr := &model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             rawURL,
		ResponseStatus:  status,
		ResponseHeaders: flattenHeaders(respHeader),
		ResponseBody:    string(respBody),
	}
	s.passiveStore.Analyze(pr)
}

// ServeHTTP dispatches to handleHTTP (plain) or handleTunnel (CONNECT).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleTunnel(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// handleHTTP forwards a plain-HTTP request, capturing request + response.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Ensure the request has an absolute URL.
	if r.URL.Host == "" {
		http.Error(w, "proxy requires absolute URL", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "unsupported scheme", http.StatusBadRequest)
		return
	}
	if err := safety.ValidateOutboundURL(r.URL.String()); err != nil {
		http.Error(w, "blocked by outbound safety policy", http.StatusForbidden)
		return
	}

	// Read the full request body (bounded by maxForwardBody) so it can be
	// forwarded intact upstream; a truncated copy is captured for storage.
	var reqBodyBytes []byte
	if r.Body != nil {
		reqBodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, maxForwardBody))
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
	}

	// Build outbound request.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), bytes.NewReader(reqBodyBytes))
	if err != nil {
		http.Error(w, "failed to build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	// Forward to destination.
	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		s.captureError(r, reqBodyBytes, err)
		return
	}
	defer resp.Body.Close()

	// Read full response body (bounded) so the client gets complete bytes.
	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxForwardBody))

	// Write response back to client.
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBodyBytes)

	// Persist captured pair asynchronously (truncated for storage).
	captured := &model.ProxyRequest{
		ID:              uuid.NewString(),
		CapturedAt:      time.Now().UTC(),
		Method:          r.Method,
		URL:             r.URL.String(),
		RequestHeaders:  flattenHeaders(r.Header),
		RequestBody:     string(truncateForCapture(reqBodyBytes)),
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: flattenHeaders(resp.Header),
		ResponseBody:    string(truncateForCapture(respBodyBytes)),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.SaveProxyRequest(ctx, captured)
		if s.passiveStore != nil {
			s.passiveStore.Analyze(captured)
		}
	}()
}

// handleTunnel handles CONNECT requests (HTTPS tunnelling). The proxy
// connects to the destination host and then pipes bytes in both directions.
// No TLS decryption is performed — the raw tunnel is recorded.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}

	// Validate host to prevent SSRF.
	u, err := url.Parse("https://" + host)
	if err != nil || u.Hostname() == "" {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	if err := safety.ValidateHostname(u.Hostname()); err != nil {
		http.Error(w, "blocked by outbound safety policy", http.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, "cannot reach destination: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	// Acknowledge the CONNECT to the client.
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// HTTPS interception ("MITM") path: terminate the client's TLS
	// using a leaf certificate signed by our CA, then forward decrypted
	// requests/responses through handleHTTP so they get captured fully.
	if s.ca != nil {
		if err := s.handleTunnelMITM(clientConn, host, destConn); err != nil {
			s.captureMITMError(host, err)
		}
		return
	}

	// Pass-through tunnel path (no CA configured). destConn is already
	// deferred above; do not defer it again.

	// Record the tunnel (no body content available without MitM).
	captured := &model.ProxyRequest{
		ID:         uuid.NewString(),
		CapturedAt: time.Now().UTC(),
		Method:     "CONNECT",
		URL:        "https://" + host,
		RequestHeaders: map[string]string{
			"Host": host,
		},
		RequestBody:     "",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{},
		ResponseBody:    "(HTTPS tunnel — body not captured without MitM CA certificate)",
		Notes:           "HTTPS CONNECT tunnel established. Configure PROXY_CA_CERT_FILE/PROXY_CA_KEY_FILE to enable TLS interception.",
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.SaveProxyRequest(ctx, captured)
	}()

	// Pipe bytes bidirectionally. When either copy finishes (EOF or
	// error), close both connections so the other goroutine unblocks
	// and we don't leak the tunnel until the idle side times out.
	closeBoth := func() {
		_ = clientConn.Close()
		_ = destConn.Close()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(destConn, clientConn)
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, destConn)
		closeBoth()
	}()
	wg.Wait()
}

// handleTunnelMITM intercepts an HTTPS CONNECT tunnel: it terminates the
// client's TLS using a leaf certificate signed by the configured CA, dials
// the upstream over real TLS, and proxies decrypted HTTP requests/responses
// while capturing the full request and response bodies.
//
// destConn is the already-established TCP connection to the upstream host
// (left un-TLS'd intentionally so we can dial TLS on top of it).
func (s *Server) handleTunnelMITM(clientConn net.Conn, host string, destConn net.Conn) error {
	// Drop the upstream TCP connection — we'll redial it as a TLS client
	// when the first decrypted request arrives, so SNI/ALPN match the
	// client request.
	_ = destConn.Close()

	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}
	leaf, err := s.ca.LeafCertificate(hostname)
	if err != nil {
		return fmt.Errorf("mint leaf certificate for %s: %w", hostname, err)
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	defer tlsConn.Close()

	clientReader := bufio.NewReader(tlsConn)
	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read decrypted request: %w", err)
		}

		// Reconstruct absolute URL from Host + RequestURI.
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = req.Host
			if req.URL.Host == "" {
				req.URL.Host = host
			}
		}

		if err := s.proxyDecryptedRequest(tlsConn, req); err != nil {
			return err
		}

		if req.Close || req.Header.Get("Connection") == "close" {
			return nil
		}
	}
}

// proxyDecryptedRequest sends a decrypted request to its real upstream over
// TLS, captures the request/response pair, and writes the response back to
// the client over the existing TLS connection.
func (s *Server) proxyDecryptedRequest(clientTLS net.Conn, req *http.Request) error {
	defer func() {
		if req.Body != nil {
			_ = req.Body.Close()
		}
	}()

	if err := safety.ValidateOutboundURL(req.URL.String()); err != nil {
		writeProxyError(clientTLS, http.StatusForbidden, "blocked by outbound safety policy")
		return nil
	}

	// Read full request body (bounded) so it forwards intact upstream.
	var reqBodyBytes []byte
	if req.Body != nil {
		reqBodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, maxForwardBody))
	}

	outReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(reqBodyBytes))
	if err != nil {
		writeProxyError(clientTLS, http.StatusInternalServerError, "failed to build request: "+err.Error())
		return nil
	}
	copyHeaders(outReq.Header, req.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		writeProxyError(clientTLS, http.StatusBadGateway, "upstream error: "+err.Error())
		s.captureError(req, reqBodyBytes, err)
		return nil
	}
	defer resp.Body.Close()

	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxForwardBody))

	// Write the response back to the client over the same TLS connection.
	out := &http.Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     resp.Header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(respBodyBytes)),
		Request:    req,
	}
	out.Header.Del("Transfer-Encoding")
	out.ContentLength = int64(len(respBodyBytes))
	if err := out.Write(clientTLS); err != nil {
		return fmt.Errorf("write decrypted response: %w", err)
	}

	captured := &model.ProxyRequest{
		ID:              uuid.NewString(),
		CapturedAt:      time.Now().UTC(),
		Method:          req.Method,
		URL:             req.URL.String(),
		RequestHeaders:  flattenHeaders(req.Header),
		RequestBody:     string(truncateForCapture(reqBodyBytes)),
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: flattenHeaders(resp.Header),
		ResponseBody:    string(truncateForCapture(respBodyBytes)),
		Notes:           "captured via TLS interception",
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.SaveProxyRequest(ctx, captured)
		if s.passiveStore != nil {
			s.passiveStore.Analyze(captured)
		}
	}()
	return nil
}

func writeProxyError(w net.Conn, status int, msg string) {
	resp := &http.Response{
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(msg + "\n")),
	}
	resp.ContentLength = int64(len(msg) + 1)
	_ = resp.Write(w)
}

// captureMITMError persists a synthetic record describing a TLS interception
// failure so operators can debug bad CA installs without reading server logs.
func (s *Server) captureMITMError(host string, err error) {
	captured := &model.ProxyRequest{
		ID:              uuid.NewString(),
		CapturedAt:      time.Now().UTC(),
		Method:          "CONNECT",
		URL:             "https://" + host,
		RequestHeaders:  map[string]string{"Host": host},
		ResponseStatus:  0,
		ResponseHeaders: map[string]string{},
		ResponseBody:    "tls interception failed: " + err.Error(),
		Notes:           "Install the proxy CA certificate (Settings → Proxy → Download CA) and restart the browser.",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.store.SaveProxyRequest(ctx, captured)
}

// captureError stores a failed request with the error as the response body.
func (s *Server) captureError(r *http.Request, body []byte, err error) {
	captured := &model.ProxyRequest{
		ID:              uuid.NewString(),
		CapturedAt:      time.Now().UTC(),
		Method:          r.Method,
		URL:             r.URL.String(),
		RequestHeaders:  flattenHeaders(r.Header),
		RequestBody:     string(body),
		ResponseStatus:  0,
		ResponseHeaders: map[string]string{},
		ResponseBody:    "proxy error: " + err.Error(),
		Notes:           "upstream connection failed",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.store.SaveProxyRequest(ctx, captured)
}

// Replay fetches a previously captured request by ID, applies any overrides,
// sends it to the original destination, and returns the new captured pair.
// OverrideHeaders values replace matching keys; new keys are added.
// When overrideBody is non-empty it replaces the original request body entirely.
func (s *Server) Replay(ctx context.Context, id string, overrideHeaders map[string]string, overrideBody string) (*model.ProxyRequest, error) {
	orig, err := s.store.GetProxyRequest(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get proxy request %s: %w", id, err)
	}

	targetURL, err := url.Parse(orig.URL)
	if err != nil {
		return nil, fmt.Errorf("parse original URL: %w", err)
	}
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q — only http/https can be replayed", targetURL.Scheme)
	}
	if err := safety.ValidateOutboundURL(orig.URL); err != nil {
		return nil, fmt.Errorf("replay blocked by outbound safety policy")
	}

	body := orig.RequestBody
	if overrideBody != "" {
		body = overrideBody
	}

	req, err := http.NewRequestWithContext(ctx, orig.Method, orig.URL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build replay request: %w", err)
	}

	// Apply original headers then overrides.
	for k, v := range orig.RequestHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range overrideHeaders {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	req.Header.Del("Proxy-Connection")

	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("replay transport error: %w", err)
	}
	defer resp.Body.Close()

	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody))

	replayed := &model.ProxyRequest{
		ID:              uuid.NewString(),
		CapturedAt:      time.Now().UTC(),
		Method:          orig.Method,
		URL:             orig.URL,
		RequestHeaders:  flattenHeaders(req.Header),
		RequestBody:     body,
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: flattenHeaders(resp.Header),
		ResponseBody:    string(respBodyBytes),
		Notes:           fmt.Sprintf("replayed from request ID %s", id),
	}

	if saveErr := s.store.SaveProxyRequest(ctx, replayed); saveErr != nil {
		return nil, fmt.Errorf("save replayed request: %w", saveErr)
	}
	return replayed, nil
}

// AnalyzeHeaders examines a captured request's response headers and returns
// security findings. This is the "read headers to make attack decisions"
// function: it flags missing security headers and technology disclosures that
// inform subsequent testing decisions.
func AnalyzeHeaders(pr *model.ProxyRequest) []model.Finding {
	findings := make([]model.Finding, 0)
	h := pr.ResponseHeaders

	get := func(name string) string { return h[http.CanonicalHeaderKey(name)] }

	// Missing Content-Security-Policy hints at XSS feasibility.
	if get("Content-Security-Policy") == "" {
		findings = append(findings, model.Finding{
			ID:             "proxy-no-csp",
			Category:       "headers",
			Severity:       model.SeverityMedium,
			Title:          "No Content-Security-Policy — XSS likely exploitable",
			Description:    "The response has no CSP header, meaning injected scripts will execute in the victim's browser without restriction.",
			Evidence:       fmt.Sprintf("GET %s — Content-Security-Policy header absent", pr.URL),
			Recommendation: "Deploy a strict CSP (default-src 'self'; script-src 'self').",
		})
	}

	// X-Frame-Options absence → clickjacking.
	if get("X-Frame-Options") == "" {
		findings = append(findings, model.Finding{
			ID:             "proxy-no-xfo",
			Category:       "headers",
			Severity:       model.SeverityMedium,
			Title:          "No X-Frame-Options — clickjacking possible",
			Description:    "Without X-Frame-Options the page can be embedded in an iframe and used for clickjacking attacks.",
			Evidence:       fmt.Sprintf("GET %s — X-Frame-Options header absent", pr.URL),
			Recommendation: "Add X-Frame-Options: DENY or use frame-ancestors in CSP.",
		})
	}

	// X-Content-Type-Options absence → MIME sniffing.
	if get("X-Content-Type-Options") == "" {
		findings = append(findings, model.Finding{
			ID:             "proxy-no-xcto",
			Category:       "headers",
			Severity:       model.SeverityMedium,
			Title:          "No X-Content-Type-Options — MIME sniffing risk",
			Description:    "Without nosniff, browsers may execute incorrectly-typed responses as scripts.",
			Evidence:       fmt.Sprintf("GET %s — X-Content-Type-Options header absent", pr.URL),
			Recommendation: "Add X-Content-Type-Options: nosniff.",
		})
	}

	// Technology disclosure via Server and X-Powered-By.
	if sv := get("Server"); sv != "" {
		findings = append(findings, model.Finding{
			ID:             "proxy-server-disclosure",
			Category:       "disclosure",
			Severity:       model.SeverityLow,
			Title:          "Server software disclosed",
			Description:    "The Server header reveals the web server software and may include version information, aiding targeted exploitation.",
			Evidence:       fmt.Sprintf("Server: %s (from %s)", sv, pr.URL),
			Recommendation: "Suppress or genericise the Server header in web server configuration.",
		})
	}

	if xpb := get("X-Powered-By"); xpb != "" {
		findings = append(findings, model.Finding{
			ID:             "proxy-xpoweredby",
			Category:       "disclosure",
			Severity:       model.SeverityLow,
			Title:          "X-Powered-By discloses server-side technology",
			Description:    "The X-Powered-By header exposes the backend technology stack, assisting attacker reconnaissance.",
			Evidence:       fmt.Sprintf("X-Powered-By: %s (from %s)", xpb, pr.URL),
			Recommendation: "Remove X-Powered-By in framework or web server configuration.",
		})
	}

	// CORS wildcard on responses carrying credentials.
	acao := get("Access-Control-Allow-Origin")
	acac := get("Access-Control-Allow-Credentials")
	if acao == "*" && strings.EqualFold(acac, "true") {
		findings = append(findings, model.Finding{
			ID:             "proxy-cors-wildcard-creds",
			Category:       "cors",
			Severity:       model.SeverityHigh,
			Title:          "CORS wildcard with credentials — account takeover possible",
			Description:    "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is invalid per spec but some implementations honour it, allowing any origin to make credentialed cross-site requests.",
			Evidence:       fmt.Sprintf("ACAO: %s, ACAC: %s (from %s)", acao, acac, pr.URL),
			Recommendation: "Specify an explicit allow-list of trusted origins; never combine wildcard with credentials.",
		})
	}

	return findings
}

// copyHeaders copies all headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// flattenHeaders converts http.Header (multi-value) to a map[string]string
// by joining multiple values with ", " (per RFC 7230 §3.2.2).
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}
