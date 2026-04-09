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
	"bytes"
	"context"
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

// maxCaptureBody is the maximum number of bytes captured from a request or
// response body to keep storage bounded.
const maxCaptureBody = 128 * 1024

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
	store     Store
	transport *http.Transport
	mu        sync.Mutex
}

// NewServer creates a new intercepting proxy backed by the provided Store.
func NewServer(store Store) *Server {
	return &Server{
		store: store,
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

// Store returns the underlying persistence store.
func (s *Server) Store() Store {
	return s.store
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

	// Capture request body.
	var reqBodyBytes []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, maxCaptureBody)
		reqBodyBytes, _ = io.ReadAll(limited)
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

	// Capture response body.
	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody))

	// Write response back to client.
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBodyBytes)

	// Persist captured pair asynchronously.
	captured := &model.ProxyRequest{
		ID:              uuid.NewString(),
		CapturedAt:      time.Now().UTC(),
		Method:          r.Method,
		URL:             r.URL.String(),
		RequestHeaders:  flattenHeaders(r.Header),
		RequestBody:     string(reqBodyBytes),
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: flattenHeaders(resp.Header),
		ResponseBody:    string(respBodyBytes),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.SaveProxyRequest(ctx, captured)
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
		Notes:           "HTTPS CONNECT tunnel established. To inspect body, configure a CA certificate for TLS interception.",
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.SaveProxyRequest(ctx, captured)
	}()

	// Pipe bytes bidirectionally.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(destConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, destConn)
	}()
	wg.Wait()
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
