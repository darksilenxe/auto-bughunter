package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/safety"
)

// handleProxySettings returns the operator-facing configuration of the
// intercepting proxy: listen port/host, MITM status, and CA fingerprint.
//
// Used by the in-browser Burp-style UI to render the "Configure your browser"
// instructions and the CA download/fingerprint badge.
func (s *Server) handleProxySettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	host := strings.TrimSpace(os.Getenv("PROXY_PUBLIC_HOST"))
	if host == "" {
		host = "localhost"
	}
	port := strings.TrimSpace(os.Getenv("PROXY_PORT"))
	if port == "" {
		port = "8081"
	}
	enabled := strings.EqualFold(strings.TrimSpace(os.Getenv("ENABLE_PROXY")), "true") ||
		os.Getenv("ENABLE_PROXY") == "1"

	resp := map[string]any{
		"enabled":     enabled,
		"host":        host,
		"port":        port,
		"mitmEnabled": s.proxyServer != nil && s.proxyServer.MITMEnabled(),
	}
	if s.proxyServer != nil {
		if ca := s.proxyServer.CA(); ca != nil {
			resp["caFingerprintSHA256"] = ca.Fingerprint()
			notAfter := ca.NotAfter()
			if !notAfter.IsZero() {
				resp["caNotAfter"] = notAfter.UTC().Format("2006-01-02T15:04:05Z")
			}
			resp["caDownloadURL"] = "/api/proxy/ca-certificate"
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleProxyCACertificate streams the proxy CA certificate as PEM so
// operators can install it into their browser/OS trust store.
func (s *Server) handleProxyCACertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.proxyServer == nil || s.proxyServer.CA() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "proxy CA is not configured",
			"hint":  "set PROXY_CA_CERT_FILE/PROXY_CA_KEY_FILE (and PROXY_CA_AUTOGENERATE=true on first boot) to enable HTTPS interception",
		})
		return
	}
	pem := s.proxyServer.CA().CertificatePEM()
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="auto-bughunter-proxy-ca.pem"`)
	_, _ = w.Write(pem)
}

// handleProxyIntruder runs an "Intruder"-style fuzz of a captured request:
// each occurrence of the marker (default "§") in the request URL, headers, or
// body is substituted with each payload from the supplied list, the resulting
// requests are sent to the original destination, and a per-payload summary is
// returned.
//
//	Body: {
//	  "requestId": "...",            // captured request to base the attack on
//	  "marker":    "§",              // optional; defaults to "§"
//	  "payloads":  ["a","b","c"],    // required
//	  "overrideHeaders": {...},       // optional baseline header overrides
//	  "overrideBody": "..."          // optional baseline body override
//	}
//
// All requests are subject to the same outbound safety policy as Replay.
func (s *Server) handleProxyIntruder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.proxyServer == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "proxy is not configured"})
		return
	}
	var req struct {
		RequestID       string            `json:"requestId"`
		Marker          string            `json:"marker"`
		Payloads        []string          `json:"payloads"`
		OverrideHeaders map[string]string `json:"overrideHeaders"`
		OverrideBody    string            `json:"overrideBody"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.RequestID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requestId is required"})
		return
	}
	if len(req.Payloads) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payloads is required"})
		return
	}
	// Cap to keep one HTTP call bounded; each payload produces an outbound
	// request and a stored capture so unbounded fuzzing is undesirable.
	const maxPayloads = 200
	if len(req.Payloads) > maxPayloads {
		req.Payloads = req.Payloads[:maxPayloads]
	}
	marker := req.Marker
	if marker == "" {
		marker = "§"
	}

	results, err := proxy.RunIntruder(r.Context(), s.proxyServer, req.RequestID, marker, req.Payloads, req.OverrideHeaders, req.OverrideBody)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requestId": req.RequestID,
		"marker":    marker,
		"results":   results,
	})
}

// handleProxyBrowse handles GET /api/proxy/browse?url=<target-url>.
//
// It fetches the requested URL using the proxy's recording transport so the
// request appears in the proxy history (/api/proxy/requests) and is visible
// on the Network Graph.  The response body is returned to the caller with its
// original Content-Type header so the frontend can display it in an <iframe>
// via a Blob URL.
//
// For HTML responses a <base href="<target-url>"> tag is injected after the
// first <head> (or prepended to the body if no <head> is present) so that
// relative links, stylesheets, and images resolve against the origin server
// rather than the operator console origin.
//
// Request rate is bounded: only GET requests are supported, and the target
// must pass the outbound safety policy.
func (s *Server) handleProxyBrowse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
	if rawURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url query parameter is required"})
		return
	}

	// Ensure the URL has a scheme so url.Parse produces a useful result.
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid URL"})
		return
	}

	if err := safety.ValidateOutboundURL(rawURL); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "URL blocked by outbound safety policy: " + err.Error()})
		return
	}

	// Build the outbound request.
	ctx := r.Context()
	outReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to build request: " + err.Error()})
		return
	}
	outReq.Header.Set("User-Agent", "Mozilla/5.0 (auto-bughunter proxy-browser/1.0)")
	outReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	outReq.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Use a recording transport so the browse request appears in the proxy
	// history and on the Network Graph.  RecordingTransport saves each
	// request/response pair; no additional save is needed here.
	rt := &proxy.RecordingTransport{
		Store: s.proxyServer.Store(),
	}
	client := &http.Client{
		Transport: rt,
		Timeout:   20 * time.Second,
		// Validate every redirect URL against the outbound safety policy to
		// prevent SSRF via server-controlled Location headers.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if err := safety.ValidateOutboundURL(req.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked by outbound safety policy: %w", err)
			}
			return nil
		},
	}

	resp, err := client.Do(outReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream request failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2 MB cap

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}

	// For HTML responses inject <base href> so relative URLs resolve correctly
	// when the response is rendered inside a Blob URL iframe on a different origin.
	if strings.Contains(strings.ToLower(contentType), "html") {
		bodyBytes = injectBaseHref(bodyBytes, rawURL)
	}

	// Serve the raw body with the original Content-Type.  Strip security
	// headers that would block the response from being displayed in an iframe.
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Proxy-Status", fmt.Sprintf("%d", resp.StatusCode))
	w.Header().Del("X-Frame-Options")
	w.Header().Del("Content-Security-Policy")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bodyBytes)

	// Run passive analysis on the captured page response so browse-tab traffic
	// feeds the passive findings store alongside traffic captured by the proxy
	// server itself.
	s.proxyServer.AnalyzeResponse(rawURL, resp.StatusCode, resp.Header, bodyBytes)
}

// reHeadTag matches the first <head …> or <HEAD …> opening tag in HTML.
var reHeadTag = regexp.MustCompile(`(?i)<head[^>]*>`)

// injectBaseHref inserts <base href="<targetURL>"> immediately after the
// first <head> tag found in the HTML body, or prepends it before the first
// <html> / <!DOCTYPE> tag when no <head> is present.  This ensures that
// relative links, stylesheets, scripts, and images in the fetched page
// resolve against the origin server when the HTML is served from a Blob URL
// in the operator console's iframe.
func injectBaseHref(body []byte, targetURL string) []byte {
	base := fmt.Sprintf(`<base href=%q>`, targetURL)
	loc := reHeadTag.FindIndex(body)
	if loc != nil {
		// Insert after the closing > of the <head> tag.
		insertAt := loc[1]
		result := make([]byte, 0, len(body)+len(base))
		result = append(result, body[:insertAt]...)
		result = append(result, []byte(base)...)
		result = append(result, body[insertAt:]...)
		return result
	}
	// No <head> found — prepend so the browser still picks it up.
	return append([]byte(base), body...)
}

// handleProxyPassiveFindings serves the passive-scan finding store.
//
//   GET    /api/proxy/passive-findings  — returns all deduplicated findings
//   DELETE /api/proxy/passive-findings  — clears the finding store
//
// Findings are discovered automatically whenever traffic flows through the
// intercepting proxy or through the proxy browse endpoint.
func (s *Server) handleProxyPassiveFindings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		findings := s.passiveScanStore.List()
		writeJSON(w, http.StatusOK, findings)
	case http.MethodDelete:
		s.passiveScanStore.Clear()
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}
