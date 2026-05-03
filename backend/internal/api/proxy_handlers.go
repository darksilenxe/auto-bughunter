package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"auto-bughunter/backend/internal/proxy"
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
