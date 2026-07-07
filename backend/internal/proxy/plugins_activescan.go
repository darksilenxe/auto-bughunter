package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// ActiveScanAttempt is one supplementary probe sent by the Active Scan++
// plugin against a captured request's endpoint.
type ActiveScanAttempt struct {
	Check      string `json:"check"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	DurationMS int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// ActiveScanResult is the outcome of running the Active Scan++ battery of
// supplementary checks against a single captured request.
type ActiveScanResult struct {
	RequestID string              `json:"requestId"`
	Attempts  []ActiveScanAttempt `json:"attempts"`
	Findings  []model.Finding     `json:"findings"`
}

// RunActiveScanPlusPlus runs a battery of supplementary active checks
// against a captured request's endpoint, mirroring a subset of Burp Suite's
// "Active Scan++" extension: suspicious input transformation (expression
// evaluation), backup/config file disclosure, HTTP TRACE method (XST), and
// Host header injection.
func RunActiveScanPlusPlus(ctx context.Context, srv *Server, requestID string) (*ActiveScanResult, error) {
	if srv == nil {
		return nil, fmt.Errorf("proxy server is nil")
	}
	orig, err := srv.store.GetProxyRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get proxy request %s: %w", requestID, err)
	}
	parsed, err := url.Parse(orig.URL)
	if err != nil {
		return nil, fmt.Errorf("parse original URL: %w", err)
	}

	result := &ActiveScanResult{RequestID: requestID}

	if f := activeScanCheckTrace(ctx, srv, result, parsed.String()); f != nil {
		result.Findings = append(result.Findings, *f)
	}
	result.Findings = append(result.Findings, activeScanCheckBackupFiles(ctx, srv, result, *parsed)...)
	if f := activeScanCheckHostHeaderInjection(ctx, srv, result, orig); f != nil {
		result.Findings = append(result.Findings, *f)
	}
	result.Findings = append(result.Findings, activeScanCheckSuspiciousInputTransformation(ctx, srv, result, *parsed)...)

	return result, nil
}

func recordAttempt(result *ActiveScanResult, check, method, rawURL string, status int, durationMS int64, errMsg string) {
	result.Attempts = append(result.Attempts, ActiveScanAttempt{
		Check: check, Method: method, URL: rawURL, Status: status, DurationMS: durationMS, Error: errMsg,
	})
}

// activeScanSend sends a single active-scan probe request and returns the
// response status, body, and any error encountered.
func activeScanSend(ctx context.Context, srv *Server, method, rawURL string, headers map[string]string, body string) (status int, respBody []byte, durationMS int64, err error) {
	parsed, perr := url.Parse(rawURL)
	if perr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return 0, nil, 0, fmt.Errorf("invalid request URL")
	}
	if serr := safety.ValidateOutboundURL(parsed.String()); serr != nil {
		return 0, nil, 0, fmt.Errorf("blocked by outbound safety policy")
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader([]byte(body)))
	if err != nil {
		return 0, nil, 0, fmt.Errorf("build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	start := time.Now()
	resp, err := srv.transport.RoundTrip(req)
	durationMS = time.Since(start).Milliseconds()
	if err != nil {
		return 0, nil, durationMS, fmt.Errorf("transport error: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ = io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody))
	return resp.StatusCode, respBody, durationMS, nil
}

// activeScanCheckTrace probes for HTTP TRACE method support and, if
// enabled, whether the response echoes a request-supplied canary header —
// the classic Cross-Site Tracing (XST) signature.
func activeScanCheckTrace(ctx context.Context, srv *Server, result *ActiveScanResult, rawURL string) *model.Finding {
	canary := "abp-xst-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	status, body, dur, err := activeScanSend(ctx, srv, http.MethodTrace, rawURL, map[string]string{"X-ActiveScanPP-Canary": canary}, "")
	if err != nil {
		recordAttempt(result, "HTTP TRACE method (XST)", http.MethodTrace, rawURL, status, dur, err.Error())
		return nil
	}
	recordAttempt(result, "HTTP TRACE method (XST)", http.MethodTrace, rawURL, status, dur, "")
	if status >= 200 && status < 300 && strings.Contains(string(body), canary) {
		return &model.Finding{
			ID:             "proxy-activescan-trace-enabled",
			Category:       "misconfiguration",
			Severity:       model.SeverityMedium,
			Title:          "HTTP TRACE method enabled (Cross-Site Tracing)",
			Description:    "The server accepts the TRACE method and echoes request headers back in the response body, enabling Cross-Site Tracing (XST) attacks that can be used to bypass HttpOnly cookie protections in combination with an XSS vector.",
			Evidence:       fmt.Sprintf("TRACE %s returned %d and reflected canary header value %q in the response body.", rawURL, status, canary),
			Recommendation: "Disable the TRACE (and TRACK) HTTP methods on the web server/load balancer.",
			AffectedURL:    rawURL,
		}
	}
	return nil
}

var backupFileSuffixes = []string{"~", ".bak", ".old", ".orig", ".save", ".swp", ".backup", ".zip", ".tar.gz"}

// activeScanCheckBackupFiles appends common backup/editor-swap suffixes to
// the last path segment and flags any that return a successful response
// distinct from a nonexistent-file baseline.
func activeScanCheckBackupFiles(ctx context.Context, srv *Server, result *ActiveScanResult, base url.URL) []model.Finding {
	path := base.Path
	if path == "" || strings.HasSuffix(path, "/") {
		return nil // no filename segment to mutate
	}

	baselineURL := base
	baselineURL.Path = path + "-abp-nonexistent-marker"
	baselineStatus, baselineBody, dur, err := activeScanSend(ctx, srv, http.MethodGet, baselineURL.String(), nil, "")
	recordAttempt(result, "backup file baseline", http.MethodGet, baselineURL.String(), baselineStatus, dur, errString(err))
	if err != nil {
		return nil
	}

	var findings []model.Finding
	for _, suffix := range backupFileSuffixes {
		u := base
		u.Path = path + suffix
		status, body, dur, err := activeScanSend(ctx, srv, http.MethodGet, u.String(), nil, "")
		if err != nil {
			recordAttempt(result, "backup file: "+suffix, http.MethodGet, u.String(), status, dur, err.Error())
			continue
		}
		recordAttempt(result, "backup file: "+suffix, http.MethodGet, u.String(), status, dur, "")
		if status >= 200 && status < 300 && (baselineStatus != status || len(body) != len(baselineBody)) {
			findings = append(findings, model.Finding{
				ID:             "proxy-activescan-backup-file",
				Category:       "disclosure",
				Severity:       model.SeverityMedium,
				Title:          "Possible backup/config file disclosure",
				Description:    fmt.Sprintf("Requesting %q returned HTTP %d with content distinguishable from a nonexistent-file baseline, suggesting a backup or editor swap file is accessible.", suffix, status),
				Evidence:       fmt.Sprintf("GET %s returned %d (%d bytes) vs baseline %d (%d bytes) for a nonexistent path.", u.String(), status, len(body), baselineStatus, len(baselineBody)),
				Recommendation: "Remove backup, temporary, and editor swap files from web-accessible directories.",
				AffectedURL:    u.String(),
			})
		}
	}
	return findings
}

// activeScanCheckHostHeaderInjection sends the request with a spoofed Host
// header (and X-Forwarded-Host) and flags cases where the response reflects
// the injected host, a signature associated with password-reset-poisoning
// and cache-poisoning attack surfaces.
func activeScanCheckHostHeaderInjection(ctx context.Context, srv *Server, result *ActiveScanResult, orig *model.ProxyRequest) *model.Finding {
	canaryHost := "abp-xst-canary-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".example"
	headers := make(map[string]string, len(orig.RequestHeaders)+2)
	for k, v := range orig.RequestHeaders {
		headers[k] = v
	}
	headers["Host"] = canaryHost
	headers["X-Forwarded-Host"] = canaryHost

	status, body, dur, err := activeScanSend(ctx, srv, orig.Method, orig.URL, headers, orig.RequestBody)
	if err != nil {
		recordAttempt(result, "host header injection", orig.Method, orig.URL, status, dur, err.Error())
		return nil
	}
	recordAttempt(result, "host header injection", orig.Method, orig.URL, status, dur, "")
	if strings.Contains(string(body), canaryHost) {
		return &model.Finding{
			ID:             "proxy-activescan-host-header-injection",
			Category:       "input-validation",
			Severity:       model.SeverityMedium,
			Title:          "Host header value reflected in response",
			Description:    "The application reflects an attacker-controlled Host/X-Forwarded-Host header value into the response body, which can enable password-reset-link poisoning, cache poisoning, or SSRF depending on how the value is subsequently used server-side.",
			Evidence:       fmt.Sprintf("Sending Host/X-Forwarded-Host: %s to %s reflected the value in the response body.", canaryHost, orig.URL),
			Recommendation: "Validate the Host header against an allow-list of expected values server-side; never trust client-supplied Host/X-Forwarded-Host for generating absolute URLs.",
			AffectedURL:    orig.URL,
		}
	}
	return nil
}

var reQueryParamPair = regexp.MustCompile(`([^&=?]+)=([^&]*)`)

// activeScanCheckSuspiciousInputTransformation replaces each query
// parameter value with a simple arithmetic expression ("7*11") and flags
// endpoints whose response reflects the *evaluated* result ("77") rather
// than the literal payload — a signature of server-side expression
// evaluation (template engines, EL/OGNL, etc.).
func activeScanCheckSuspiciousInputTransformation(ctx context.Context, srv *Server, result *ActiveScanResult, base url.URL) []model.Finding {
	if base.RawQuery == "" {
		return nil
	}
	const payload = "7*11"
	const evaluated = "77"

	matches := reQueryParamPair.FindAllStringSubmatch(base.RawQuery, -1)
	if len(matches) == 0 {
		return nil
	}

	var findings []model.Finding
	seen := map[string]bool{}
	for _, m := range matches {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true

		values, err := url.ParseQuery(base.RawQuery)
		if err != nil {
			continue
		}
		values.Set(name, payload)
		u := base
		u.RawQuery = values.Encode()

		status, body, dur, err := activeScanSend(ctx, srv, http.MethodGet, u.String(), nil, "")
		if err != nil {
			recordAttempt(result, "suspicious input transformation: "+name, http.MethodGet, u.String(), status, dur, err.Error())
			continue
		}
		recordAttempt(result, "suspicious input transformation: "+name, http.MethodGet, u.String(), status, dur, "")
		if strings.Contains(string(body), evaluated) && !strings.Contains(string(body), payload) {
			findings = append(findings, model.Finding{
				ID:                "proxy-activescan-suspicious-input-transformation",
				Category:          "input-validation",
				Severity:          model.SeverityHigh,
				Title:             "Suspicious input transformation (possible server-side expression evaluation)",
				Description:       fmt.Sprintf("Submitting the arithmetic expression %q as the %q parameter caused the response to contain its evaluated result %q instead of the literal payload, suggesting server-side template/expression evaluation of user input.", payload, name, evaluated),
				Evidence:          fmt.Sprintf("GET %s returned a response containing %q (evaluated) rather than %q (literal).", u.String(), evaluated, payload),
				Recommendation:    "Treat this as a potential server-side template injection (SSTI) / expression-language injection finding and manually confirm with an out-of-band or code-execution payload before remediating the templating/evaluation path.",
				AffectedURL:       u.String(),
				AffectedParameter: name,
			})
		}
	}
	return findings
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
