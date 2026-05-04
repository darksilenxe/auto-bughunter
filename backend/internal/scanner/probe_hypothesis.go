package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// wafSignatures are body strings that indicate a WAF interception page.
var wafSignatures = []string{
	"access denied", "request blocked", "mod_security",
	"cloudflare", "akamai", "incapsula", "sucuri", "barracuda",
	"web application firewall", "f5 big-ip", "imperva",
}

// serverErrorSignatures indicate the server produced an unhandled exception,
// which is itself a signal worth investigating for injection.
var serverErrorSignatures = []string{
	"stack trace", "unhandled exception", "traceback",
	"fatal error", "internal server error",
}

// ProbeHypothesis executes a targeted HTTP probe for a single hypothesis and
// returns a ProbeResult that captures the full HTTP-level observation, even
// when no vulnerability is confirmed. This allows the AI reflection step to
// reason about WHY a probe failed:
//
//   - WAF_BLOCKED  → server actively filtered the payload; try an evasion variant
//   - NEAR_MISS    → partial signal detected; refine the payload or context
//   - SERVER_ERROR → unhandled exception on injection; follow up with error-based probe
//   - NO_SIGNAL    → genuinely clean response; move to the next category
//   - ERROR        → network/URL issue; skip and continue
//
// The Observation field is written in plain English so it can be included
// verbatim in the AI prompt without further processing.
func (s *Service) ProbeHypothesis(
	ctx context.Context,
	category, endpoint, paramName, payloadHint string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) model.ProbeResult {
	base := model.ProbeResult{
		Category:  category,
		Endpoint:  endpoint,
		ParamName: paramName,
		Payload:   payloadHint,
	}

	if options.PassiveOnly {
		base.Outcome = model.ProbeNoSignal
		base.Observation = "Passive-only mode is active; active probe skipped for " + category + "."
		return base
	}

	if err := safety.ValidateOutboundURL(endpoint); err != nil {
		base.Outcome = model.ProbeError
		base.Observation = "Probe skipped: endpoint URL failed safety validation (" + err.Error() + ")."
		return base
	}

	// Issue the HTTP probe and capture the raw response.
	statusCode, body, probeURL, probeErr := s.issueProbeRequest(ctx, category, endpoint, paramName, payloadHint, auth, options)

	if probeErr != nil {
		base.Outcome = model.ProbeError
		base.Observation = "Probe request failed: " + probeErr.Error() + ". The endpoint may be unreachable or the context was cancelled."
		return base
	}

	base.StatusCode = statusCode

	// ── WAF / rate-limit detection ────────────────────────────────────────
	if statusCode == 403 || statusCode == 406 || statusCode == 429 {
		base.Outcome = model.ProbeWAFBlocked
		bodyLow := strings.ToLower(body)
		wafName := ""
		for _, sig := range wafSignatures {
			if strings.Contains(bodyLow, sig) {
				wafName = sig
				break
			}
		}
		if wafName != "" {
			base.Observation = fmt.Sprintf(
				"Server returned HTTP %d and the response body contains a WAF interception signature (%q). "+
					"The payload was actively filtered before reaching application logic. "+
					"An evasion-variant payload (URL-encoded, case-variant, or chunked) is warranted.",
				statusCode, wafName,
			)
		} else {
			base.Observation = fmt.Sprintf(
				"Server returned HTTP %d on probe %s. This typically indicates WAF or access-control filtering. "+
					"The vulnerability may still be present; try an evasion-variant payload for %s.",
				statusCode, probeURL, category,
			)
		}
		return base
	}

	// ── Server error — potential injection signal ─────────────────────────
	if statusCode >= 500 {
		bodyLow := strings.ToLower(body)
		for _, sig := range serverErrorSignatures {
			if strings.Contains(bodyLow, sig) {
				base.Outcome = model.ProbeServerError
				base.Observation = fmt.Sprintf(
					"Server returned HTTP %d with a stack trace or exception message in the response body. "+
						"This is a strong signal for unhandled injection on %s — the payload caused an application crash. "+
						"Follow up with an error-based or blind probe to confirm exploitability.",
					statusCode, endpoint,
				)
				return base
			}
		}
		base.Outcome = model.ProbeServerError
		base.Observation = fmt.Sprintf(
			"Server returned HTTP %d on %s %s probe. An application error on a crafted payload is a potential "+
				"injection indicator. Try a blind (time-based or out-of-band) follow-up probe.",
			statusCode, category, endpoint,
		)
		return base
	}

	// ── Run the existing oracle to check for confirmation ─────────────────
	finding := s.RunHypothesisVerification(ctx, endpoint, paramName, payloadHint, category, auth, options)
	if finding != nil {
		base.Outcome = model.ProbeConfirmed
		base.Confirmed = true
		base.Finding = finding
		base.Observation = fmt.Sprintf(
			"Probe CONFIRMED: %s on %s. Oracle returned a positive signal (status %d). "+
				"Finding: %s.",
			category, endpoint, statusCode, finding.Title,
		)
		return base
	}

	// ── Near-miss detection — category-specific partial signals ───────────
	nearMissObs := nearMissObservation(category, endpoint, paramName, payloadHint, statusCode, body, probeURL)
	if nearMissObs != "" {
		base.Outcome = model.ProbeNearMiss
		base.Observation = nearMissObs
		return base
	}

	// ── No signal ─────────────────────────────────────────────────────────
	base.Outcome = model.ProbeNoSignal
	base.Observation = fmt.Sprintf(
		"Probe returned HTTP %d with no detectable signals for %s on %s. "+
			"The target does not appear vulnerable to this payload/parameter combination. "+
			"Consider trying a different endpoint or parameter name.",
		statusCode, category, endpoint,
	)
	return base
}

// issueProbeRequest builds and executes the appropriate HTTP request for the
// given category and returns (statusCode, bodyExcerpt, probeURL, error).
// It captures the response even for non-200 status codes so that WAF and
// near-miss classification can inspect the body.
func (s *Service) issueProbeRequest(
	ctx context.Context,
	category, endpoint, paramName, payloadHint string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) (int, string, string, error) {
	const bodyLimit = 8 * 1024 // 8 KB is enough for WAF/near-miss classification

	cat := strings.ToLower(strings.TrimSpace(category))

	switch cat {
	case "cors":
		// CORS: GET with Origin header, no query param needed.
		attackerOrigin := "https://evil.example.com"
		if after, ok := strings.CutPrefix(payloadHint, "Origin: "); ok {
			attackerOrigin = strings.TrimSpace(after)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return 0, "", endpoint, err
		}
		req.Header.Set("Origin", attackerOrigin)
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			return 0, "", endpoint, fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
		return resp.StatusCode, string(b), endpoint, nil

	case "open_redirect":
		param := paramName
		if param == "" {
			param = "redirect_uri"
		}
		payload := payloadHint
		if payload == "" {
			payload = "https://" + openRedirectMarker
		}
		probeURL, err := appendQueryParam(endpoint, param, payload)
		if err != nil {
			return 0, "", endpoint, err
		}
		if !sameOrigin(endpoint, probeURL) {
			return 0, "", probeURL, fmt.Errorf("origin mismatch after building probe URL")
		}
		noFollow := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 15 * time.Second,
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			return 0, "", probeURL, err
		}
		ApplyAuthProfile(req, auth)
		resp, err := noFollow.Do(req)
		if err != nil || resp == nil {
			return 0, "", probeURL, fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
		return resp.StatusCode, string(b) + "\nLocation: " + resp.Header.Get("Location"), probeURL, nil

	default:
		// xss, sqli, ssti, ssrf, idor, auth_bypass, business_logic, etc.
		// All use a query-parameter injection approach for the diagnostic request.
		param := paramName
		if param == "" {
			param = defaultParamForCategory(cat)
		}
		payload := payloadHint
		if payload == "" {
			payload = defaultPayloadForCategory(cat)
		}
		probeURL, err := appendQueryParam(endpoint, param, payload)
		if err != nil {
			return 0, "", endpoint, err
		}
		if !sameOrigin(endpoint, probeURL) {
			return 0, "", probeURL, fmt.Errorf("origin mismatch after building probe URL")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			return 0, "", probeURL, err
		}
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			return 0, "", probeURL, fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
		return resp.StatusCode, string(b), probeURL, nil
	}
}

// nearMissObservation returns a plain-English observation when the response
// contains partial signals consistent with vulnerability but falls short of
// the oracle's confirmation threshold. Returns "" when no near-miss is found.
func nearMissObservation(category, endpoint, paramName, payload string, statusCode int, body, probeURL string) string {
	bodyLow := strings.ToLower(body)
	cat := strings.ToLower(strings.TrimSpace(category))

	switch cat {
	case "xss":
		// Payload appears in body but inside a JS string or attribute (not raw HTML).
		if len(payload) > 4 && strings.Contains(body, payload[:len(payload)/2]) {
			return fmt.Sprintf(
				"XSS probe on %s: the first half of the payload appears in the HTTP %d response body, "+
					"suggesting partial reflection. The payload may be landing inside a JavaScript string "+
					"or HTML attribute context rather than raw HTML. "+
					"Try a context-specific variant such as `\";alert(1)//` or `' onmouseover=alert(1) x='`.",
				probeURL, statusCode,
			)
		}
		// Body contains raw angle brackets — reflection without encoding, but different payload.
		if strings.Contains(body, "<script") || strings.Contains(body, "onerror=") {
			return fmt.Sprintf(
				"XSS probe on %s: the response body (HTTP %d) already contains unencoded <script> or event-handler "+
					"attributes. The page may have existing XSS or be reflecting other parameters. "+
					"Try injecting via a different parameter or a polyglot payload.",
				probeURL, statusCode,
			)
		}

	case "sqli":
		// Response body contains generic error keywords but not SQL-specific strings.
		genericErrors := []string{"error", "exception", "warning", "notice", "undefined"}
		for _, sig := range genericErrors {
			if strings.Contains(bodyLow, sig) {
				return fmt.Sprintf(
					"SQL injection probe on %s: the HTTP %d response body contains the word %q, which may indicate "+
						"an application error triggered by the payload — but no canonical SQL error string was matched. "+
						"Try an error-based payload targeting a specific database engine (MySQL, PostgreSQL, MSSQL) "+
						"or switch to a time-based blind probe (`1 AND SLEEP(5)--`).",
					probeURL, statusCode, sig,
				)
			}
		}
		// Server took unusually long — timing signal (can't measure from body, but 200 with delay is noted).
		if strings.Contains(bodyLow, "timeout") || strings.Contains(bodyLow, "timed out") {
			return fmt.Sprintf(
				"SQL injection probe on %s: the response body mentions a timeout, which may indicate a successful "+
					"time-based injection. Confirm with `1; WAITFOR DELAY '0:0:5'--` (MSSQL) or `1 AND SLEEP(5)--` (MySQL).",
				probeURL, statusCode,
			)
		}

	case "open_redirect":
		// 3xx but Location doesn't contain the marker.
		if statusCode >= 300 && statusCode < 400 {
			return fmt.Sprintf(
				"Open redirect probe on %s: server returned HTTP %d (redirect) but the Location header does not "+
					"contain the attacker marker. The parameter may accept only relative paths or same-origin URLs. "+
					"Try `//evil.example.com/` or a URL-encoded variant `%%2F%%2Fevil.example.com%%2F`.",
				endpoint, statusCode,
			)
		}
		// No redirect but the param exists — may need a different param name.
		if strings.Contains(strings.ToLower(body), "redirect") || strings.Contains(strings.ToLower(body), "return") {
			return fmt.Sprintf(
				"Open redirect probe on %s: the response body contains 'redirect' or 'return' keywords but the server "+
					"did not issue a redirect for parameter %q. Try alternate parameter names: `next`, `url`, `goto`, `dest`.",
				endpoint, paramName,
			)
		}

	case "cors":
		// ACAO wildcard present but no ACAC — lower severity, but still worth noting.
		if strings.Contains(body, "Access-Control-Allow-Origin: *") {
			return fmt.Sprintf(
				"CORS probe on %s: server returns Access-Control-Allow-Origin: * (HTTP %d), which permits "+
					"unauthenticated cross-origin reads. This does not allow credential sharing but may still "+
					"expose public API data. Verify whether Access-Control-Allow-Credentials is absent or false.",
				endpoint, statusCode,
			)
		}

	case "ssrf":
		if statusCode == 200 && (strings.Contains(bodyLow, "169.254") || strings.Contains(bodyLow, "metadata")) {
			return fmt.Sprintf(
				"SSRF probe on %s: the HTTP %d response body contains metadata-like content, potentially from an "+
					"internal endpoint. Confirm by requesting `http://169.254.169.254/latest/meta-data/iam/` "+
					"or internal service addresses.",
				endpoint, statusCode,
			)
		}
	}

	return ""
}

// defaultParamForCategory returns a sensible default parameter name to probe
// when the hypothesis does not specify one.
func defaultParamForCategory(category string) string {
	switch category {
	case "sqli", "idor":
		return "id"
	case "xss":
		return "q"
	case "ssti":
		return "template"
	case "ssrf":
		return "url"
	case "auth_bypass":
		return "token"
	default:
		return "input"
	}
}

// defaultPayloadForCategory returns a minimal probe payload for categories
// where the hypothesis did not specify one.
func defaultPayloadForCategory(category string) string {
	switch category {
	case "xss":
		return xssMarker
	case "sqli":
		return "'"
	case "ssti":
		return "{{7*7}}"
	case "ssrf":
		return "http://169.254.169.254/latest/meta-data/"
	case "idor":
		return "1"
	case "auth_bypass":
		return "' OR 1=1--"
	default:
		return "test"
	}
}
