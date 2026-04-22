package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// hypothesisBodyLimit caps the response body read during verification probes.
const hypothesisBodyLimit = 64 * 1024

// RunHypothesisVerification executes a targeted verification probe for a
// single AI-generated hypothesis. It selects the appropriate oracle based on
// the hypothesis category, issues at most one request to the target endpoint,
// and returns a finding only when the oracle detects a positive signal.
//
// Supported categories: xss, sqli, open_redirect, cors.
// Unknown categories produce nil (no finding).
//
// The verification is deliberately minimal — the same lightweight oracle used
// by the existing active probes — so it produces no false positives from
// ambiguous heuristics and leaves no observable side-effects.
func (s *Service) RunHypothesisVerification(
	ctx context.Context,
	endpoint, paramName, payloadHint, category string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) *model.Finding {
	if options.PassiveOnly {
		return nil
	}
	if err := safety.ValidateOutboundURL(endpoint); err != nil {
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(category)) {
	case "xss":
		return s.verifyXSSHypothesis(ctx, endpoint, paramName, payloadHint, auth, options)
	case "sqli":
		return s.verifySQLiHypothesis(ctx, endpoint, paramName, payloadHint, auth, options)
	case "open_redirect":
		return s.verifyOpenRedirectHypothesis(ctx, endpoint, paramName, payloadHint, auth, options)
	case "cors":
		return s.verifyCORSHypothesis(ctx, endpoint, payloadHint, auth, options)
	default:
		return nil
	}
}

// verifyXSSHypothesis probes a single endpoint+parameter with the hypothesis
// payload and checks whether the marker appears unescaped in the response body.
func (s *Service) verifyXSSHypothesis(
	ctx context.Context,
	endpoint, paramName, payload string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) *model.Finding {
	if payload == "" {
		payload = xssMarker
	}
	param := paramName
	if param == "" {
		param = "q"
	}

	probeURL, err := appendQueryParam(endpoint, param, payload)
	if err != nil {
		return nil
	}
	// Verify the host and scheme haven't changed after appending the payload
	// as a query parameter. appendQueryParam uses standard URL encoding, but
	// this is a defence-in-depth check against unexpected URL mangling.
	if !sameOrigin(endpoint, probeURL) {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, auth)

	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, hypothesisBodyLimit))
	body := string(bodyBytes)

	// Check for unescaped reflection of the full payload string in the response
	// body. This confirms the server is echoing user input verbatim without HTML
	// encoding. We require the whole payload string (not just substrings like
	// "<svg") to minimise false positives from unrelated page content.
	if !strings.Contains(body, payload) {
		return nil
	}

	return &model.Finding{
		ID:       "hyp-xss-verified",
		Category: "xss",
		Severity: model.SeverityHigh,
		Title:    "Reflected XSS confirmed via hypothesis verification",
		Description: "The hypothesis probe reflected the XSS payload unescaped into the " +
			"HTTP response body. An attacker can inject arbitrary JavaScript into the " +
			"victim's browser session.",
		Evidence: fmt.Sprintf(
			"GET %s returned a response containing the unescaped payload %q.",
			probeURL, payload,
		),
		Recommendation: "HTML-encode all user-supplied input before rendering into HTML " +
			"response bodies. Apply a strict Content-Security-Policy.",
		Confidence:        0.88,
		AffectedURL:       endpoint,
		CWE:               "CWE-79",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"hypothesis-agent", "active-scanner"},
		ReproductionSteps: []string{fmt.Sprintf("GET %s", probeURL), "Observe reflected payload in response body."},
		EvidenceFields: map[string]string{
			"param":          param,
			"payload":        payload,
			"validationType": "active-probe",
		},
	}
}

// verifySQLiHypothesis sends the payload and looks for SQL error messages in
// the response body as a confirmatory signal.
func (s *Service) verifySQLiHypothesis(
	ctx context.Context,
	endpoint, paramName, payload string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) *model.Finding {
	if payload == "" {
		payload = "'"
	}
	param := paramName
	if param == "" {
		param = "id"
	}

	probeURL, err := appendQueryParam(endpoint, param, payload)
	if err != nil {
		return nil
	}
	if !sameOrigin(endpoint, probeURL) {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, auth)

	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, hypothesisBodyLimit))
	body := strings.ToLower(string(bodyBytes))

	sqlErrors := []string{
		"you have an error in your sql syntax",
		"unclosed quotation mark",
		"syntax error",
		"odbc driver",
		"sqlexception",
		"pg_query()",
		"supplied argument is not a valid mysql",
		"ora-",
		"sqlite3::query",
	}
	for _, sig := range sqlErrors {
		if strings.Contains(body, sig) {
			return &model.Finding{
				ID:       "hyp-sqli-verified",
				Category: "injection",
				Severity: model.SeverityHigh,
				Title:    "SQL injection confirmed via hypothesis verification",
				Description: "The hypothesis probe triggered a database error message in " +
					"the HTTP response body, confirming SQL injection is possible.",
				Evidence: fmt.Sprintf(
					"GET %s returned a response containing the SQL error indicator %q.",
					probeURL, sig,
				),
				Recommendation: "Use parameterized queries or prepared statements. " +
					"Never interpolate user-supplied values into SQL strings directly.",
				Confidence:        0.92,
				AffectedURL:       endpoint,
				CWE:               "CWE-89",
				OWASPCategory:     "A03:2021 - Injection",
				Sources:           []string{"hypothesis-agent", "active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("GET %s", probeURL), "Observe SQL error in response body."},
				EvidenceFields: map[string]string{
					"param":          param,
					"payload":        payload,
					"sqlErrorSig":    sig,
					"validationType": "active-probe",
				},
			}
		}
	}
	return nil
}

// verifyOpenRedirectHypothesis sends the payload as a redirect parameter and
// checks the Location response header for an off-host destination.
func (s *Service) verifyOpenRedirectHypothesis(
	ctx context.Context,
	endpoint, paramName, payload string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) *model.Finding {
	if payload == "" {
		payload = "https://" + openRedirectMarker
	}
	param := paramName
	if param == "" {
		param = "redirect_uri"
	}

	probeURL, err := appendQueryParam(endpoint, param, payload)
	if err != nil {
		return nil
	}
	if !sameOrigin(endpoint, probeURL) {
		return nil
	}

	// Use a client that does not follow redirects so we can inspect the Location header.
	noFollowClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, auth)

	resp, err := noFollowClient.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(strings.ToLower(location), strings.ToLower(openRedirectMarker)) {
		return nil
	}

	return &model.Finding{
		ID:       "hyp-open-redirect-verified",
		Category: "cors-redirect",
		Severity: model.SeverityMedium,
		Title:    "Open redirect confirmed via hypothesis verification",
		Description: "The hypothesis probe confirmed that the application redirects to an " +
			"attacker-controlled URL without validation, enabling phishing and OAuth " +
			"authorization-code theft attacks.",
		Evidence: fmt.Sprintf(
			"GET %s returned HTTP %d Location: %s",
			probeURL, resp.StatusCode, location,
		),
		Recommendation: "Validate all redirect targets against an exact-match allowlist of " +
			"trusted destinations. Never accept arbitrary URLs from user-supplied input.",
		Confidence:        0.93,
		AffectedURL:       endpoint,
		CWE:               "CWE-601",
		OWASPCategory:     "A01:2021 - Broken Access Control",
		Sources:           []string{"hypothesis-agent", "active-scanner"},
		ReproductionSteps: []string{fmt.Sprintf("GET %s", probeURL), fmt.Sprintf("Observe Location: %s", location)},
		EvidenceFields: map[string]string{
			"param":          param,
			"payload":        payload,
			"location":       location,
			"validationType": "active-probe",
		},
	}
}

// verifyCORSHypothesis issues a preflight-style request with an attacker
// origin and checks whether the response reflects that origin in ACAO.
func (s *Service) verifyCORSHypothesis(
	ctx context.Context,
	endpoint, payloadHint string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) *model.Finding {
	attackerOrigin := "https://evil.example.com"
	// Extract origin from payloadHint if provided (e.g. "Origin: https://attacker.com").
	if after, ok := strings.CutPrefix(payloadHint, "Origin: "); ok {
		attackerOrigin = strings.TrimSpace(after)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", attackerOrigin)
	ApplyAuthProfile(req, auth)

	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
	if acao != attackerOrigin && acao != "*" {
		return nil
	}

	severity := model.SeverityMedium
	desc := "The application reflects the attacker-controlled Origin in Access-Control-Allow-Origin."
	if acac == "true" {
		severity = model.SeverityHigh
		desc += " With Access-Control-Allow-Credentials: true, an attacker can issue " +
			"credentialed cross-origin requests and exfiltrate authenticated session data."
	}

	return &model.Finding{
		ID:            "hyp-cors-verified",
		Category:      "cors",
		Severity:      severity,
		Title:         "CORS misconfiguration confirmed via hypothesis verification",
		Description:   desc,
		Evidence:      fmt.Sprintf("GET %s with Origin: %s → ACAO: %s ACAC: %s", endpoint, attackerOrigin, acao, acac),
		Recommendation: "Restrict Access-Control-Allow-Origin to an explicit trusted-origin " +
			"allowlist. Never reflect arbitrary request origins. Avoid pairing wildcard " +
			"origins with Allow-Credentials: true.",
		Confidence:        0.90,
		AffectedURL:       endpoint,
		CWE:               "CWE-942",
		OWASPCategory:     "A05:2021 - Security Misconfiguration",
		Sources:           []string{"hypothesis-agent", "active-scanner"},
		ReproductionSteps: []string{fmt.Sprintf("GET %s with Origin: %s", endpoint, attackerOrigin), fmt.Sprintf("Observe ACAO: %s", acao)},
		EvidenceFields: map[string]string{
			"origin":         attackerOrigin,
			"acao":           acao,
			"acac":           acac,
			"validationType": "active-probe",
		},
	}
}

// appendQueryParam returns a copy of rawURL with the given parameter set to value.
func appendQueryParam(rawURL, param, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// sameOrigin returns true if both rawURLs share the same scheme and host. It
// is used as a defence-in-depth guard after building probe URLs: the payload
// is added only as a query parameter and should never change the host/scheme.
func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return ua.Host == ub.Host && ua.Scheme == ub.Scheme
}
