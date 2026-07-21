package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// pwResetBodyLimit caps per-probe response reads for the password reset probe.
const pwResetBodyLimit = 128 * 1024

// pwResetProbePaths are conventional endpoints for password-reset initiation.
var pwResetProbePaths = []string{
	"/forgot-password",
	"/api/auth/forgot-password",
	"/api/auth/reset-request",
	"/api/user/forgot-password",
	"/api/password/reset",
	"/api/password-reset",
	"/password-reset",
	"/auth/forgot-password",
	"/account/forgot-password",
	"/users/password",
}

// pwResetTokenFields are response body field names that may contain a reset
// token in verbose APIs or development builds.
var pwResetTokenFields = []string{"token", "resetToken", "reset_token", "code", "verificationCode", "otp"}

// pwResetTestEmail is the email address submitted in all reset requests.
// Use a clearly synthetic address that no production user would own.
const pwResetTestEmail = "abh-probe-test-user@abh-scanner.invalid"

// runPasswordResetProbe is a multi-step probe for password-reset account
// takeover vulnerabilities:
//
//  1. POST to common reset-initiation endpoints with pwResetTestEmail.
//     If the response includes a reset token (verbose API / dev build),
//     harvest it via HarvestFromResponse.
//
//  2. If a token was harvested, attempt to use it to set a new password at
//     the same or a sibling endpoint. Success indicates account takeover
//     via reset token disclosure.
//
//  3. Inject an attacker-controlled Host header in the reset initiation
//     request. If the server reflects the poisoned host in its response
//     (e.g. in a reset URL), emit a host-header poisoning finding.
func (s *Service) runPasswordResetProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly || input.Session == nil {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("password-reset-probe %s", input.Target),
			Message: "Probing for password reset token disclosure and host-header poisoning",
		})
	}

	candidates := collectPWResetCandidates(base, input.Options.SeedRuntimeEndpoints, input.Scope)
	if len(candidates) == 0 {
		return nil
	}
	for _, ep := range candidates {
		RecordProbedKey(http.MethodPost, ep, "email")
	}

	var findings []model.Finding

	for _, resetEP := range candidates {
		// Build reset initiation body.
		body := pwResetBuildBody(pwResetTestEmail)
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			continue
		}

		// Step 1: POST to reset endpoint.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, resetEP, bytes.NewReader(bodyJSON))
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, pwResetBodyLimit))
		_ = resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 500 {
			continue
		}

		// Harvest any token the API disclosed.
		input.Session.HarvestFromResponse(resp, respBody)
		token := extractResetToken(respBody)

		// Step 2: If a token was leaked, attempt to use it.
		if token != "" {
			if f := s.tryResetWithToken(ctx, input, base, resetEP, token); f != nil {
				findings = append(findings, *f)
			}
		}

		// Step 3: Host-header poisoning test on the same endpoint.
		if f := s.testResetHostHeaderPoisoning(ctx, input, resetEP, bodyJSON); f != nil {
			findings = append(findings, *f)
		}

		if len(findings) > 0 {
			break // one confirmed issue per scan is sufficient
		}
	}

	return findings
}

// pwResetBuildBody builds the JSON body for a reset initiation request,
// populating the most common email field names.
func pwResetBuildBody(email string) map[string]string {
	return map[string]string{"email": email}
}

// extractResetToken scans a JSON response body for well-known reset-token
// field names and returns the first non-empty value found.
func extractResetToken(body []byte) string {
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	for _, field := range pwResetTokenFields {
		if v, ok := parsed[field]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func pwResetInvalidControlToken(token string) string {
	control := strings.ReplaceAll(RandomMarker(), "_", "")
	if len(token) <= 0 {
		return control
	}
	for len(control) < len(token) {
		control += "x"
	}
	if len(control) > len(token) {
		control = control[:len(token)]
	}
	return control
}

// tryResetWithToken attempts to consume a disclosed reset token to change the
// account password. Returns a finding when the reset succeeds.
func (s *Service) tryResetWithToken(ctx context.Context, input RunInput, base *url.URL, resetEP, token string) *model.Finding {
	// Build reset-consumption body.
	body := map[string]string{
		"token":       token,
		"newPassword": "ABH-Probe-P@ssw0rd-8742",
		"password":    "ABH-Probe-P@ssw0rd-8742",
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil
	}

	// Try the same endpoint and common sibling paths.
	candidates := []string{resetEP}
	for _, p := range []string{"/api/auth/reset-password", "/api/password/reset/confirm", "/reset-password", "/auth/reset"} {
		candidates = append(candidates, base.ResolveReference(&url.URL{Path: p}).String())
	}

	for _, ep := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, pwResetBodyLimit))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		// Weak signal: 2xx AND body contains success indicators.
		lower := strings.ToLower(string(respBody))
		successIndicators := strings.Contains(lower, "success") ||
			strings.Contains(lower, "updated") ||
			strings.Contains(lower, "changed") ||
			strings.Contains(lower, "password")
		if !successIndicators {
			continue
		}
		controlToken := pwResetInvalidControlToken(token)
		controlBody := map[string]string{
			"token":       controlToken,
			"newPassword": body["newPassword"],
			"password":    body["password"],
		}
		controlJSON, err := json.Marshal(controlBody)
		if err != nil {
			continue
		}
		controlReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(controlJSON))
		if err != nil {
			continue
		}
		ApplyAuthProfile(controlReq, input.AuthProfile)
		controlReq.Header.Set("Content-Type", "application/json")
		controlResp, err := s.doRequestWithSession(ctx, controlReq, input.Options, input.Session)
		if err != nil || controlResp == nil {
			continue
		}
		controlRespBody, _ := io.ReadAll(io.LimitReader(controlResp.Body, pwResetBodyLimit))
		_ = controlResp.Body.Close()
		controlLower := strings.ToLower(string(controlRespBody))
		controlAccepted := controlResp.StatusCode >= 200 && controlResp.StatusCode < 300 &&
			(strings.Contains(controlLower, "success") ||
				strings.Contains(controlLower, "updated") ||
				strings.Contains(controlLower, "changed") ||
				strings.Contains(controlLower, "password"))
		if controlAccepted {
			continue
		}
		return &model.Finding{
			ID:       "password-reset-token-disclosure",
			Category: "authentication",
			Severity: model.SeverityCritical,
			Title:    "Password reset token disclosed in API response — account takeover confirmed",
			Description: fmt.Sprintf(
				"The API at %s disclosed a plaintext password-reset token in the JSON response body "+
					"(%q). The token was successfully consumed at %s to demonstrate account takeover, while a valid-shaped invalid control token was rejected. "+
					"Any party who can intercept the response (MITM, logging infrastructure, browser "+
					"history) gains the ability to take over the associated account.",
				resetEP, token, ep,
			),
			Evidence: fmt.Sprintf(
				"POST %s → token=%q disclosed; POST %s with token → HTTP %d; invalid control token → HTTP %d",
				resetEP, truncateString(token, 20), ep, resp.StatusCode, controlResp.StatusCode,
			),
			Recommendation: "Never return reset tokens in API responses. Send them only via a secure " +
				"out-of-band channel (email). Tokens must be single-use, time-limited (≤15 min), " +
				"and cryptographically random (≥128 bits). Expire them immediately upon use.",
			Confidence:    0.90,
			AffectedURL:   resetEP,
			CWE:           "CWE-640",
			OWASPCategory: "A07:2021 - Identification and Authentication Failures",
			Sources:       []string{"active-scanner", "password-reset-probe"},
			BusinessTags:  []string{"account-takeover", "password-reset", "token-disclosure"},
			EvidenceFields: map[string]string{
				"validationType":       "active-probe",
				"resetEndpoint":        resetEP,
				"consumeEndpoint":      ep,
				"disclosedToken":       truncateString(token, 20),
				"responseStatus":       fmt.Sprintf("%d", resp.StatusCode),
				"controlTokenRejected": "true",
				"controlStatus":        fmt.Sprintf("%d", controlResp.StatusCode),
				"method":               http.MethodPost,
				"url":                  resetEP,
				"param":                "token",
				"oracleName":           "password_reset_probe",
				"oracleVersion":        "v1",
			},
		}
	}
	return nil
}

// testResetHostHeaderPoisoning injects an attacker-controlled Host header into
// a reset request and checks whether the poisoned value appears in the
// response (which would indicate it might be embedded in reset emails).
func (s *Service) testResetHostHeaderPoisoning(ctx context.Context, input RunInput, resetEP string, bodyJSON []byte) *model.Finding {
	const poisonedHost = "abh-host-header-canary.invalid"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resetEP, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", poisonedHost)
	req.Header.Set("X-Forwarded-Host", poisonedHost)

	resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
	if err != nil || resp == nil {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, pwResetBodyLimit))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	// Check if the poisoned host appears in the response (e.g. in a reset link).
	if !strings.Contains(string(respBody), poisonedHost) {
		return nil
	}

	return &model.Finding{
		ID:       "password-reset-host-header-poisoning",
		Category: "authentication",
		Severity: model.SeverityHigh,
		Title:    "Password reset link poisoning via Host header injection",
		Description: fmt.Sprintf(
			"A forged Host header (%q) was reflected in the response body of the password-reset "+
				"initiation endpoint %s. If the server constructs the reset URL from the Host "+
				"header, an attacker can poison reset emails to point to an attacker-controlled "+
				"domain, stealing the reset token when the victim clicks the link.",
			poisonedHost, resetEP,
		),
		Evidence: fmt.Sprintf(
			"POST %s with Host: %s → poisoned host reflected in HTTP %d response body",
			resetEP, poisonedHost, resp.StatusCode,
		),
		Recommendation: "Construct reset URLs from an allowlisted base URL configured in server-side " +
			"application settings, never from the incoming Host header. Validate and reject " +
			"requests whose Host header does not match the allowlist.",
		Confidence:    0.82,
		AffectedURL:   resetEP,
		CWE:           "CWE-601",
		OWASPCategory: "A07:2021 - Identification and Authentication Failures",
		Sources:       []string{"active-scanner", "password-reset-probe"},
		BusinessTags:  []string{"host-header-injection", "password-reset", "account-takeover"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"poisonedHost":   poisonedHost,
			"resetEndpoint":  resetEP,
			"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
			"method":         http.MethodPost,
			"url":            resetEP,
			"oracleName":     "password_reset_probe",
			"oracleVersion":  "v1",
		},
	}
}

// collectPWResetCandidates returns in-scope reset-initiation endpoints.
func collectPWResetCandidates(base *url.URL, seedEndpoints []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		var resolved *url.URL
		if ref.Scheme == "" || ref.Host == "" {
			resolved = base.ResolveReference(ref)
		} else {
			resolved = ref
		}
		s := resolved.String()
		if _, ok := seen[s]; ok {
			return
		}
		if !scope.IsURLInScope(s, scanScope) {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	for _, p := range pwResetProbePaths {
		add(p)
	}

	for _, ep := range seedEndpoints {
		lower := strings.ToLower(ep)
		if strings.Contains(lower, "forgot") ||
			strings.Contains(lower, "reset") ||
			strings.Contains(lower, "recover") {
			add(ep)
		}
	}

	const max = 6
	if len(out) > max {
		out = out[:max]
	}
	return out
}
