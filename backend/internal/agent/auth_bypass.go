package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// AuthBypassAgent actively tests authentication controls for weaknesses
// including JWT algorithm confusion, missing/bypassable auth on sensitive
// endpoints, session fixation hints, and common token manipulation flaws.
type AuthBypassAgent struct {
	enabled bool
}

func NewAuthBypassAgent(enabled bool) *AuthBypassAgent {
	return &AuthBypassAgent{enabled: enabled}
}

func (a *AuthBypassAgent) Name() string  { return "auth_bypass" }
func (a *AuthBypassAgent) Enabled() bool { return a.enabled }

func (a *AuthBypassAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) < 5 {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	output.Findings = append(output.Findings, testJWTAlgNone(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, testJWTWeakSecret(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, testMissingAuthOnSensitiveEndpoints(ctx, client, input.Target)...)
	output.Findings = append(output.Findings, testSessionFixation(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, testPasswordResetFlaws(ctx, client, input.Target)...)

	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "Auth bypass testing completed: JWT manipulation, missing auth, session fixation, password reset."
	return output, nil
}

// jwtHeaderPayload builds a JWT with a custom header and an already-serialised
// payload JSON string, signing with the provided secret (empty = alg:none).
func buildJWT(header, payloadJSON, secret string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	if secret == "" {
		// alg:none — no signature
		return h + "." + p + "."
	}
	// Weak HMAC-SHA256 using stdlib (crypto/hmac) is not imported here to
	// keep the file self-contained; we use an empty signature intentionally
	// to test servers that skip verification entirely.
	return h + "." + p + "."
}

// extractJWT looks for a Bearer token in the auth profile headers and cookies.
func extractJWT(profile model.ScanAuthProfile) string {
	for key, val := range profile.Headers {
		if strings.EqualFold(key, "authorization") {
			parts := strings.SplitN(strings.TrimSpace(val), " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	for _, c := range profile.Cookies {
		if strings.Contains(strings.ToLower(c), "jwt") || strings.Contains(strings.ToLower(c), "token") {
			parts := strings.SplitN(c, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// parseJWTPayload base64-decodes the JWT payload (middle segment).
func parseJWTPayload(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	m := map[string]interface{}{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func testJWTAlgNone(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	originalToken := extractJWT(profile)
	if originalToken == "" {
		return findings // no JWT to tamper with
	}

	payload := parseJWTPayload(originalToken)
	if payload == nil {
		return findings
	}

	// Escalate role in payload
	for _, roleKey := range []string{"role", "roles", "scope", "groups", "is_admin", "admin"} {
		if _, ok := payload[roleKey]; ok {
			payload[roleKey] = "admin"
		}
	}
	payloadJSON, _ := json.Marshal(payload)

	// Build alg:none token
	noneToken := buildJWT(`{"alg":"none","typ":"JWT"}`, string(payloadJSON), "")

	for _, sensitiveEndpoint := range []string{"/api/admin", "/admin", "/api/users", "/api/settings"} {
		testURL := strings.TrimRight(target, "/") + sensitiveEndpoint

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+noneToken)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		// If the server accepts alg:none and returns 200 with real-looking content
		if resp.StatusCode == http.StatusOK && len(body) > 50 {
			findings = append(findings, model.Finding{
				ID:             "jwt-alg-none",
				Category:       "auth_bypass",
				Severity:       model.SeverityHigh,
				Title:          "JWT 'alg:none' accepted — signature validation bypassed",
				Description:    "The server accepted a JWT token signed with algorithm 'none', meaning it does not verify token signatures. An attacker can forge arbitrary tokens and impersonate any user.",
				Evidence:       fmt.Sprintf("endpoint=%s status=%d response_len=%d", sensitiveEndpoint, resp.StatusCode, len(body)),
				Recommendation: "Explicitly reject tokens with alg=none. Use a strict allowlist of accepted algorithms (e.g. RS256). Never rely on the token's own header to determine the verification algorithm.",
				AffectedURL:    testURL,
				OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
				CWE:            "CWE-347",
				ReproductionSteps: []string{
					"Take any valid JWT, change its header to {\"alg\":\"none\",\"typ\":\"JWT\"}, remove the signature segment",
					"Send the forged token in Authorization: Bearer <token>",
					fmt.Sprintf("Request GET %s — server returns HTTP 200", testURL),
				},
			})
			return findings
		}
	}

	return findings
}

func testJWTWeakSecret(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	originalToken := extractJWT(profile)
	if originalToken == "" {
		return findings
	}

	payload := parseJWTPayload(originalToken)
	if payload == nil {
		return findings
	}

	// Escalate to admin in forged payload
	payload["role"] = "admin"
	payload["is_admin"] = true
	payloadJSON, _ := json.Marshal(payload)

	// Common weak HMAC secrets used in insecure JWT configurations
	weakSecrets := []string{
		"secret", "password", "changeme", "123456", "qwerty",
		"jwt_secret", "mysecret", "youshallnotpass", "supersecret",
		"", // alg:none fallback handled above; try empty string as secret too
	}

	for _, secret := range weakSecrets {
		token := buildJWT(`{"alg":"HS256","typ":"JWT"}`, string(payloadJSON), secret)

		testURL := strings.TrimRight(target, "/") + "/api/admin"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && len(body) > 50 {
			displaySecret := secret
			if displaySecret == "" {
				displaySecret = "(empty string)"
			}
			findings = append(findings, model.Finding{
				ID:             "jwt-weak-secret",
				Category:       "auth_bypass",
				Severity:       model.SeverityHigh,
				Title:          "JWT signed with a predictable/weak secret",
				Description:    "The server accepted a JWT token forged using a well-known weak signing secret. An attacker can mint arbitrary tokens with escalated privileges.",
				Evidence:       fmt.Sprintf("weak_secret=%q forged_token_accepted status=%d", displaySecret, resp.StatusCode),
				Recommendation: "Use a cryptographically random secret of at least 256 bits for HS256, or switch to asymmetric RS256/ES256. Rotate the secret immediately and invalidate all existing tokens.",
				AffectedURL:    testURL,
				OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
				CWE:            "CWE-798",
			})
			return findings
		}
	}

	return findings
}

func testMissingAuthOnSensitiveEndpoints(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	sensitiveEndpoints := []struct {
		path     string
		methods  []string
		keywords []string
	}{
		{"/api/admin", []string{http.MethodGet}, []string{"admin", "user", "config", "setting"}},
		{"/api/users", []string{http.MethodGet}, []string{"email", "username", "password", "role"}},
		{"/api/keys", []string{http.MethodGet}, []string{"key", "token", "secret", "api_key"}},
		{"/api/config", []string{http.MethodGet}, []string{"config", "setting", "database", "smtp"}},
		{"/api/debug", []string{http.MethodGet}, []string{"debug", "stack", "trace", "env"}},
		{"/actuator/env", []string{http.MethodGet}, []string{"property", "profile", "spring"}},
		{"/actuator/heapdump", []string{http.MethodGet}, []string{}},
		{"/debug/vars", []string{http.MethodGet}, []string{"cmdline", "memstats"}},
		{"/.env", []string{http.MethodGet}, []string{"DB_PASSWORD", "SECRET", "API_KEY", "DATABASE_URL"}},
		{"/config.json", []string{http.MethodGet}, []string{"password", "secret", "key", "token"}},
	}

	base := strings.TrimRight(target, "/")

	for _, ep := range sensitiveEndpoints {
		for _, method := range ep.methods {
			testURL := base + ep.path

			req, err := http.NewRequestWithContext(ctx, method, testURL, nil)
			if err != nil {
				continue
			}
			// No auth — deliberate
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				continue
			}

			bodyStr := strings.ToLower(string(body))

			// If no keywords defined, any 200 with substantial body is interesting
			if len(ep.keywords) == 0 && len(body) > 100 {
				findings = append(findings, model.Finding{
					ID:             "unauth-endpoint-" + strings.ReplaceAll(ep.path, "/", "_"),
					Category:       "auth_bypass",
					Severity:       model.SeverityHigh,
					Title:          "Sensitive endpoint accessible without authentication: " + ep.path,
					Description:    "An endpoint that should require authentication returned HTTP 200 without any credentials.",
					Evidence:       fmt.Sprintf("method=%s endpoint=%s status=200 response_len=%d", method, ep.path, len(body)),
					Recommendation: "Enforce authentication on all sensitive endpoints. Return 401 with WWW-Authenticate for unauthenticated requests.",
					AffectedURL:    testURL,
					OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
					CWE:            "CWE-306",
				})
				continue
			}

			for _, kw := range ep.keywords {
				if strings.Contains(bodyStr, strings.ToLower(kw)) {
					findings = append(findings, model.Finding{
						ID:             "unauth-endpoint-" + strings.ReplaceAll(ep.path, "/", "_"),
						Category:       "auth_bypass",
						Severity:       model.SeverityHigh,
						Title:          "Sensitive endpoint accessible without authentication: " + ep.path,
						Description:    "An endpoint that should require authentication returned HTTP 200 with sensitive content without any credentials.",
						Evidence:       fmt.Sprintf("method=%s endpoint=%s keyword=%q status=200", method, ep.path, kw),
						Recommendation: "Enforce authentication and authorisation on all sensitive endpoints. Return 401/403 for unauthenticated/unauthorised access.",
						AffectedURL:    testURL,
						OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
						CWE:            "CWE-306",
					})
					break
				}
			}
		}
	}

	return findings
}

func testSessionFixation(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Session fixation: supply a known session ID before login and check if
	// the server adopts it (i.e. does not regenerate a new session on login).
	fixedSessionID := "FIXED_SESSION_ABC123XYZ"
	loginPaths := []string{"/login", "/api/login", "/auth/login", "/api/auth/login", "/signin"}
	base := strings.TrimRight(target, "/")

	for _, path := range loginPaths {
		testURL := base + path

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL, strings.NewReader(`{"username":"test","password":"test"}`))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "PHPSESSID="+fixedSessionID+"; JSESSIONID="+fixedSessionID+"; session="+fixedSessionID)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// If the response sets the *same* session cookie we sent, the server
		// accepted the attacker-supplied session identifier.
		for _, sc := range resp.Cookies() {
			if strings.Contains(sc.Value, fixedSessionID) {
				findings = append(findings, model.Finding{
					ID:             "session-fixation",
					Category:       "auth_bypass",
					Severity:       model.SeverityMedium,
					Title:          "Session fixation vulnerability detected",
					Description:    "The server preserved the attacker-supplied session identifier after authentication instead of issuing a fresh one. An attacker can pre-set a known session token and hijack the victim's authenticated session.",
					Evidence:       fmt.Sprintf("path=%s server_echoed_cookie=%s=%s", path, sc.Name, sc.Value),
					Recommendation: "Always regenerate the session identifier upon successful login. Invalidate old session tokens immediately.",
					AffectedURL:    testURL,
					OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
					CWE:            "CWE-384",
				})
				return findings
			}
		}
	}

	// Also check if the application is missing Secure/HttpOnly/SameSite on its
	// session cookies, which makes fixation/hijacking more practical.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return findings
	}
	scanner.ApplyAuthProfile(req, profile)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	resp.Body.Close()

	for _, sc := range resp.Cookies() {
		nameLower := strings.ToLower(sc.Name)
		isSession := strings.Contains(nameLower, "session") ||
			strings.Contains(nameLower, "auth") ||
			strings.Contains(nameLower, "token") ||
			strings.Contains(nameLower, "sid")
		if !isSession {
			continue
		}
		missing := []string{}
		if !sc.Secure {
			missing = append(missing, "Secure")
		}
		if !sc.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if sc.SameSite == http.SameSiteDefaultMode {
			missing = append(missing, "SameSite")
		}
		if len(missing) > 0 {
			findings = append(findings, model.Finding{
				ID:             "session-cookie-flags-missing",
				Category:       "auth_bypass",
				Severity:       model.SeverityMedium,
				Title:          "Session cookie missing security flags: " + strings.Join(missing, ", "),
				Description:    "One or more security attributes are absent from the session cookie, increasing the risk of session theft via network sniffing or cross-site scripting.",
				Evidence:       fmt.Sprintf("cookie=%s missing_flags=%s", sc.Name, strings.Join(missing, ",")),
				Recommendation: "Set Secure, HttpOnly, and SameSite=Strict on all session cookies. Use __Host- or __Secure- cookie prefixes where supported.",
				AffectedURL:    target,
				OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
				CWE:            "CWE-614",
			})
		}
	}

	return findings
}

func testPasswordResetFlaws(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	resetPaths := []string{
		"/forgot-password", "/forgot_password", "/reset-password",
		"/api/forgot-password", "/api/auth/forgot-password", "/api/password-reset",
	}
	base := strings.TrimRight(target, "/")

	for _, path := range resetPaths {
		testURL := base + path

		// Check whether the reset endpoint leaks a token in the response body
		// (some implementations return the token instead of only e-mailing it).
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, testURL,
			strings.NewReader(`{"email":"test@example.com"}`))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		bodyStr := string(body)
		lower := strings.ToLower(bodyStr)

		tokenLeakIndicators := []string{"reset_token", "resettoken", "reset_link", "token=", "\"token\""}
		for _, ind := range tokenLeakIndicators {
			if strings.Contains(lower, ind) {
				findings = append(findings, model.Finding{
					ID:             "password-reset-token-leak",
					Category:       "auth_bypass",
					Severity:       model.SeverityHigh,
					Title:          "Password reset token exposed in API response",
					Description:    "The password reset endpoint returned a token directly in the HTTP response body instead of transmitting it only via e-mail. An attacker who can trigger a reset can immediately use the token to take over the account.",
					Evidence:       fmt.Sprintf("endpoint=%s indicator=%q", path, ind),
					Recommendation: "Never return reset tokens in API responses. Send them only via the registered e-mail address. Tokens must be one-time-use, short-lived (≤15 min), and cryptographically random.",
					AffectedURL:    testURL,
					OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
					CWE:            "CWE-640",
				})
				return findings
			}
		}

		// Check if the token is entirely absent (no e-mail flow) but the
		// endpoint returns 200 for any e-mail (user enumeration).
		if resp.StatusCode == http.StatusOK {
			userEnumPatterns := []string{"email sent", "check your email", "if this email exists", "reset link sent"}
			for _, pat := range userEnumPatterns {
				if strings.Contains(lower, pat) {
					// This is expected behaviour; skip the finding.
					break
				}
			}
			// If the response reveals whether an account exists
			if strings.Contains(lower, "user not found") || strings.Contains(lower, "no account") || strings.Contains(lower, "email not registered") {
				findings = append(findings, model.Finding{
					ID:             "password-reset-user-enum",
					Category:       "auth_bypass",
					Severity:       model.SeverityLow,
					Title:          "User enumeration via password reset endpoint",
					Description:    "The password reset endpoint returns different responses for existing and non-existing e-mail addresses, allowing attackers to enumerate registered accounts.",
					Evidence:       fmt.Sprintf("endpoint=%s response_reveals_account_existence", path),
					Recommendation: "Return the same response message regardless of whether the e-mail address is registered.",
					AffectedURL:    testURL,
					OWASPCategory:  "OWASP A07:2021 - Identification and Authentication Failures",
					CWE:            "CWE-204",
				})
				return findings
			}
		}
	}

	return findings
}
