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
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// loginBodyLimit caps per-probe response reads for the login probe.
const loginBodyLimit = 64 * 1024

// loginPaths are conventional login endpoint paths.
var loginPaths = []string{
	"/login",
	"/signin",
	"/sign-in",
	"/api/login",
	"/api/auth/login",
	"/api/auth/signin",
	"/api/v1/auth/login",
	"/api/v1/login",
	"/auth/login",
	"/user/login",
	"/account/login",
	"/users/sign_in",
}

// registrationPaths are conventional registration endpoint paths.
var registrationPaths = []string{
	"/register",
	"/signup",
	"/sign-up",
	"/api/register",
	"/api/auth/register",
	"/api/auth/signup",
	"/api/v1/auth/register",
	"/api/user/register",
	"/users/sign_up",
	"/account/register",
}

// defaultCredentials are well-known default username/password pairs.
var defaultCredentials = []struct{ username, password string }{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "123456"},
	{"admin", "admin123"},
	{"admin", "password123"},
	{"test", "test"},
	{"test", "password"},
	{"root", "root"},
	{"root", "toor"},
	{"user", "user"},
	{"demo", "demo"},
	{"guest", "guest"},
}

// RunLoginProbe tests login, registration, and account enumeration weaknesses:
//
//  1. Username enumeration on login — differing responses for valid vs. invalid users.
//  2. Login brute-force / no lockout — 15 wrong-password attempts without 429/lock.
//  3. Default credential acceptance — known default pairs accepted.
//  4. Registration user enumeration — "already registered" reveals account existence.
//  5. Password complexity not enforced — single-character password accepted.
//  6. API login rate-limit absent — 20 requests without throttling.
//  7. Login CSRF — login POST without CSRF token succeeds.
func (s *Service) RunLoginProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	loginEPs := loginDiscoverEndpoints(base, loginPaths, options.SeedRuntimeEndpoints, scanScope)
	regEPs := loginDiscoverEndpoints(base, registrationPaths, options.SeedRuntimeEndpoints, scanScope)

	if len(loginEPs) == 0 && len(regEPs) == 0 {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("login-probe %s", target),
			Message: fmt.Sprintf("Probing %d login and %d registration endpoints for enumeration, brute-force, and credential weaknesses", len(loginEPs), len(regEPs)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	// ── Probe 1: Username enumeration on login ─────────────────────────────
	fid := "login-username-enumeration"
	if !emitted[fid] {
		for _, ep := range loginEPs {
			if f := loginTestUsernameEnumeration(ctx, s, ep, auth, options); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 2: Login brute-force / no lockout ────────────────────────────
	fid = "login-no-lockout"
	if !emitted[fid] {
		for _, ep := range loginEPs {
			if loginTestBruteForce(ctx, s, ep, auth, options, 15) {
				emitted[fid] = true
				findings = append(findings, loginFinding(
					fid, ep, model.SeverityHigh,
					"Login endpoint lacks brute-force protection",
					fmt.Sprintf(
						"15 consecutive login attempts with incorrect passwords were sent to %s "+
							"without triggering HTTP 429 or an account lockout response. "+
							"The endpoint is vulnerable to password guessing and credential stuffing.",
						ep,
					),
					"CWE-307",
					[]string{
						"Submit 15+ login requests with wrong passwords to: " + ep,
						"Observe that no rate limiting or lockout is triggered.",
						"Continue guessing until the correct password is found.",
					},
					map[string]string{"attemptsWithoutLock": "15", "rateLimitDetected": "false"},
				))
				break
			}
		}
	}

	// ── Probe 3: Default credential acceptance ─────────────────────────────
	fid = "login-default-credentials"
	if !emitted[fid] {
		for _, ep := range loginEPs {
			if cred := loginTestDefaultCredentials(ctx, s, ep, auth, options); cred != nil {
				emitted[fid] = true
				findings = append(findings, loginFinding(
					fid, ep, model.SeverityCritical,
					"Default credentials accepted — account accessible with factory defaults",
					fmt.Sprintf(
						"The login endpoint %s accepted the default credential pair %q / %q "+
							"(HTTP 200 / session token in response). "+
							"Default credentials are the first thing an attacker tries and "+
							"indicate that post-deployment hardening was not performed.",
						ep, cred[0], cred[1],
					),
					"CWE-798",
					[]string{
						"Navigate to: " + ep,
						fmt.Sprintf("Submit username=%q and ******", cred[0]),
						"Observe that a valid session is established.",
					},
					map[string]string{"username": cred[0], "password": cred[1]},
				))
				break
			}
		}
	}

	// ── Probe 4: Registration user enumeration ─────────────────────────────
	fid = "registration-user-enumeration"
	if !emitted[fid] {
		for _, ep := range regEPs {
			if f := loginTestRegistrationEnumeration(ctx, s, ep, auth, options); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 5: Password complexity not enforced ──────────────────────────
	fid = "registration-weak-password-accepted"
	if !emitted[fid] {
		for _, ep := range regEPs {
			if loginTestWeakPassword(ctx, s, ep, auth, options) {
				emitted[fid] = true
				findings = append(findings, loginFinding(
					fid, ep, model.SeverityMedium,
					"Registration accepts single-character passwords — no complexity policy",
					fmt.Sprintf(
						"The registration endpoint %s accepted a single-character password (\"a\") "+
							"without returning a validation error. Weak password policies enable "+
							"accounts to be created with trivially guessable credentials.",
						ep,
					),
					"CWE-521",
					[]string{
						"Submit a registration request to: " + ep,
						"Set the password field to a single character (e.g., \"a\").",
						"Observe that the account is created without a complexity error.",
					},
					map[string]string{"passwordTested": "a", "complexityEnforced": "false"},
				))
				break
			}
		}
	}

	// ── Probe 6: API login rate-limit absent ───────────────────────────────
	fid = "api-login-no-ratelimit"
	if !emitted[fid] {
		for _, ep := range loginEPs {
			if strings.Contains(strings.ToLower(ep), "/api/") &&
				loginTestBruteForce(ctx, s, ep, auth, options, 20) {
				emitted[fid] = true
				findings = append(findings, loginFinding(
					fid, ep, model.SeverityHigh,
					"API login endpoint has no rate limiting — credential stuffing possible",
					fmt.Sprintf(
						"20 consecutive requests were sent to the API login endpoint %s without "+
							"triggering HTTP 429 or a lockout. API login paths are commonly excluded "+
							"from WAF rate-limiting rules, enabling high-volume credential stuffing.",
						ep,
					),
					"CWE-307",
					[]string{
						"Send 20+ POST requests to: " + ep,
						"Observe that no 429 or lockout response is returned.",
						"Use a credential list to perform credential stuffing.",
					},
					map[string]string{"attemptsWithoutThrottle": "20", "endpoint": ep},
				))
				break
			}
		}
	}

	// ── Probe 7: Login CSRF ────────────────────────────────────────────────
	fid = "login-csrf"
	if !emitted[fid] {
		for _, ep := range loginEPs {
			if f := loginTestLoginCSRF(ctx, s, ep, auth, options); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	return findings
}

// loginFinding constructs a standardized Finding for the login probe.
func loginFinding(id, endpoint string, severity model.Severity, title, evidence, cwe string, steps []string, extra map[string]string) model.Finding {
	ef := map[string]string{"validationType": "active-probe"}
	for k, v := range extra {
		ef[k] = v
	}
	return model.Finding{
		ID:                id,
		Category:          "authentication",
		Severity:          severity,
		Title:             title,
		Description:       "A login or registration authentication control was found to be absent or insufficiently enforced.",
		Evidence:          evidence,
		Recommendation:    "Implement account lockout or exponential back-off after failed login attempts. Require strong password complexity. Rotate all default credentials at deployment. Return identical responses for existing and non-existing accounts on login and registration.",
		Confidence:        0.80,
		AffectedURL:       endpoint,
		CWE:               cwe,
		OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
		Sources:           []string{"active-scanner", "login-probe"},
		ReproductionSteps: steps,
		BusinessTags:      []string{"login", "brute-force", "enumeration"},
		EvidenceFields:    ef,
	}
}

// loginDiscoverEndpoints returns in-scope login endpoints.
func loginDiscoverEndpoints(base *url.URL, paths []string, seeded []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string

	addEP := func(raw string) {
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		var ep string
		if ref.Scheme == "" || ref.Host == "" {
			ep = base.ResolveReference(ref).String()
		} else {
			ep = ref.String()
		}
		if _, ok := seen[ep]; ok {
			return
		}
		if !scope.IsURLInScope(ep, scanScope) {
			return
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}

	for _, p := range paths {
		addEP(p)
	}
	for _, s := range seeded {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "login") || strings.Contains(lower, "signin") ||
			strings.Contains(lower, "sign-in") || strings.Contains(lower, "register") ||
			strings.Contains(lower, "signup") {
			addEP(s)
		}
	}

	const max = 6
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// loginPost sends a login POST with given credentials and returns status + body.
func loginPost(ctx context.Context, s *Service, ep, username, password string, auth model.ScanAuthProfile, options model.ScanOptions) (int, string) {
	creds := map[string]string{
		"username": username,
		"email":    username,
		"login":    username,
		"password": password,
		"passwd":   password,
	}
	bodyJSON, _ := json.Marshal(creds)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return 0, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, loginBodyLimit))
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// loginTestUsernameEnumeration sends two requests — one for a likely-valid
// account and one for a synthetic non-existent account — and compares responses.
func loginTestUsernameEnumeration(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) *model.Finding {
	existing := "admin@example.com"
	synthetic := "abh-probe-nonexistent-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "@abh-scanner.invalid"

	status1, body1 := loginPost(ctx, s, ep, existing, "wrong-password-abh-probe", auth, options)
	status2, body2 := loginPost(ctx, s, ep, synthetic, "wrong-password-abh-probe", auth, options)

	if status1 == 0 && status2 == 0 {
		return nil
	}

	lower1 := strings.ToLower(body1)
	lower2 := strings.ToLower(body2)

	statusDiffers := status1 != status2
	bodyIndicatorDiffers := false
	accountExistIndicators := []string{"user not found", "no account", "email not registered", "account does not exist", "unknown email"}
	for _, ind := range accountExistIndicators {
		inBody1 := strings.Contains(lower1, ind)
		inBody2 := strings.Contains(lower2, ind)
		if inBody1 != inBody2 {
			bodyIndicatorDiffers = true
			break
		}
	}

	if statusDiffers || bodyIndicatorDiffers {
		return &model.Finding{
			ID:          "login-username-enumeration",
			Category:    "authentication",
			Severity:    model.SeverityMedium,
			Title:       "Username enumeration via differing login responses",
			Description: "The login endpoint returns different responses for existing and non-existing usernames, allowing attackers to enumerate registered accounts before launching targeted attacks.",
			Evidence: fmt.Sprintf(
				"POST %s — existing account returned HTTP %d; non-existent account returned HTTP %d; body differs: %v",
				ep, status1, status2, bodyIndicatorDiffers,
			),
			Recommendation:    "Return the same HTTP status code and response body for both valid and invalid usernames. Consider a generic message such as \"Invalid credentials\" for all failure cases.",
			Confidence:        0.72,
			AffectedURL:       ep,
			CWE:               "CWE-204",
			OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
			Sources:           []string{"active-scanner", "login-probe"},
			BusinessTags:      []string{"enumeration", "login"},
			ReproductionSteps: []string{
				"POST " + ep + " with an email known to exist and a wrong password.",
				"POST " + ep + " with a non-existent email and a wrong password.",
				"Compare the HTTP status codes and response bodies.",
			},
			EvidenceFields: map[string]string{
				"validationType":  "active-probe",
				"existingStatus":  fmt.Sprintf("%d", status1),
				"syntheticStatus": fmt.Sprintf("%d", status2),
				"bodyDiffers":     fmt.Sprintf("%v", bodyIndicatorDiffers),
			},
		}
	}
	return nil
}

// loginTestBruteForce submits n login attempts and returns true if none triggered
// a 429 or lockout.
func loginTestBruteForce(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions, n int) bool {
	for i := 0; i < n; i++ {
		status, _ := loginPost(ctx, s, ep, "admin", fmt.Sprintf("wrong-probe-pass-%d", i), auth, options)
		if status == http.StatusTooManyRequests || status == http.StatusLocked {
			return false
		}
		if status == 0 {
			return false
		}
	}
	return true
}

// loginTestDefaultCredentials tries default cred pairs and returns the first
// successful pair, or nil.
func loginTestDefaultCredentials(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) []string {
	for _, cred := range defaultCredentials {
		status, body := loginPost(ctx, s, ep, cred.username, cred.password, auth, options)
		if status >= 200 && status < 300 {
			lower := strings.ToLower(body)
			// Exclude obvious rejection patterns.
			if !strings.Contains(lower, "invalid") &&
				!strings.Contains(lower, "incorrect") &&
				!strings.Contains(lower, "unauthorized") &&
				!strings.Contains(lower, "wrong") {
				return []string{cred.username, cred.password}
			}
		}
	}
	return nil
}

// loginTestRegistrationEnumeration registers with a likely-existing email
// and checks if the server reveals it is taken.
func loginTestRegistrationEnumeration(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) *model.Finding {
	existingEmail := "admin@example.com"
	body := map[string]string{
		"username": existingEmail,
		"email":    existingEmail,
		"password": "ABH-Probe-Test-P@ss1!",
	}
	bodyJSON, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, loginBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(rb))
	enumerationIndicators := []string{
		"already registered", "already exists", "email taken",
		"username taken", "account exists", "email already",
	}
	for _, ind := range enumerationIndicators {
		if strings.Contains(lower, ind) {
			return &model.Finding{
				ID:          "registration-user-enumeration",
				Category:    "authentication",
				Severity:    model.SeverityLow,
				Title:       "Registration endpoint reveals whether account already exists",
				Description: "The registration endpoint returns a distinct error message when the submitted email/username is already registered. Attackers can use this to determine which accounts exist before launching targeted attacks.",
				Evidence:    fmt.Sprintf("POST %s → HTTP %d with body containing %q", ep, resp.StatusCode, ind),
				Recommendation: "Return the same response message for both new and existing accounts (e.g., \"If this address is not registered, you will receive a confirmation email\").",
				Confidence:    0.75,
				AffectedURL:   ep,
				CWE:           "CWE-204",
				OWASPCategory: "A07:2021 - Identification and Authentication Failures",
				Sources:       []string{"active-scanner", "login-probe"},
				BusinessTags:  []string{"enumeration", "registration"},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"indicator":      ind,
					"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
				},
			}
		}
	}
	return nil
}

// loginTestWeakPassword attempts registration with a single-character password.
func loginTestWeakPassword(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) bool {
	uniqueEmail := fmt.Sprintf("abh-probe-weakpw-%d@abh-scanner.invalid", time.Now().UnixNano()%1000000)
	body := map[string]string{
		"username": uniqueEmail,
		"email":    uniqueEmail,
		"password": "a",
		"passwd":   "a",
	}
	bodyJSON, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return false
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, loginBodyLimit))
	_ = resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		lower := strings.ToLower(string(rb))
		// Exclude obvious rejection patterns.
		if !strings.Contains(lower, "password") || strings.Contains(lower, "created") ||
			strings.Contains(lower, "success") || strings.Contains(lower, "registered") {
			return true
		}
	}
	return false
}

// loginTestLoginCSRF submits a login POST without a CSRF token and checks if
// the server accepts it.
func loginTestLoginCSRF(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) *model.Finding {
	creds := map[string]string{
		"username": "admin",
		"email":    "admin@example.com",
		"password": "admin",
	}
	bodyJSON, _ := json.Marshal(creds)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	// Deliberately omit any CSRF token header.
	// Apply base auth headers but remove any csrf-token.
	ApplyAuthProfile(req, auth)
	req.Header.Del("X-CSRF-Token")
	req.Header.Del("X-XSRF-TOKEN")
	req.Header.Del("csrf-token")

	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, loginBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(rb))
	csrfRejected := strings.Contains(lower, "csrf") ||
		strings.Contains(lower, "forbidden") ||
		resp.StatusCode == http.StatusForbidden

	if !csrfRejected && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &model.Finding{
			ID:          "login-csrf",
			Category:    "authentication",
			Severity:    model.SeverityMedium,
			Title:       "Login endpoint missing CSRF protection",
			Description: "The login endpoint accepted a POST request without a CSRF token. An attacker can craft a malicious page that auto-submits a login form, silently authenticating the victim as an attacker-controlled account (login CSRF), enabling account takeover via session fixation.",
			Evidence:    fmt.Sprintf("POST %s without CSRF token → HTTP %d", ep, resp.StatusCode),
			Recommendation: "Require a synchronizer CSRF token on the login form. Validate it server-side before processing credentials. Combine with SameSite=Strict cookies to provide defense in depth.",
			Confidence:    0.70,
			AffectedURL:   ep,
			CWE:           "CWE-352",
			OWASPCategory: "A07:2021 - Identification and Authentication Failures",
			Sources:       []string{"active-scanner", "login-probe"},
			BusinessTags:  []string{"csrf", "login", "session-fixation"},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"csrfTokenSent":  "false",
				"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
			},
		}
	}
	return nil
}
