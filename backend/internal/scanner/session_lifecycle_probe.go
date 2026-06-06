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

// sessionLifecycleBodyLimit caps per-probe response reads.
const sessionLifecycleBodyLimit = 64 * 1024

// sessionLogoutPaths are conventional logout endpoint paths.
var sessionLogoutPaths = []string{
	"/logout",
	"/signout",
	"/sign-out",
	"/api/logout",
	"/api/auth/logout",
	"/api/auth/signout",
	"/api/v1/auth/logout",
	"/auth/logout",
	"/user/logout",
	"/account/logout",
}

// sessionProtectedPaths are paths expected to be authentication-gated;
// used to verify whether a session is still valid after revocation.
var sessionProtectedPaths = []string{
	"/api/me",
	"/api/user",
	"/api/profile",
	"/api/account",
	"/api/v1/me",
	"/api/v1/user",
	"/profile",
	"/dashboard",
	"/account",
}

// passwordChangePaths are conventional password-change endpoint paths.
var passwordChangePaths = []string{
	"/api/user/password",
	"/api/auth/password",
	"/api/settings/password",
	"/api/account/password",
	"/api/password",
}

// sessionAuthCookieHints are cookie name patterns that suggest an
// authentication or session cookie.
var sessionAuthCookieHints = []string{
	"session", "auth", "token", "jwt", "sid", "sess", "id",
}

// RunSessionLifecycleProbe tests session management weaknesses:
//
//  1. Session rotation after login — session ID must change post-login.
//  2. Session invalidated on logout — cookie rejected after logout.
//  3. Session invalidated on password change — old session rejected.
//  4. Concurrent session — two sessions active simultaneously (Info).
//  5. Cookie missing Secure flag.
//  6. Cookie missing HttpOnly flag.
//  7. Cookie SameSite not Strict/Lax.
//  8. Cookie overly broad domain scope.
func (s *Service) RunSessionLifecycleProbe(
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

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("session-lifecycle-probe %s", target),
			Message: "Probing session rotation, invalidation, and cookie security attributes",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	// ── Probes 5-8: Cookie attribute analysis (passive, no extra requests) ──
	// Issue a single GET to the target and inspect Set-Cookie headers.
	req0, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err == nil {
		ApplyAuthProfile(req0, auth)
		resp0, err := s.doRequestWithRetry(ctx, req0, options)
		if err == nil && resp0 != nil {
			body0, _ := io.ReadAll(io.LimitReader(resp0.Body, sessionLifecycleBodyLimit))
			_ = resp0.Body.Close()
			_ = body0

			cookieFindings := sessionAnalyzeCookieHeaders(resp0.Cookies(), base, target)
			for _, cf := range cookieFindings {
				if !emitted[cf.ID] {
					emitted[cf.ID] = true
					findings = append(findings, cf)
				}
			}
		}
	}

	// ── Probe 1: Session rotation after login ──────────────────────────────
	fid := "session-no-rotation-after-login"
	if !emitted[fid] && hasStandardLoginCredentials(auth) {
		preLoginCookie := sessionExtractSessionCookie(auth)
		if preLoginCookie != "" {
			// Attempt login and compare the session identifier.
			loginEPs := sessionDiscoverLoginEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
			for _, ep := range loginEPs {
				newCookie := sessionAttemptLoginAndGetCookie(ctx, s, ep, auth, options)
				if newCookie != "" && newCookie == preLoginCookie {
					emitted[fid] = true
					findings = append(findings, model.Finding{
						ID:          fid,
						Category:    "authentication",
						Severity:    model.SeverityHigh,
						Title:       "Session identifier not rotated after login",
						Description: "The session cookie value was identical before and after authentication. The server did not issue a new session identifier upon login, leaving the session vulnerable to fixation attacks where an attacker pre-sets a known session ID and hijacks the authenticated session.",
						Evidence:    fmt.Sprintf("Session cookie value unchanged before/after login at %s: %q", ep, truncateString(preLoginCookie, 30)),
						Recommendation: "Regenerate the session identifier immediately upon successful authentication. Invalidate the pre-login session and issue a new, cryptographically random session token.",
						Confidence:    0.85,
						AffectedURL:   ep,
						CWE:           "CWE-384",
						OWASPCategory: "A07:2021 - Identification and Authentication Failures",
						Sources:       []string{"active-scanner", "session-lifecycle-probe"},
						BusinessTags:  []string{"session-fixation", "session-rotation"},
						EvidenceFields: map[string]string{
							"validationType":  "active-probe",
							"preLoginCookie":  truncateString(preLoginCookie, 30),
							"postLoginCookie": truncateString(newCookie, 30),
						},
					})
					break
				}
			}
		}
	}

	// ── Probe 2: Session invalidated on logout ─────────────────────────────
	fid = "session-not-invalidated-on-logout"
	if !emitted[fid] {
		bearerToken := oauthExtractBearerToken(auth)
		sessionCookie := sessionExtractSessionCookie(auth)
		credential := bearerToken
		if credential == "" {
			credential = sessionCookie
		}

		if credential != "" {
			logoutEPs := sessionDiscoverLogoutEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
			protectedEPs := sessionDiscoverProtectedEndpoints(base, options.SeedRuntimeEndpoints, scanScope)

			for _, logoutEP := range logoutEPs {
				// Call logout.
				lReq, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutEP, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(lReq, auth)
				lResp, err := s.doRequestWithRetry(ctx, lReq, options)
				if err != nil || lResp == nil {
					continue
				}
				_ = lResp.Body.Close()
				logoutAccepted := lResp.StatusCode >= 200 && lResp.StatusCode < 400

				if !logoutAccepted {
					// Also try GET logout.
					lReq2, err := http.NewRequestWithContext(ctx, http.MethodGet, logoutEP, nil)
					if err != nil {
						continue
					}
					ApplyAuthProfile(lReq2, auth)
					lResp2, err := s.doRequestWithRetry(ctx, lReq2, options)
					if err != nil || lResp2 == nil {
						continue
					}
					_ = lResp2.Body.Close()
					logoutAccepted = lResp2.StatusCode >= 200 && lResp2.StatusCode < 400
				}

				if !logoutAccepted {
					continue
				}

				// Replay the original credential.
				for _, protectedEP := range protectedEPs {
					req2, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
					if err != nil {
						continue
					}
					if bearerToken != "" {
						req2.Header.Set("Authorization", "Bearer "+bearerToken)
					} else {
						// Reattach the original session cookie.
						req2.AddCookie(&http.Cookie{Name: "session", Value: sessionCookie})
					}
					resp2, err := s.doRequestWithRetry(ctx, req2, options)
					if err != nil || resp2 == nil {
						continue
					}
					replayBody, _ := io.ReadAll(io.LimitReader(resp2.Body, sessionLifecycleBodyLimit))
					_ = resp2.Body.Close()

					lowerBody := strings.ToLower(string(replayBody))
					if resp2.StatusCode >= 200 && resp2.StatusCode < 300 &&
						!strings.Contains(lowerBody, "unauthorized") &&
						!strings.Contains(lowerBody, "login") &&
						!strings.Contains(lowerBody, "sign in") {
						emitted[fid] = true
						findings = append(findings, model.Finding{
							ID:          fid,
							Category:    "authentication",
							Severity:    model.SeverityHigh,
							Title:       "Session not invalidated server-side after logout",
							Description: "After calling the logout endpoint, the original session token was replayed and the server returned a successful (2xx) response. Server-side session state was not destroyed on logout, meaning a stolen session token remains valid indefinitely after the user logs out.",
							Evidence:    fmt.Sprintf("POST/GET %s (logout) → then GET %s with original token → HTTP %d", logoutEP, protectedEP, resp2.StatusCode),
							Recommendation: "Destroy server-side session state immediately when the logout endpoint is called. Invalidate all related tokens and cookies. Redirect to the login page.",
							Confidence:    0.82,
							AffectedURL:   logoutEP,
							CWE:           "CWE-613",
							OWASPCategory: "A07:2021 - Identification and Authentication Failures",
							Sources:       []string{"active-scanner", "session-lifecycle-probe"},
							BusinessTags:  []string{"session-invalidation", "logout"},
							EvidenceFields: map[string]string{
								"validationType":  "active-probe",
								"logoutEndpoint":  logoutEP,
								"replayEndpoint":  protectedEP,
								"replayStatus":    fmt.Sprintf("%d", resp2.StatusCode),
							},
						})
						break
					}
				}
				if emitted[fid] {
					break
				}
			}
		}
	}

	// ── Probe 3: Session invalidated on password change ────────────────────
	fid = "session-not-invalidated-on-password-change"
	if !emitted[fid] {
		bearerToken := oauthExtractBearerToken(auth)
		if bearerToken != "" {
			pwEPs := sessionDiscoverEndpoints(base, passwordChangePaths, scanScope)
			protectedEPs := sessionDiscoverProtectedEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
			for _, pwEP := range pwEPs {
				changeBody := map[string]string{
					"currentPassword": auth.Password,
					"newPassword":     "ABH-Probe-Changed-P@ss1!",
					"password":        "ABH-Probe-Changed-P@ss1!",
				}
				changeJSON, _ := json.Marshal(changeBody)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, pwEP, bytes.NewReader(changeJSON))
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, auth)
				req.Header.Set("Content-Type", "application/json")
				resp, err := s.doRequestWithRetry(ctx, req, options)
				if err != nil || resp == nil {
					continue
				}
				_ = resp.Body.Close()

				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					// Password change succeeded; replay original token.
					for _, protectedEP := range protectedEPs {
						req2, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
						if err != nil {
							continue
						}
						req2.Header.Set("Authorization", "Bearer "+bearerToken)
						resp2, err := s.doRequestWithRetry(ctx, req2, options)
						if err != nil || resp2 == nil {
							continue
						}
						replayBody, _ := io.ReadAll(io.LimitReader(resp2.Body, sessionLifecycleBodyLimit))
						_ = resp2.Body.Close()
						lowerBody := strings.ToLower(string(replayBody))
						if resp2.StatusCode >= 200 && resp2.StatusCode < 300 &&
							!strings.Contains(lowerBody, "unauthorized") {
							emitted[fid] = true
							findings = append(findings, model.Finding{
								ID:          fid,
								Category:    "authentication",
								Severity:    model.SeverityMedium,
								Title:       "Active sessions not invalidated on password change",
								Description: "After changing the account password, the original access token remained valid and the server returned a successful response. Changing a password should invalidate all existing sessions to prevent an attacker who has stolen a session from retaining access.",
								Evidence:    fmt.Sprintf("POST %s (password change) → GET %s with original token → HTTP %d", pwEP, protectedEP, resp2.StatusCode),
								Recommendation: "Invalidate all active sessions and tokens immediately when a password change is processed. Force re-authentication with the new credentials.",
								Confidence:    0.78,
								AffectedURL:   pwEP,
								CWE:           "CWE-613",
								OWASPCategory: "A07:2021 - Identification and Authentication Failures",
								Sources:       []string{"active-scanner", "session-lifecycle-probe"},
								BusinessTags:  []string{"session-invalidation", "password-change"},
								EvidenceFields: map[string]string{
									"validationType": "active-probe",
									"passwordEP":     pwEP,
									"replayStatus":   fmt.Sprintf("%d", resp2.StatusCode),
								},
							})
							break
						}
					}
				}
				if emitted[fid] {
					break
				}
			}
		}
	}

	// ── Probe 4: Concurrent sessions (Info) ────────────────────────────────
	fid = "session-concurrent-allowed"
	if !emitted[fid] && hasStandardLoginCredentials(auth) {
		loginEPs := sessionDiscoverLoginEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
		if len(loginEPs) > 0 {
			// Attempt two logins and verify both return a session token.
			ep := loginEPs[0]
			cookie1 := sessionAttemptLoginAndGetCookie(ctx, s, ep, auth, options)
			cookie2 := sessionAttemptLoginAndGetCookie(ctx, s, ep, auth, options)
			if cookie1 != "" && cookie2 != "" && cookie1 != cookie2 {
				emitted[fid] = true
				findings = append(findings, model.Finding{
					ID:          fid,
					Category:    "authentication",
					Severity:    model.SeverityInfo,
					Title:       "Concurrent sessions allowed — no session limit enforced",
					Description: "Two simultaneous login sessions were established for the same account without invalidating the first. Depending on the application's risk tolerance, concurrent sessions may increase the window for session hijacking after credential compromise.",
					Evidence:    fmt.Sprintf("Two logins at %s returned distinct session tokens", ep),
					Recommendation: "Consider limiting concurrent sessions for sensitive applications. At minimum, provide users with session management UI to view and revoke active sessions.",
					Confidence:    0.70,
					AffectedURL:   ep,
					CWE:           "CWE-613",
					OWASPCategory: "A07:2021 - Identification and Authentication Failures",
					Sources:       []string{"active-scanner", "session-lifecycle-probe"},
					BusinessTags:  []string{"session-management", "concurrent-sessions"},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"sessionCount":   "2",
					},
				})
			}
		}
	}

	return findings
}

// sessionAnalyzeCookieHeaders inspects Set-Cookie headers and emits findings
// for missing Secure, HttpOnly, SameSite, and overly broad Domain.
func sessionAnalyzeCookieHeaders(cookies []*http.Cookie, base *url.URL, target string) []model.Finding {
	var findings []model.Finding
	for _, ck := range cookies {
		if !sessionIsAuthCookie(ck.Name) {
			continue
		}

		// Probe 5: Missing Secure flag.
		if !ck.Secure && base.Scheme == "https" {
			findings = append(findings, model.Finding{
				ID:          "cookie-missing-secure-flag",
				Category:    "authentication",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Session cookie %q missing Secure flag", ck.Name),
				Description: "The authentication cookie is served without the Secure attribute over an HTTPS connection. If the user's browser ever makes an HTTP request to the same host (via redirect, mixed content, or HSTS pre-load gap), the cookie will be sent in plaintext.",
				Evidence:    fmt.Sprintf("Set-Cookie: %s (Secure flag absent)", ck.Name),
				Recommendation: "Set the Secure attribute on all authentication cookies so they are only transmitted over HTTPS.",
				Confidence:    0.90,
				AffectedURL:   target,
				CWE:           "CWE-614",
				OWASPCategory: "A07:2021 - Identification and Authentication Failures",
				Sources:       []string{"active-scanner", "session-lifecycle-probe"},
				BusinessTags:  []string{"cookie", "secure-flag"},
				EvidenceFields: map[string]string{"cookieName": ck.Name, "secureFlagPresent": "false"},
			})
		}

		// Probe 6: Missing HttpOnly flag.
		if !ck.HttpOnly {
			findings = append(findings, model.Finding{
				ID:          "cookie-missing-httponly-flag",
				Category:    "authentication",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Session cookie %q missing HttpOnly flag", ck.Name),
				Description: "The authentication cookie lacks the HttpOnly attribute, making it accessible via JavaScript (document.cookie). Any XSS vulnerability in the application can be used to steal the session token.",
				Evidence:    fmt.Sprintf("Set-Cookie: %s (HttpOnly flag absent)", ck.Name),
				Recommendation: "Set the HttpOnly attribute on all authentication cookies to prevent JavaScript access.",
				Confidence:    0.90,
				AffectedURL:   target,
				CWE:           "CWE-1004",
				OWASPCategory: "A07:2021 - Identification and Authentication Failures",
				Sources:       []string{"active-scanner", "session-lifecycle-probe"},
				BusinessTags:  []string{"cookie", "httponly-flag"},
				EvidenceFields: map[string]string{"cookieName": ck.Name, "httpOnlyFlagPresent": "false"},
			})
		}

		// Probe 7: SameSite not Strict or Lax.
		sameSite := sameSiteString(ck.SameSite)
		if ck.SameSite == http.SameSiteDefaultMode || ck.SameSite == http.SameSiteNoneMode {
			findings = append(findings, model.Finding{
				ID:          "cookie-samesite-not-enforced",
				Category:    "authentication",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Session cookie %q missing or permissive SameSite attribute", ck.Name),
				Description: fmt.Sprintf("The authentication cookie has SameSite=%q. Without SameSite=Strict or Lax, cross-site requests initiated by a malicious page will include the cookie, enabling CSRF even without a token if the server relies on cookie-based authentication alone.", sameSite),
				Evidence:    fmt.Sprintf("Set-Cookie: %s; SameSite=%s", ck.Name, sameSite),
				Recommendation: "Set SameSite=Strict for session cookies where cross-site POST is not required, or SameSite=Lax as a minimum baseline.",
				Confidence:    0.85,
				AffectedURL:   target,
				CWE:           "CWE-352",
				OWASPCategory: "A07:2021 - Identification and Authentication Failures",
				Sources:       []string{"active-scanner", "session-lifecycle-probe"},
				BusinessTags:  []string{"cookie", "samesite"},
				EvidenceFields: map[string]string{"cookieName": ck.Name, "sameSite": sameSite},
			})
		}

		// Probe 8: Overly broad Domain.
		if ck.Domain != "" && strings.HasPrefix(ck.Domain, ".") {
			findings = append(findings, model.Finding{
				ID:          "cookie-broad-domain-scope",
				Category:    "authentication",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Session cookie %q scoped to parent domain %q", ck.Name, ck.Domain),
				Description: fmt.Sprintf("The authentication cookie has Domain=%q, which shares it across all subdomains of %s. A subdomain under attacker control (e.g., via subdomain takeover) can read or set the session cookie.", ck.Domain, ck.Domain),
				Evidence:    fmt.Sprintf("Set-Cookie: %s; Domain=%s", ck.Name, ck.Domain),
				Recommendation: "Scope session cookies to the exact host (omit the Domain attribute) unless cross-subdomain sharing is intentional and all subdomains are equally trusted.",
				Confidence:    0.80,
				AffectedURL:   target,
				CWE:           "CWE-565",
				OWASPCategory: "A07:2021 - Identification and Authentication Failures",
				Sources:       []string{"active-scanner", "session-lifecycle-probe"},
				BusinessTags:  []string{"cookie", "domain-scope"},
				EvidenceFields: map[string]string{"cookieName": ck.Name, "domain": ck.Domain},
			})
		}
	}
	return findings
}

// sessionIsAuthCookie returns true for cookies whose names suggest auth/session use.
func sessionIsAuthCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range sessionAuthCookieHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// sessionExtractSessionCookie returns the first session/auth cookie value from
// the auth profile.
func sessionExtractSessionCookie(auth model.ScanAuthProfile) string {
	for name, val := range auth.Cookies {
		if sessionIsAuthCookie(name) && val != "" {
			return val
		}
	}
	return ""
}

// sessionAttemptLoginAndGetCookie performs a login POST and returns any
// Set-Cookie value that looks like a session token.
func sessionAttemptLoginAndGetCookie(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) string {
	if auth.Username == "" || auth.Password == "" {
		return ""
	}
	creds := map[string]string{
		"username": auth.Username,
		"email":    auth.Username,
		"password": auth.Password,
	}
	bodyJSON, _ := json.Marshal(creds)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return ""
	}
	_ = resp.Body.Close()
	for _, ck := range resp.Cookies() {
		if sessionIsAuthCookie(ck.Name) {
			return ck.Value
		}
	}
	return ""
}

// sessionDiscoverEndpoints resolves paths against base and returns in-scope ones.
func sessionDiscoverEndpoints(base *url.URL, paths []string, scanScope model.ScanScope) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, p := range paths {
		ref, _ := url.Parse(p)
		ep := base.ResolveReference(ref).String()
		if _, ok := seen[ep]; ok {
			continue
		}
		if !scope.IsURLInScope(ep, scanScope) {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}
	return out
}

// sessionDiscoverLoginEndpoints returns in-scope login endpoints.
func sessionDiscoverLoginEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	eps := sessionDiscoverEndpoints(base, loginPaths, scanScope)
	for _, s := range seeded {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "login") || strings.Contains(lower, "signin") {
			if scope.IsURLInScope(s, scanScope) {
				eps = append(eps, s)
			}
		}
	}
	const max = 3
	if len(eps) > max {
		eps = eps[:max]
	}
	return eps
}

// sessionDiscoverLogoutEndpoints returns in-scope logout endpoints.
func sessionDiscoverLogoutEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	eps := sessionDiscoverEndpoints(base, sessionLogoutPaths, scanScope)
	for _, s := range seeded {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "logout") || strings.Contains(lower, "signout") {
			if scope.IsURLInScope(s, scanScope) {
				eps = append(eps, s)
			}
		}
	}
	const max = 3
	if len(eps) > max {
		eps = eps[:max]
	}
	return eps
}

// sessionDiscoverProtectedEndpoints returns in-scope likely-auth-protected endpoints.
func sessionDiscoverProtectedEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	eps := sessionDiscoverEndpoints(base, sessionProtectedPaths, scanScope)
	for _, s := range seeded {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "/me") || strings.Contains(lower, "/profile") ||
			strings.Contains(lower, "/user") || strings.Contains(lower, "/account") {
			if scope.IsURLInScope(s, scanScope) {
				eps = append(eps, s)
			}
		}
	}
	const max = 3
	if len(eps) > max {
		eps = eps[:max]
	}
	return eps
}

// sameSiteString returns a human-readable string for an http.SameSite value.
func sameSiteString(s http.SameSite) string {
switch s {
case http.SameSiteDefaultMode:
return "default"
case http.SameSiteLaxMode:
return "Lax"
case http.SameSiteStrictMode:
return "Strict"
case http.SameSiteNoneMode:
return "None"
default:
return "unknown"
}
}
