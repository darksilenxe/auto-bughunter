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

// mfaBodyLimit caps per-probe response reads for the MFA probe.
const mfaBodyLimit = 64 * 1024

// mfaEndpointPaths are conventional MFA challenge and verification paths.
var mfaEndpointPaths = []string{
	"/mfa",
	"/otp",
	"/2fa",
	"/verify",
	"/totp/verify",
	"/api/auth/mfa",
	"/api/auth/otp",
	"/api/auth/2fa",
	"/api/mfa/verify",
	"/api/otp/verify",
	"/api/2fa/verify",
	"/auth/mfa",
	"/auth/otp",
	"/auth/2fa",
	"/account/mfa",
}

// mfaBackupCodePaths are conventional recovery/backup-code paths.
var mfaBackupCodePaths = []string{
	"/api/auth/backup-code",
	"/api/auth/recovery-code",
	"/api/recovery",
	"/account-recovery",
	"/recovery",
	"/auth/recovery",
	"/api/mfa/backup",
}

// mfaStepUpPaths are endpoints that typically require step-up authentication.
var mfaStepUpPaths = []string{
	"/api/settings/change-password",
	"/api/user/password",
	"/api/payment",
	"/api/admin",
	"/api/settings/2fa",
	"/api/account/delete",
	"/settings/security",
	"/api/profile/delete",
}

// RunMFAProbe tests MFA/OTP bypass and step-up authentication weaknesses:
//
//  1. MFA endpoint discovery.
//  2. OTP brute-force / no rate-limit — 10 sequential wrong OTP guesses.
//  3. OTP reuse — same code submitted twice must be rejected.
//  4. MFA skip via direct resource access.
//  5. Backup code brute-force.
//  6. MFA enrollment state manipulation.
//  7. Remember-me / device-trust bypass.
//  8. Step-up auth skip.
func (s *Service) RunMFAProbe(
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

	mfaEPs := mfaDiscoverEndpoints(base, mfaEndpointPaths, options.SeedRuntimeEndpoints, scanScope)
	backupEPs := mfaDiscoverEndpoints(base, mfaBackupCodePaths, options.SeedRuntimeEndpoints, scanScope)
	stepUpEPs := mfaDiscoverEndpoints(base, mfaStepUpPaths, options.SeedRuntimeEndpoints, scanScope)

	if len(mfaEPs) == 0 && len(backupEPs) == 0 {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("mfa-probe %s", target),
			Message: fmt.Sprintf("Probing %d MFA endpoints for OTP brute-force, bypass, and step-up vulnerabilities", len(mfaEPs)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}
	mfaWrongCodeRejected := mfaAnyEndpointRejectsWrongCode(ctx, s, mfaEPs, auth, options)

	// ── Probe 1: Surface discovery ─────────────────────────────────────────
	if len(mfaEPs) > 0 {
		findings = append(findings, model.Finding{
			ID:             "mfa-surface-discovered",
			Category:       "authentication",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("MFA/OTP surface discovered: %d endpoints", len(mfaEPs)),
			Description:    "Multi-factor authentication or OTP verification endpoints were found. These are tested for brute-force protection, single-use enforcement, and bypass vulnerabilities.",
			Evidence:       strings.Join(mfaEPs, ", "),
			Recommendation: "Ensure MFA endpoints enforce rate limiting, OTP single-use invalidation, and do not allow direct resource access without a completed MFA challenge.",
			Confidence:     0.95,
			AffectedURL:    target,
			CWE:            "CWE-307",
			OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
			Sources:        []string{"active-scanner", "mfa-probe"},
			BusinessTags:   []string{"mfa", "otp", "2fa"},
		})
	}

	// ── Probe 2: OTP brute-force / no rate-limit ───────────────────────────
	fid := "mfa-otp-no-ratelimit"
	if !emitted[fid] {
		for _, ep := range mfaEPs {
			if mfaTestOTPBruteForce(ctx, s, ep, auth, options) {
				emitted[fid] = true
				findings = append(findings, mfaFinding(
					fid, ep, model.SeverityHigh,
					"MFA/OTP endpoint lacks brute-force protection",
					fmt.Sprintf(
						"The MFA verification endpoint %s accepted 10 sequential OTP submissions "+
							"with incorrect codes without returning HTTP 429 or locking the account. "+
							"A 6-digit TOTP has only 1,000,000 possible values; without rate limiting "+
							"an attacker can enumerate all codes within minutes.",
						ep,
					),
					"CWE-307",
					[]string{
						"Submit 10+ incorrect OTP codes in rapid succession to: " + ep,
						"Observe that the server never returns HTTP 429 or a lockout response.",
						"Continue submitting until the correct code is discovered.",
					},
					map[string]string{"attemptsBeforeLock": "10+", "rateLimitDetected": "false"},
				))
				break
			}
		}
	}

	// ── Probe 3: OTP reuse ─────────────────────────────────────────────────
	fid = "mfa-otp-reuse"
	if !emitted[fid] {
		for _, ep := range mfaEPs {
			if f := mfaTestOTPReuse(ctx, s, ep, auth, options); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 4: MFA skip via direct resource access ───────────────────────
	fid = "mfa-skip-direct-access"
	if !emitted[fid] && len(stepUpEPs) > 0 {
		for _, ep := range stepUpEPs {
			if !scope.IsURLInScope(ep, scanScope) {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, auth)
			resp, err := s.doRequestWithRetry(ctx, req, options)
			if err != nil || resp == nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, mfaBodyLimit))
			_ = resp.Body.Close()

			lowerBody := strings.ToLower(string(body))
			// If the resource returns 200 and no MFA-challenge signal, MFA is bypassable.
			if mfaWrongCodeRejected &&
				resp.StatusCode >= 200 && resp.StatusCode < 300 &&
				!strings.Contains(lowerBody, "mfa") &&
				!strings.Contains(lowerBody, "otp") &&
				!strings.Contains(lowerBody, "2fa") &&
				!strings.Contains(lowerBody, "verify") &&
				!strings.Contains(lowerBody, "unauthorized") {
				emitted[fid] = true
				findings = append(findings, mfaFinding(
					fid, ep, model.SeverityHigh,
					"MFA / step-up authentication not enforced on sensitive endpoint",
					fmt.Sprintf(
						"The sensitive endpoint %s returned HTTP %d without requiring "+
							"a completed MFA challenge. An attacker who compromises a base-level "+
							"session (e.g., through session hijacking or credential stuffing) "+
							"can access sensitive operations without a second factor.",
						ep, resp.StatusCode,
					),
					"CWE-306",
					[]string{
						"Authenticate with username/password only (no MFA).",
						"Access: " + ep,
						"Observe that the resource is returned without an MFA challenge.",
					},
					map[string]string{"sensitiveEndpoint": ep, "responseStatus": fmt.Sprintf("%d", resp.StatusCode), "wrongCodeControlRejected": fmt.Sprintf("%v", mfaWrongCodeRejected)},
				))
				break
			}
		}
	}

	// ── Probe 5: Backup code brute-force ────────────────────────────────────
	fid = "mfa-backup-code-bruteforce"
	if !emitted[fid] {
		commonBackupCodes := []string{"00000000", "12345678", "11111111", "99999999", "00000001"}
		for _, ep := range backupEPs {
			if mfaTestBackupCodeBruteForce(ctx, s, ep, commonBackupCodes, auth, options) {
				emitted[fid] = true
				findings = append(findings, mfaFinding(
					fid, ep, model.SeverityMedium,
					"MFA backup/recovery code endpoint lacks brute-force protection",
					fmt.Sprintf(
						"The backup code endpoint %s accepted multiple recovery code submissions "+
							"without rate limiting. Backup codes are often shorter or less random "+
							"than primary OTPs; brute-force is practical without rate limiting.",
						ep,
					),
					"CWE-307",
					[]string{
						"Submit several invalid backup codes to: " + ep,
						"Observe that no rate-limiting or lockout is triggered.",
					},
					map[string]string{"backupEndpoint": ep, "rateLimitDetected": "false"},
				))
				break
			}
		}
	}

	// ── Probe 6: MFA enrollment state manipulation ─────────────────────────
	fid = "mfa-enrollment-bypass"
	if !emitted[fid] {
		enrollmentPaths := []string{"/api/auth/mfa/setup", "/api/mfa/enroll", "/mfa/setup", "/2fa/setup"}
		for _, path := range enrollmentPaths {
			ref, _ := url.Parse(path)
			ep := base.ResolveReference(ref).String()
			if !scope.IsURLInScope(ep, scanScope) {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, auth)
			resp, err := s.doRequestWithRetry(ctx, req, options)
			if err != nil || resp == nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, mfaBodyLimit))
			_ = resp.Body.Close()
			lowerBody := strings.ToLower(string(body))

			// If we can initiate MFA setup (200) and access protected resources at the
			// same time, the enrollment-pending state doesn't restrict access.
			if resp.StatusCode == 200 && (strings.Contains(lowerBody, "qr") ||
				strings.Contains(lowerBody, "secret") ||
				strings.Contains(lowerBody, "setup") ||
				strings.Contains(lowerBody, "enroll")) {
				// Check if a sensitive resource is simultaneously accessible.
				for _, protectedEP := range stepUpEPs {
					req2, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
					if err != nil {
						continue
					}
					ApplyAuthProfile(req2, auth)
					resp2, err := s.doRequestWithRetry(ctx, req2, options)
					if err != nil || resp2 == nil {
						continue
					}
					_ = resp2.Body.Close()
					if mfaWrongCodeRejected && resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
						emitted[fid] = true
						findings = append(findings, mfaFinding(
							fid, ep, model.SeverityHigh,
							"MFA enrollment state does not restrict access to sensitive endpoints",
							fmt.Sprintf(
								"MFA enrollment was accessible at %s while the sensitive resource %s "+
									"also returned HTTP %d. The application may allow access to privileged "+
									"operations while MFA enrollment is pending, before a second factor "+
									"is configured.",
								ep, protectedEP, resp2.StatusCode,
							),
							"CWE-306",
							[]string{
								"Begin MFA enrollment at: " + ep,
								"Without completing enrollment, access a sensitive resource: " + protectedEP,
								"Observe that the resource is returned without requiring MFA completion.",
							},
							map[string]string{
								"enrollmentEndpoint":       ep,
								"sensitiveEndpoint":        protectedEP,
								"sensitiveStatus":          fmt.Sprintf("%d", resp2.StatusCode),
								"wrongCodeControlRejected": fmt.Sprintf("%v", mfaWrongCodeRejected),
							},
						))
						break
					}
				}
				if emitted[fid] {
					break
				}
			}
		}
	}

	// ── Probe 7: Remember-me / device-trust bypass ─────────────────────────
	fid = "mfa-device-trust-bypass"
	if !emitted[fid] {
		deviceCookie := mfaExtractDeviceTrustCookie(auth)
		if deviceCookie != "" {
			// Replay the device-trust cookie without a session cookie to see if
			// it alone grants access.
			for _, ep := range mfaEPs {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
				if err != nil {
					continue
				}
				// Apply only the device-trust cookie, not the full auth profile.
				req.AddCookie(&http.Cookie{Name: deviceCookie, Value: "abh-probe-replay"})
				resp, err := s.doRequestWithRetry(ctx, req, options)
				if err != nil || resp == nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, mfaBodyLimit))
				_ = resp.Body.Close()
				lowerBody := strings.ToLower(string(body))

				if mfaWrongCodeRejected &&
					resp.StatusCode >= 200 && resp.StatusCode < 300 &&
					!strings.Contains(lowerBody, "unauthorized") &&
					!strings.Contains(lowerBody, "invalid") {
					emitted[fid] = true
					findings = append(findings, mfaFinding(
						fid, ep, model.SeverityHigh,
						"MFA device-trust cookie accepted without session binding",
						fmt.Sprintf(
							"The MFA endpoint %s accepted a replayed device-trust/remember-me "+
								"cookie without a valid session cookie (HTTP %d). Device trust "+
								"tokens must be bound to the user session; an isolated cookie "+
								"allows an attacker who steals only the device-trust value to "+
								"bypass MFA entirely.",
							ep, resp.StatusCode,
						),
						"CWE-384",
						[]string{
							"Extract the remember_device or trusted_device cookie value.",
							"In a new browser session (no session cookie), submit the cookie to: " + ep,
							"Observe that MFA is bypassed.",
						},
						map[string]string{"cookieName": deviceCookie, "responseStatus": fmt.Sprintf("%d", resp.StatusCode), "wrongCodeControlRejected": fmt.Sprintf("%v", mfaWrongCodeRejected)},
					))
					break
				}
			}
		}
	}

	// ── Probe 8: Step-up auth skip ────────────────────────────────────────
	fid = "mfa-stepup-not-enforced"
	if !emitted[fid] {
		writeMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch}
		for _, ep := range stepUpEPs {
			if !scope.IsURLInScope(ep, scanScope) {
				continue
			}
			for _, method := range writeMethods {
				body := map[string]string{"abh_probe": "step_up_test"}
				bodyJSON, _ := json.Marshal(body)
				req, err := http.NewRequestWithContext(ctx, method, ep, bytes.NewReader(bodyJSON))
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, auth)
				req.Header.Set("Content-Type", "application/json")
				resp, err := s.doRequestWithRetry(ctx, req, options)
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, mfaBodyLimit))
				_ = resp.Body.Close()

				lowerBody := strings.ToLower(string(respBody))
				// 200/204 without a step-up challenge signal = no step-up required.
				if mfaWrongCodeRejected &&
					(resp.StatusCode == 200 || resp.StatusCode == 204) &&
					!strings.Contains(lowerBody, "step_up") &&
					!strings.Contains(lowerBody, "stepup") &&
					!strings.Contains(lowerBody, "mfa_required") &&
					!strings.Contains(lowerBody, "otp_required") &&
					!strings.Contains(lowerBody, "unauthorized") {
					emitted[fid] = true
					findings = append(findings, mfaFinding(
						fid, ep, model.SeverityHigh,
						"Step-up authentication not enforced on sensitive write endpoint",
						fmt.Sprintf(
							"A %s request to the sensitive endpoint %s returned HTTP %d without "+
								"requiring step-up re-authentication. Sensitive operations "+
								"(password change, payment, account deletion) should require "+
								"re-authentication even when a valid session exists.",
							method, ep, resp.StatusCode,
						),
						"CWE-306",
						[]string{
							"Authenticate with a valid session.",
							"Issue a " + method + " request to: " + ep,
							"Observe that the operation proceeds without an MFA or re-auth challenge.",
						},
						map[string]string{
							"method":                   method,
							"endpoint":                 ep,
							"responseStatus":           fmt.Sprintf("%d", resp.StatusCode),
							"wrongCodeControlRejected": fmt.Sprintf("%v", mfaWrongCodeRejected),
						},
					))
					break
				}
			}
			if emitted[fid] {
				break
			}
		}
	}

	return findings
}

// mfaFinding constructs a standardized Finding for the MFA probe.
func mfaFinding(id, endpoint string, severity model.Severity, title, evidence, cwe string, steps []string, extra map[string]string) model.Finding {
	ef := map[string]string{"validationType": "active-probe"}
	for k, v := range extra {
		ef[k] = v
	}
	return model.Finding{
		ID:                id,
		Category:          "authentication",
		Severity:          severity,
		Title:             title,
		Description:       "A multi-factor authentication control was found to be absent, bypassable, or insufficiently enforced.",
		Evidence:          evidence,
		Recommendation:    "Enforce rate limiting and account lockout on OTP endpoints. Ensure OTP codes are single-use and expire after one validation attempt. Bind device-trust tokens to the user session. Require step-up re-authentication for sensitive operations.",
		Confidence:        0.80,
		AffectedURL:       endpoint,
		CWE:               cwe,
		OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
		Sources:           []string{"active-scanner", "mfa-probe"},
		ReproductionSteps: steps,
		BusinessTags:      []string{"mfa", "otp", "2fa", "brute-force"},
		EvidenceFields:    ef,
	}
}

// mfaDiscoverEndpoints returns in-scope MFA endpoints.
func mfaDiscoverEndpoints(base *url.URL, paths []string, seeded []string, scanScope model.ScanScope) []string {
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
		if strings.Contains(lower, "mfa") || strings.Contains(lower, "otp") ||
			strings.Contains(lower, "2fa") || strings.Contains(lower, "totp") ||
			strings.Contains(lower, "verify") || strings.Contains(lower, "recovery") {
			addEP(s)
		}
	}

	const max = 8
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// mfaTestOTPBruteForce submits 10 wrong OTP codes and returns true if none
// triggered a rate-limit or lockout response.
func mfaTestOTPBruteForce(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) bool {
	rateLimited := false
	for i := 0; i < 10; i++ {
		code := fmt.Sprintf("%06d", (i+1)*11111%1000000)
		body := map[string]string{"code": code, "otp": code, "token": code}
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
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusLocked {
			rateLimited = true
			break
		}
	}
	return !rateLimited
}

// mfaTestOTPReuse checks if the same OTP code is accepted twice.
func mfaTestOTPReuse(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) *model.Finding {
	// We use a synthetic code; if the server accepts the same code twice (e.g.,
	// returns 200 on both without a "used" / "invalid" error), report it only
	// when a definitely-wrong control code is rejected.
	code := "123456"
	status1, body1 := mfaSubmitCode(ctx, s, ep, code, auth, options)
	status2, body2 := mfaSubmitCode(ctx, s, ep, code, auth, options)
	controlStatus, controlBody := mfaSubmitCode(ctx, s, ep, "000000", auth, options)

	// Only flag if both return 200 and neither body indicates rejection.
	if status1 == 200 && status2 == 200 &&
		!mfaResponseIndicatesOTPError(body1) &&
		!mfaResponseIndicatesOTPError(body2) &&
		(controlStatus == 0 || mfaResponseIndicatesOTPError(controlBody) || controlStatus >= 400) {
		return &model.Finding{
			ID:             "mfa-otp-reuse",
			Category:       "authentication",
			Severity:       model.SeverityMedium,
			Title:          "MFA OTP code accepted on second submission (single-use not enforced)",
			Description:    "The MFA endpoint accepted the same one-time code on two consecutive submissions without returning an error or invalidating the code, while a definitely-wrong control code was rejected. OTP codes must be invalidated immediately after their first use.",
			Evidence:       fmt.Sprintf("POST %s with code=%q → first HTTP %d, second HTTP %d (both accepted); wrong-code control → HTTP %d", ep, code, status1, status2, controlStatus),
			Recommendation: "Invalidate OTP codes immediately upon first successful validation. Store used codes in a short-lived cache keyed by (session, code) and reject duplicate submissions within the validity window.",
			Confidence:     0.75,
			AffectedURL:    ep,
			CWE:            "CWE-294",
			OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
			Sources:        []string{"active-scanner", "mfa-probe"},
			BusinessTags:   []string{"mfa", "otp", "replay"},
			EvidenceFields: map[string]string{
				"validationType":           "active-probe",
				"firstStatus":              fmt.Sprintf("%d", status1),
				"secondStatus":             fmt.Sprintf("%d", status2),
				"code":                     code,
				"wrongCodeControlRejected": "true",
				"controlStatus":            fmt.Sprintf("%d", controlStatus),
			},
		}
	}
	return nil
}

func mfaSubmitCode(ctx context.Context, s *Service, ep, code string, auth model.ScanAuthProfile, options model.ScanOptions) (int, string) {
	body := map[string]string{"code": code, "otp": code, "token": code}
	bodyJSON, _ := json.Marshal(body)
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
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, mfaBodyLimit))
	_ = resp.Body.Close()
	return resp.StatusCode, string(rb)
}

func mfaAnyEndpointRejectsWrongCode(ctx context.Context, s *Service, endpoints []string, auth model.ScanAuthProfile, options model.ScanOptions) bool {
	for _, ep := range endpoints {
		status, body := mfaSubmitCode(ctx, s, ep, "000000", auth, options)
		if status == 0 {
			continue
		}
		if status >= 400 || status == http.StatusTooManyRequests || status == http.StatusLocked || mfaResponseIndicatesOTPError(body) {
			return true
		}
	}
	return false
}

// mfaTestBackupCodeBruteForce checks if the backup code endpoint lacks rate limiting.
func mfaTestBackupCodeBruteForce(ctx context.Context, s *Service, ep string, codes []string, auth model.ScanAuthProfile, options model.ScanOptions) bool {
	rateLimited := false
	for _, code := range codes {
		body := map[string]string{"code": code, "backupCode": code, "recoveryCode": code}
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
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusLocked {
			rateLimited = true
			break
		}
	}
	return !rateLimited
}

// mfaExtractDeviceTrustCookie returns the name of a device-trust cookie if
// one is present in the auth profile.
func mfaExtractDeviceTrustCookie(auth model.ScanAuthProfile) string {
	for name := range auth.Cookies {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "device") || strings.Contains(lower, "trusted") ||
			strings.Contains(lower, "remember") {
			return name
		}
	}
	return ""
}

// mfaResponseIndicatesOTPError returns true when an OTP response body signals
// a rejection (e.g., "invalid code", "expired", "already used").
func mfaResponseIndicatesOTPError(body string) bool {
	lower := strings.ToLower(body)
	for _, kw := range []string{"invalid", "expired", "incorrect", "wrong", "already used", "error", "unauthorized"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
