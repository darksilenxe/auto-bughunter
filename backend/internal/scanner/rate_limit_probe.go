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

// rateLimitBodyLimit caps per-request response reads.
const rateLimitBodyLimit = 32 * 1024

// rateLimitMaxRequests is how many rapid requests are fired at a single
// candidate endpoint to look for throttling. Bounded low to keep scan time
// reasonable; PayloadsAllTheThings' "Brute Force" methodology notes that
// most rate limiters trigger well within a dozen requests when present.
const rateLimitMaxRequests = 12

// rateLimitSensitivePaths are endpoint categories the PayloadsAllTheThings
// "Brute Force Rate Limit" and "Account Takeover" guides call out as
// high-value rate-limiting targets beyond the login form itself (which
// login_probe.go already covers via its own dedicated checks).
var rateLimitSensitivePaths = []string{
	"/password-reset", "/forgot-password", "/forgot", "/reset-password",
	"/api/password-reset", "/api/forgot-password", "/api/auth/forgot-password",
	"/register", "/signup", "/api/register", "/api/signup",
	"/otp", "/verify-otp", "/api/otp/verify", "/mfa/verify",
	"/api/coupon", "/api/promo", "/api/invite/accept",
}

// rateLimitLockoutSignals are response body substrings indicating the server
// recognised and throttled/locked the burst of requests.
var rateLimitLockoutSignals = []string{
	"too many requests", "rate limit", "rate-limit", "try again later",
	"temporarily locked", "account locked", "throttled", "slow down",
}

// runRateLimitProbe is a dedicated, endpoint-agnostic active probe for the
// PayloadsAllTheThings "Brute Force Rate Limit" technique. Unlike the
// rate-limit checks embedded in login_probe.go/mfa_probe.go (which are
// scoped to the login and OTP verification flows respectively), this probe
// measures throttling behaviour across other commonly-abused sensitive
// endpoints: password reset, registration, OTP verification, and
// coupon/invite redemption — surfaces frequently excluded from a WAF's
// rate-limiting rules because they are not the primary login form.
//
// For each candidate endpoint it fires a bounded burst of requests and flags
// the endpoint when none of them return HTTP 429/423, a Retry-After header,
// or a body signal indicating throttling.
func (s *Service) runRateLimitProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	candidates := loginDiscoverEndpoints(base, rateLimitSensitivePaths, input.Options.SeedRuntimeEndpoints, input.Scope)
	if len(candidates) == 0 {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("rate-limit-probe %s", input.Target),
			Message: fmt.Sprintf("Probing %d sensitive endpoints for missing rate limiting", len(candidates)),
		})
	}

	var findings []model.Finding
	for _, ep := range candidates {
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}

		// Phase 2 coverage accounting: record this endpoint as probed so
		// the surface-gap detector subtracts it from the inventory.
		RecordProbedKey(http.MethodPost, ep, "")
		throttled, lastStatus, lastBody, sent := s.rateLimitBurst(ctx, input, ep, rateLimitMaxRequests)
		if sent == 0 {
			continue
		}
		if throttled {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       "rate-limit-missing-" + hhSlug(ep),
			Category: "authentication",
			Severity: model.SeverityMedium,
			Title:    "Missing rate limiting on sensitive endpoint",
			Description: fmt.Sprintf(
				"The endpoint %s accepted %d rapid, consecutive requests without returning HTTP 429/423, a "+
					"Retry-After header, or any throttling/lockout indication in the response body. Sensitive "+
					"endpoints such as password reset, registration, OTP verification, and coupon/invite redemption "+
					"are common brute-force and abuse targets; without rate limiting an attacker can enumerate "+
					"accounts, exhaust OTP keyspaces, mass-register accounts, or brute-force promotional codes at "+
					"high volume.",
				ep, sent,
			),
			Evidence: fmt.Sprintf(
				"%d consecutive requests to %s — last response HTTP %d, body excerpt: %q",
				sent, ep, lastStatus, truncateForEvidence(lastBody, 160),
			),
			Recommendation: "Apply rate limiting (fixed-window or token-bucket, keyed by IP + account/session " +
				"identifier) to every sensitive state-changing endpoint, not only the primary login form. Return " +
				"HTTP 429 with a Retry-After header once the threshold is exceeded, and back this with a server-" +
				"side lockout/backoff counter that survives client-side retries.",
			Confidence:    0.80,
			AffectedURL:   ep,
			CWE:           "CWE-307",
			OWASPCategory: "A07:2021 - Identification and Authentication Failures",
			Sources:       []string{"active-scanner", "rate-limit-probe"},
			ReproductionSteps: []string{
				fmt.Sprintf("Send %d consecutive POST requests to %s in quick succession.", rateLimitMaxRequests, ep),
				"Observe that no request returns HTTP 429/423, a Retry-After header, or a throttling message.",
			},
			BusinessTags: []string{"rate-limit", "brute-force", "authentication"},
			EvidenceFields: map[string]string{
				"validationType":    "active-probe",
				"requestsSent":      fmt.Sprintf("%d", sent),
				"lastStatus":        fmt.Sprintf("%d", lastStatus),
				"rateLimitDetected": "false",
			},
		})
	}

	return findings
}

// rateLimitBurst sends up to n consecutive requests to ep with a benign JSON
// body and reports whether any response indicated throttling (HTTP 429/423,
// a Retry-After header, or a known lockout body signal). It returns the
// number of requests actually sent (0 when the endpoint is unreachable) so
// callers can distinguish "no signal because probing failed" from "no signal
// because the endpoint isn't rate limited".
func (s *Service) rateLimitBurst(ctx context.Context, input RunInput, ep string, n int) (throttled bool, lastStatus int, lastBody string, sent int) {
	payload, _ := json.Marshal(map[string]string{
		"email":    "abh_ratelimit_probe@abh-test.invalid",
		"username": "abh_ratelimit_probe",
		"otp":      "000000",
		"code":     "000000",
	})

	for i := 0; i < n; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			// doRequestWithRetry converts retriable statuses (429, 502, 503,
			// 504 — see isRetriableStatus) into a non-nil error with a nil
			// response once retries are exhausted. A 429 collapsing this way
			// is itself the throttling signal we're looking for, so treat a
			// request failure mid-burst as evidence of rate limiting rather
			// than silently skipping it (mirrors loginTestBruteForce's
			// status==0 handling in login_probe.go).
			if err != nil && strings.Contains(err.Error(), "status 429") {
				return true, http.StatusTooManyRequests, "", sent
			}
			continue
		}
		sent++
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, rateLimitBodyLimit))
		_ = resp.Body.Close()
		lastStatus = resp.StatusCode
		lastBody = string(respBody)

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusLocked {
			return true, lastStatus, lastBody, sent
		}
		if resp.Header.Get("Retry-After") != "" {
			return true, lastStatus, lastBody, sent
		}
		if matchAnyLower(lastBody, rateLimitLockoutSignals) != "" {
			return true, lastStatus, lastBody, sent
		}
	}
	return false, lastStatus, lastBody, sent
}

// truncateForEvidence trims s to at most n bytes for compact evidence text.
func truncateForEvidence(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
