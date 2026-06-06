package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

var mfaPaths = []string{"/2fa", "/otp", "/verify", "/mfa", "/totp", "/code", "/confirm"}
var mfaProtectedPaths = []string{"/dashboard", "/profile", "/home"}

func (s *Service) runMFABypassProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly || input.Session == nil || !hasAnyAuthMaterial(input.AuthProfile) {
		return nil
	}
	otpEndpoints := mfaResolvePaths(input.Target, mfaPaths, input.Scope)
	protectedEndpoints := mfaResolvePaths(input.Target, mfaProtectedPaths, input.Scope)
	for _, otpEndpoint := range otpEndpoints {
		statusCodes := map[int]int{}
		locked := false
		reachable := false
		for i := 0; i < 10; i++ {
			status, body, ok := s.mfaPostCode(ctx, input, otpEndpoint, "000000")
			if !ok {
				continue
			}
			statusCodes[status]++
			if status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
				reachable = true
			}
			lower := strings.ToLower(string(body))
			if status == http.StatusTooManyRequests || strings.Contains(lower, "locked") || strings.Contains(lower, "rate") {
				locked = true
			}
		}
		if reachable && len(statusCodes) > 0 && !locked {
			return []model.Finding{{
				ID:             "mfa-bypass-rate-limit",
				Category:       "auth_bypass",
				Severity:       model.SeverityHigh,
				Title:          "MFA endpoint lacks brute-force rate limiting",
				Description:    "The OTP/MFA verification endpoint accepted repeated invalid submissions without locking or rate limiting, materially increasing the feasibility of MFA guessing attacks.",
				Evidence:       fmt.Sprintf("Ten invalid OTP submissions to %s did not trigger 429/lockout responses", otpEndpoint),
				Recommendation: "Apply per-account and per-session rate limits, progressive lockouts, and anomaly monitoring on MFA verification endpoints.",
				Confidence:     0.8,
				AffectedURL:    otpEndpoint,
				CWE:            "CWE-308",
				OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
				Sources:        []string{"active-scanner"},
				EvidenceFields: map[string]string{"validationType": "active-probe"},
			}}
		}
		if token := firstNonEmpty(input.Session.TokenStore.Get("otp"), input.Session.TokenStore.Get("code")); token != "" {
			if status, _, ok := s.mfaPostCode(ctx, input, otpEndpoint, token); ok && status == http.StatusOK {
				return []model.Finding{{
					ID:             "mfa-bypass-otp-reuse",
					Category:       "auth_bypass",
					Severity:       model.SeverityHigh,
					Title:          "MFA code reuse accepted",
					Description:    "A previously harvested MFA code was accepted again, indicating missing one-time-use enforcement for OTP verification.",
					Evidence:       fmt.Sprintf("Replayed MFA code to %s and received HTTP %d", otpEndpoint, status),
					Recommendation: "Invalidate OTPs immediately after a single successful use and bind them tightly to the session and challenge they were issued for.",
					Confidence:     0.78,
					AffectedURL:    otpEndpoint,
					CWE:            "CWE-308",
					OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
					Sources:        []string{"active-scanner"},
				}}
			}
		}
	}
	for _, protected := range protectedEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, protected, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		lower := strings.ToLower(string(body))
		if resp.StatusCode == http.StatusOK && !strings.Contains(lower, "mfa") && !strings.Contains(lower, "otp") && !strings.Contains(lower, "verify") && !strings.Contains(lower, "login") {
			return []model.Finding{{
				ID:                "mfa-bypass-step-skip",
				Category:          "auth_bypass",
				Severity:          model.SeverityHigh,
				Title:             "Authenticated area reachable without completing MFA step",
				Description:       "A protected post-login page was reachable despite the scanner not completing an observed MFA step, indicating that MFA enforcement is incomplete or can be skipped entirely.",
				Evidence:          fmt.Sprintf("GET %s returned HTTP 200 without an MFA-complete signal", protected),
				Recommendation:    "Enforce MFA completion server-side on every privileged route and gate the session on a dedicated MFA-complete flag before granting application access.",
				Confidence:        0.82,
				AffectedURL:       protected,
				CWE:               "CWE-308",
				OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
				Sources:           []string{"active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("Authenticate normally to seed the session, then GET %s without completing MFA", protected), "Observe access to the protected page."},
				EvidenceFields:    map[string]string{"validationType": "active-probe"},
			}}
		}
	}
	return nil
}

func (s *Service) mfaPostCode(ctx context.Context, input RunInput, raw, code string) (int, []byte, bool) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("otp", code)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, false
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
	if err != nil || resp == nil {
		return 0, nil, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	_ = resp.Body.Close()
	return resp.StatusCode, body, true
}

func mfaResolvePaths(target string, paths []string, scanScope model.ScanScope) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	var out []string
	for _, path := range paths {
		resolved := base.ResolveReference(&url.URL{Path: path}).String()
		if scope.IsURLInScope(resolved, scanScope) {
			out = append(out, resolved)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
