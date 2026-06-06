package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

const accountEnumerationMaxAttempts = 4

var accountEnumerationPaths = []string{"/login", "/signin", "/password-reset", "/forgot", "/register"}

func (s *Service) runAccountEnumerationProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := []string{input.Target}
	candidates = append(candidates, accountEnumerationCandidatePaths(input.Target, input.Scope)...)
	candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	attempts := 0
	for _, raw := range dedupeStrings(candidates) {
		if attempts >= accountEnumerationMaxAttempts {
			break
		}
		if !scope.IsURLInScope(raw, input.Scope) {
			continue
		}
		validStatus, validBody, validElapsed, ok := s.accountEnumerationRequest(ctx, input, raw, "admin")
		if !ok {
			continue
		}
		invalidStatus, invalidBody, invalidElapsed, ok := s.accountEnumerationRequest(ctx, input, raw, "nouser_abh_7f9e2@abh-test.invalid")
		attempts += 2
		if !ok {
			continue
		}
		reasons := []string{}
		if validStatus != invalidStatus {
			reasons = append(reasons, fmt.Sprintf("status codes differ (%d vs %d)", validStatus, invalidStatus))
		}
		if absInt(len(validBody)-len(invalidBody)) > 50 {
			reasons = append(reasons, fmt.Sprintf("body lengths differ (%d vs %d)", len(validBody), len(invalidBody)))
		}
		if diff := validElapsed - invalidElapsed; diff < -150*time.Millisecond || diff > 150*time.Millisecond {
			reasons = append(reasons, fmt.Sprintf("timings differ (%s vs %s)", validElapsed.Round(time.Millisecond), invalidElapsed.Round(time.Millisecond)))
		}
		if len(reasons) == 0 {
			continue
		}
		return []model.Finding{{
			ID:             "account-enumeration",
			Category:       "information_disclosure",
			Severity:       model.SeverityMedium,
			Title:          "Account enumeration via differential authentication responses",
			Description:    "The authentication-related endpoint responds differently for likely-valid and invalid usernames, allowing attackers to enumerate real accounts prior to password attacks or credential stuffing.",
			Evidence:       fmt.Sprintf("POST %s produced differential behavior: %s", raw, strings.Join(reasons, "; ")),
			Recommendation: "Return uniform status codes, response bodies, and timing for valid and invalid accounts. Use generic error messages and apply rate limits/monitoring to login and reset flows.",
			Confidence:     0.86,
			AffectedURL:    raw,
			CWE:            "CWE-200",
			OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
			Sources:        []string{"active-scanner"},
			ReproductionSteps: []string{
				fmt.Sprintf("POST %s with username=admin and a dummy password", raw),
				"Repeat with a clearly non-existent username and compare status, body length, and timing.",
			},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"validStatus":    fmt.Sprintf("%d", validStatus),
				"invalidStatus":  fmt.Sprintf("%d", invalidStatus),
			},
		}}
	}
	return nil
}

func (s *Service) accountEnumerationRequest(ctx context.Context, input RunInput, raw, username string) (int, []byte, time.Duration, bool) {
	form := url.Values{}
	form.Set("username", username)
	form.Set("email", username)
	form.Set("password", "WrongPassw0rd!")
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, 0, false
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return 0, nil, 0, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	_ = resp.Body.Close()
	return resp.StatusCode, body, time.Since(start), true
}

func accountEnumerationCandidatePaths(target string, scanScope model.ScanScope) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	var out []string
	for _, path := range accountEnumerationPaths {
		resolved := base.ResolveReference(&url.URL{Path: path}).String()
		if scope.IsURLInScope(resolved, scanScope) {
			out = append(out, resolved)
		}
	}
	return out
}
