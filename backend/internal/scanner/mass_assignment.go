package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

const (
	massAssignmentBody        = `{"role":"admin","isAdmin":true,"admin":true,"verified":true,"is_staff":true,"privilege":"admin"}`
	massAssignmentMaxAttempts = 6
)

var massAssignmentPaths = []string{"/api/user", "/api/profile", "/api/account", "/api/register", "/api/update", "/api/edit", "/user", "/profile", "/account", "/register", "/update", "/edit"}

func (s *Service) runMassAssignmentProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	candidates = append(candidates, massAssignmentCandidatePaths(input.Target, input.Scope)...)
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}
	attempts := 0
	for _, raw := range dedupeStrings(candidates) {
		if attempts >= massAssignmentMaxAttempts {
			break
		}
		if !scope.IsURLInScope(raw, input.Scope) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewBufferString(massAssignmentBody))
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		attempts++
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		lower := strings.ToLower(string(respBody))
		if resp.StatusCode == http.StatusOK && (strings.Contains(lower, `"admin"`) || strings.Contains(lower, `"role":"admin"`) || strings.Contains(lower, `"isadmin":true`) || strings.Contains(lower, `"verified":true`)) {
			curl := buildCurlReproducer(http.MethodPost, raw, input.AuthProfile, "application/json", massAssignmentBody)
			return []model.Finding{{
				ID:                "mass-assignment",
				Category:          "input-validation",
				Severity:          model.SeverityHigh,
				Title:             "Mass assignment of privileged fields",
				Description:       "The API accepted and reflected privileged fields such as role/admin/verified from a user-controlled JSON body, indicating missing server-side field allowlisting and potential privilege escalation.",
				Evidence:          fmt.Sprintf("POST %s accepted privileged JSON fields and returned %s", raw, truncateString(string(respBody), 120)),
				Recommendation:    "Apply server-side allowlists for bindable fields, ignore or reject security-sensitive properties from client input, and derive authorization flags exclusively from trusted server-side state.",
				Confidence:        0.87,
				AffectedURL:       raw,
				CWE:               "CWE-915",
				OWASPCategory:     "A08:2021 - Software and Data Integrity Failures",
				Sources:           []string{"active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("Send POST %s with body %s", raw, massAssignmentBody), "Observe privileged fields echoed or applied by the response."},
				PoC:               curl,
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"curlReproducer": curl,
				},
			}}
		}
	}
	return nil
}

func massAssignmentCandidatePaths(target string, scanScope model.ScanScope) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	var out []string
	for _, path := range massAssignmentPaths {
		resolved := base.ResolveReference(&url.URL{Path: path}).String()
		if scope.IsURLInScope(resolved, scanScope) {
			out = append(out, resolved)
		}
	}
	return out
}
