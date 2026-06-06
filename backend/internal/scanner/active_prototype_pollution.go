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
	prototypePollutionMarker      = "abh_pp_7f9e2"
	prototypePollutionMaxAttempts = 8
)

var prototypePollutionPaths = []string{"/api/profile", "/api/user", "/api/account", "/profile", "/account", "/user", "/register", "/update", "/edit"}

func (s *Service) runActivePrototypePollutionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	candidates = append(candidates, prototypePollutionCandidatePaths(input.Target, input.Scope)...)
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}
	attempts := 0
	for _, raw := range dedupeStrings(candidates) {
		if attempts >= prototypePollutionMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range []string{"__proto__[polluted]", "constructor[prototype][polluted]"} {
			if attempts >= prototypePollutionMaxAttempts {
				break
			}
			probe := *base
			q := probe.Query()
			q.Set(param, prototypePollutionMarker)
			probe.RawQuery = q.Encode()
			probeURL := probe.String()
			if !scope.IsURLInScope(probeURL, input.Scope) {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			attempts++
			if err != nil || resp == nil {
				continue
			}
			_, _ = io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			_ = resp.Body.Close()
			if followBody := s.prototypePollutionFollowUp(ctx, input, raw); strings.Contains(followBody, prototypePollutionMarker) {
				curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
				return []model.Finding{{
					ID:                "active-prototype-pollution",
					Category:          "input-validation",
					Severity:          model.SeverityHigh,
					Title:             "Server-side prototype pollution indicator detected",
					Description:       "A prototype-pollution payload introduced a marker that subsequently appeared in a follow-up response, indicating attacker-controlled properties may be polluting server-side object prototypes or shared object templates.",
					Evidence:          fmt.Sprintf("GET %s polluted subsequent response content with marker %q", probeURL, prototypePollutionMarker),
					Recommendation:    "Reject __proto__, constructor, and prototype keys during input deserialization/merge operations, use safe object-merge libraries, and deep-clone onto null-prototype objects where possible.",
					Confidence:        0.82,
					AffectedURL:       raw,
					AffectedParameter: param,
					CWE:               "CWE-1321",
					OWASPCategory:     "A03:2021 - Injection",
					Sources:           []string{"active-scanner"},
					ReproductionSteps: []string{fmt.Sprintf("Send GET %s", probeURL), fmt.Sprintf("Request %s again and observe marker %q in the response.", raw, prototypePollutionMarker)},
					PoC:               curl,
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"payload":        prototypePollutionMarker,
						"curlReproducer": curl,
					},
				}}
			}
		}
		if attempts >= prototypePollutionMaxAttempts {
			break
		}
		if !prototypePollutionPostCandidate(base.Path) {
			continue
		}
		postBody := []byte(`{"__proto__":{"polluted":"` + prototypePollutionMarker + `"}}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader(postBody))
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
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		if followBody := s.prototypePollutionFollowUp(ctx, input, raw); strings.Contains(followBody, prototypePollutionMarker) {
			curl := buildCurlReproducer(http.MethodPost, raw, input.AuthProfile, "application/json", string(postBody))
			return []model.Finding{{
				ID:                "active-prototype-pollution",
				Category:          "input-validation",
				Severity:          model.SeverityHigh,
				Title:             "Server-side prototype pollution indicator detected",
				Description:       "A JSON prototype-pollution payload introduced a marker that appeared in a later response, indicating unsafe object merge or deserialization behavior on the server.",
				Evidence:          fmt.Sprintf("POST %s with a __proto__ JSON body caused marker %q to persist into a follow-up response", raw, prototypePollutionMarker),
				Recommendation:    "Block prototype keys during object merges and treat JSON object graphs from untrusted sources as tainted until normalized into safe application types.",
				Confidence:        0.82,
				AffectedURL:       raw,
				CWE:               "CWE-1321",
				OWASPCategory:     "A03:2021 - Injection",
				Sources:           []string{"active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("Send POST %s with body %s", raw, string(postBody)), fmt.Sprintf("Request %s again and observe marker %q in the response.", raw, prototypePollutionMarker)},
				PoC:               curl,
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"payload":        prototypePollutionMarker,
					"curlReproducer": curl,
				},
			}}
		}
	}
	return nil
}

func (s *Service) prototypePollutionFollowUp(ctx context.Context, input RunInput, raw string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return ""
	}
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return string(body)
}

func prototypePollutionPostCandidate(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{"api", "user", "profile", "account", "register", "update", "edit"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return lower == "" || lower == "/"
}

func prototypePollutionCandidatePaths(target string, scanScope model.ScanScope) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	var out []string
	for _, path := range prototypePollutionPaths {
		resolved := base.ResolveReference(&url.URL{Path: path}).String()
		if scope.IsURLInScope(resolved, scanScope) {
			out = append(out, resolved)
		}
	}
	return out
}
