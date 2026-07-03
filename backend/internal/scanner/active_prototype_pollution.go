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

// prototypePollutionBaseKeys are the query-string gadget keys probed on
// every candidate endpoint, independent of any miner-discovered parameter
// names.
var prototypePollutionBaseKeys = []string{"__proto__[polluted]", "constructor[prototype][polluted]"}

// prototypePollutionProbeKeys merges Phase 2 hidden-parameter miner names
// into the pollution gadget key list (see PHASE2_AUDIT.md). Query-string
// miners frequently surface object-shaped parameter names (e.g. "options",
// "settings") that are the primary real-world source of `__proto__`
// merge sinks, so each discovered name is also tried as a nested-object
// container ahead of the top-level built-in keys.
func prototypePollutionProbeKeys(dynamic []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(dynamic)*2+len(prototypePollutionBaseKeys))
	add := func(k string) {
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	for _, p := range dynamic {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		add(p + "[__proto__][polluted]")
		add(p + "[constructor][prototype][polluted]")
	}
	for _, k := range prototypePollutionBaseKeys {
		add(k)
	}
	return out
}

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
	// Phase 2 reference wiring: merge miner-discovered parameter names into
	// the pollution gadget key list.
	probeKeys := prototypePollutionProbeKeys(phase2DynamicParams(input.Session))
	attempts := 0
	for _, raw := range dedupeStrings(candidates) {
		if attempts >= prototypePollutionMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range probeKeys {
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
			// Phase 2 coverage accounting: record this probe key so the
			// surface-gap detector subtracts it from the inventory.
			RecordProbedKey(http.MethodGet, probeURL, param)
			if err != nil || resp == nil {
				continue
			}
			_, _ = io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			_ = resp.Body.Close()
			followBody, followHdr := s.prototypePollutionFollowUp(ctx, input, raw)
			// Phase 1 shape gate: JSON APIs are the primary sink for
			// pollution-observation; binary follow-up responses cannot
			// meaningfully "echo" the marker.
			if IsBinaryShape(followHdr) {
				continue
			}
			if !strings.Contains(followBody, prototypePollutionMarker) {
				continue
			}
			// Phase 1 differential re-verify: replay the same request
			// path WITHOUT the pollution payload and confirm the marker
			// is absent from the follow-up response. If the marker
			// still appears, the target is caching/echoing content
			// from an earlier session or from another source, and this
			// is a false positive.
			diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
				ProbeName:       "active-prototype-pollution",
				OriginalPayload: prototypePollutionMarker,
				SafePayload:     "abh_pp_benign",
				Exec: func(dctx context.Context, benign string) (*http.Response, []byte, error) {
					dprobe := *base
					dq := dprobe.Query()
					dq.Set(param, benign)
					dprobe.RawQuery = dq.Encode()
					dreq, derr := http.NewRequestWithContext(dctx, http.MethodGet, dprobe.String(), nil)
					if derr != nil {
						return nil, nil, derr
					}
					ApplyAuthProfile(dreq, input.AuthProfile)
					dresp, dcerr := s.doRequestWithRetry(dctx, dreq, input.Options)
					if dcerr != nil || dresp == nil {
						return nil, nil, dcerr
					}
					_, _ = io.ReadAll(io.LimitReader(dresp.Body, 256*1024))
					_ = dresp.Body.Close()
					fb, _ := s.prototypePollutionFollowUp(dctx, input, raw)
					return dresp, []byte(fb), nil
				},
				Oracle: func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
					return strings.Contains(string(body), prototypePollutionMarker), nil
				},
			})
			if diffOutcome.Ran && !diffOutcome.Confirmed {
				continue
			}
			curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
			finding := model.Finding{
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
					"responseShape":  ClassifyResponseShape(followHdr).String(),
				},
			}
			AttachDifferentialEvidence(&finding, diffOutcome)
			return []model.Finding{finding}
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
		// Phase 2 coverage accounting: record this probe key so the
		// surface-gap detector subtracts it from the inventory.
		RecordProbedKey(http.MethodPost, raw, "__proto__")
		if err != nil || resp == nil {
			continue
		}
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		followBody, followHdr := s.prototypePollutionFollowUp(ctx, input, raw)
		if IsBinaryShape(followHdr) {
			continue
		}
		if !strings.Contains(followBody, prototypePollutionMarker) {
			continue
		}
		// Phase 1 differential re-verify for the POST/JSON branch: send
		// a benign JSON body without prototype keys and confirm the
		// marker is absent from the follow-up response.
		diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
			ProbeName:       "active-prototype-pollution",
			OriginalPayload: string(postBody),
			SafePayload:     `{"polluted":"abh_pp_benign"}`,
			Exec: func(dctx context.Context, benign string) (*http.Response, []byte, error) {
				dreq, derr := http.NewRequestWithContext(dctx, http.MethodPost, raw, bytes.NewReader([]byte(benign)))
				if derr != nil {
					return nil, nil, derr
				}
				dreq.Header.Set("Content-Type", "application/json")
				ApplyAuthProfile(dreq, input.AuthProfile)
				dresp, dcerr := s.doRequestWithRetry(dctx, dreq, input.Options)
				if dcerr != nil || dresp == nil {
					return nil, nil, dcerr
				}
				_, _ = io.ReadAll(io.LimitReader(dresp.Body, 256*1024))
				_ = dresp.Body.Close()
				fb, _ := s.prototypePollutionFollowUp(dctx, input, raw)
				return dresp, []byte(fb), nil
			},
			Oracle: func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
				return strings.Contains(string(body), prototypePollutionMarker), nil
			},
		})
		if diffOutcome.Ran && !diffOutcome.Confirmed {
			continue
		}
		curl := buildCurlReproducer(http.MethodPost, raw, input.AuthProfile, "application/json", string(postBody))
		finding := model.Finding{
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
				"responseShape":  ClassifyResponseShape(followHdr).String(),
			},
		}
		AttachDifferentialEvidence(&finding, diffOutcome)
		return []model.Finding{finding}
	}
	return nil
}

func (s *Service) prototypePollutionFollowUp(ctx context.Context, input RunInput, raw string) (string, http.Header) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", nil
	}
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return string(body), resp.Header.Clone()
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
