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

var formulaProbeParams = []string{"name", "first_name", "last_name", "title", "comment", "note", "description", "text", "value", "field"}

const (
	formulaMarker      = "=abh_formula_7f9e2"
	formulaMaxAttempts = 10
)

func (s *Service) runFormulaInjectionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}
	// Phase 2 reference wiring: merge miner-discovered parameter names in
	// front of the built-in wordlist (see PHASE2_AUDIT.md).
	dynamicParams := phase2DynamicParams(input.Session)
	attempts := 0
	for _, raw := range candidates {
		if attempts >= formulaMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range phase2ProbeParams(dynamicParams, formulaProbeParams) {
			if attempts >= formulaMaxAttempts {
				break
			}
			probe := *base
			q := probe.Query()
			q.Set(param, formulaMarker)
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
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			respHeader := resp.Header
			_ = resp.Body.Close()
			// Phase 1 FP-reduction: reflection into binary responses
			// (images, PDFs, archives) is a pattern-match artefact and
			// cannot be exploited by any CSV/XLSX export downstream.
			if IsBinaryShape(respHeader) {
				continue
			}
			if !strings.Contains(string(respBody), formulaMarker) {
				continue
			}
			// Phase 1 FP-reduction (base): re-issue the same request with
			// a benign parameter value to prove the marker was not part
			// of the static baseline (banner, cached template, JS
			// literal reflecting param keys, ...).
			baselines, berr := s.phase1QueryBaselines(ctx, probeURL, param, "abh_benign_baseline", true, input, 256*1024)
			if berr == nil && phase1BaselineContains(baselines, formulaMarker) {
				continue
			}
			// Phase 1 FP-reduction (verify): confirm the marker reflection
			// is payload-controlled and not a static echo of the parameter
			// name/value by replaying with a benign value. If the benign
			// replay also returns the marker, the signal is baseline noise.
			diffOutcome := phase1DifferentialQuery(ctx, s, input, "formula-injection", probeURL, param, formulaMarker, "abh_benign_baseline", 256*1024,
				func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
					return strings.Contains(string(body), formulaMarker), nil
				},
			)
			if diffOutcome.Ran && !diffOutcome.Confirmed {
				continue
			}
			shape := ClassifyResponseShape(respHeader).String()
			ctxKind := ClassifyReflectionContext(string(respBody), formulaMarker).String()
			curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
			finding := model.Finding{
				ID:                "formula-injection",
				Category:          "injection",
				Severity:          model.SeverityMedium,
				Title:             "Spreadsheet formula injection via untrusted reflected value",
				Description:       "A spreadsheet-style formula marker beginning with '=' was reflected intact. If this value is later exported to CSV/XLSX and opened in spreadsheet software, it can execute attacker-controlled formulas or data-exfiltration primitives.",
				Evidence:          fmt.Sprintf("Probe %s reflected marker %q on parameter %q", probeURL, formulaMarker, param),
				Recommendation:    "Prefix spreadsheet-exported values that begin with =, +, -, or @ with a single quote, or otherwise neutralize formula execution before generating CSV/XLSX output.",
				Confidence:        0.84,
				AffectedURL:       probeURL,
				AffectedParameter: param,
				CWE:               "CWE-1236",
				OWASPCategory:     "A03:2021 - Injection",
				Sources:           []string{"active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("Send GET %s", probeURL), fmt.Sprintf("Observe the exact marker %q in the response/export path.", formulaMarker)},
				PoC:               curl,
				EvidenceFields: map[string]string{
					"validationType":    "active-probe",
					"payload":           formulaMarker,
					"curlReproducer":    curl,
					"method":            http.MethodGet,
					"url":               probeURL,
					"param":             param,
					"payloadClass":      "formula-injection",
					"responseShape":     shape,
					"reflectionContext": ctxKind,
					"oracleName":        "formula_injection",
					"oracleVersion":     "v1",
				},
			}
			AttachDifferentialEvidence(&finding, diffOutcome)
			return []model.Finding{finding}
		}
	}
	return nil
}
