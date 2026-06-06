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
	attempts := 0
	for _, raw := range candidates {
		if attempts >= formulaMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range formulaProbeParams {
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
			if err != nil || resp == nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			_ = resp.Body.Close()
			if strings.Contains(string(respBody), formulaMarker) {
				curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
				return []model.Finding{{
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
						"validationType": "active-probe",
						"payload":        formulaMarker,
						"curlReproducer": curl,
					},
				}}
			}
		}
	}
	return nil
}
