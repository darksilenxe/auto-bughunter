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

var danglingMarkupParams = []string{"q", "search", "query", "s", "keyword", "text", "name", "title", "msg", "message"}

const (
	danglingMarkupPayload     = `<img src="//abh-dangling-7f9e2.invalid/`
	danglingMarkupMaxAttempts = 10
)

func (s *Service) runDanglingMarkupProbe(ctx context.Context, input RunInput, body string) []model.Finding {
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
		if attempts >= danglingMarkupMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range danglingMarkupParams {
			if attempts >= danglingMarkupMaxAttempts {
				break
			}
			probe := *base
			q := probe.Query()
			q.Set(param, danglingMarkupPayload)
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
			respHeader := resp.Header
			_ = resp.Body.Close()
			// Phase 1 FP-reduction: dangling markup only executes when the
			// payload lands in an HTML response body. Binary bodies and
			// JSON APIs that echo user input are not exploitable via this
			// vector.
			if !IsHTMLShape(respHeader) {
				continue
			}
			if !strings.Contains(string(respBody), danglingMarkupPayload) {
				continue
			}
			// Phase 1 FP-reduction: classify reflection context and only
			// emit when the payload landed in an HTML text or attribute
			// position where a partial <img tag actually creates a
			// dangling-markup sink. A payload reflected inside a JS
			// string or a comment cannot exfiltrate via <img src=...>.
			ctxKind := ClassifyReflectionContext(string(respBody), danglingMarkupPayload)
			switch ctxKind {
			case ContextHTMLText,
				ContextHTMLAttrDouble,
				ContextHTMLAttrSingle,
				ContextHTMLAttrUnquoted:
				// exploitable sink
			default:
				continue
			}
			curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
			return []model.Finding{{
				ID:                "dangling-markup-injection",
				Category:          "injection",
				Severity:          model.SeverityMedium,
				Title:             "Dangling markup injection in HTML context",
				Description:       "An unclosed HTML tag payload was reflected verbatim, indicating injection into an HTML attribute or tag context where dangling-markup exfiltration attacks can succeed even when classic script payloads fail.",
				Evidence:          fmt.Sprintf("Probe %s reflected the partial tag payload on parameter %q", probeURL, param),
				Recommendation:    "Apply strict HTML output encoding for all untrusted data rendered into HTML contexts, especially attribute values and raw markup fragments.",
				Confidence:        0.85,
				AffectedURL:       probeURL,
				AffectedParameter: param,
				CWE:               "CWE-79",
				OWASPCategory:     "A03:2021 - Injection",
				Sources:           []string{"active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("Send GET %s", probeURL), "Inspect the HTML response and verify the partial <img tag is reflected unencoded."},
				PoC:               curl,
				EvidenceFields: map[string]string{
					"validationType":     "active-probe",
					"payload":            danglingMarkupPayload,
					"curlReproducer":     curl,
					"responseShape":      ClassifyResponseShape(respHeader).String(),
					"reflectionContext":  ctxKind.String(),
				},
			}}
		}
	}
	return nil
}
