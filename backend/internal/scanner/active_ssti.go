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

// sstiProbeParams are the parameter names most commonly rendered through a
// server-side template engine. Picked to overlap with the XSS probe set
// because the shapes ("name", "title", "msg", "search") frequently appear
// inside greeting/landing/error templates.
var sstiProbeParams = []string{"q", "search", "name", "title", "msg", "message", "subject", "preview"}

// sstiPayloads is a dictionary of "harmless arithmetic" markers, one per
// major template engine family. Each pair is the rendered-input/expected-
// output combination that confirms server-side evaluation. We deliberately
// pick `7*7` rather than `49*7` etc. to avoid double-counting natural-text
// `49` occurrences in the response.
var sstiPayloads = []struct {
	engine  string
	payload string
	expect  string
}{
	// Jinja2 / Twig / Liquid (Python, PHP, Ruby).
	{"jinja2/twig", "{{7*7}}", "49"},
	// AngularJS / Vue (client-side, but listed for completeness — the same
	// signature appearing in HTML still indicates an evaluating template).
	{"angular", "{{7*'7'}}", "49"},
	// JSP EL / Spring SpEL / Velocity.
	{"jsp-el/spel", "${7*7}", "49"},
	// ERB / EJS / ASP.
	{"erb/ejs/asp", "<%= 7*7 %>", "49"},
	// Mustache/Handlebars don't evaluate expressions, so we do not include
	// a `{{7*7}}` -> `49` payload for those — the marker would simply be
	// echoed verbatim and we would false-positive.
}

// sstiMaxAttempts caps probe budget per scan.
const sstiMaxAttempts = 12

// runActiveSSTIProbe is an active server-side-template-injection scanner.
// For each in-scope runtime endpoint it injects a small arithmetic payload
// for each common template-engine family into a curated list of reflective
// parameter names and inspects the response for the *evaluated* result
// (e.g. `49`) without the literal payload also being present (which would
// indicate the input was simply reflected, not evaluated).
//
// Confirmation requires BOTH:
//   - the expected result substring appears in the response body, AND
//   - the literal payload does NOT appear (otherwise the response is a
//     plain reflection, which is the XSS probe's job, not SSTI's).
func (s *Service) runActiveSSTIProbe(ctx context.Context, input RunInput, body string) []model.Finding {
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

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-ssti %s", input.Target),
			Message: "Probing for server-side template injection via arithmetic markers",
		})
	}

	type hit struct {
		url     string
		param   string
		engine  string
		payload string
	}
	var hits []hit
	attempts := 0
	for _, raw := range candidates {
		if attempts >= sstiMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, p := range sstiProbeParams {
			if attempts >= sstiMaxAttempts {
				break
			}
			payloads := make([]sstiVariant, 0, len(sstiPayloads))
			if input.Options.WAFBypass {
				payloads = sstiBypassVariants()
			} else {
				for _, v := range sstiPayloads {
					payloads = append(payloads, sstiVariant{engine: v.engine, payload: v.payload, expect: v.expect})
				}
			}
			for _, payload := range payloads {
				if attempts >= sstiMaxAttempts {
					break
				}
				probe := *base
				q := probe.Query()
				q.Set(p, payload.payload)
				probe.RawQuery = q.Encode()
				probeURL := probe.String()
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				// safety.ValidateOutboundURL is intentionally not re-checked
				// here — see active_xss.go for rationale.
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
				if isSSTIEvaluation(string(respBody), payload.payload, payload.expect) {
					hits = append(hits, hit{url: probeURL, param: p, engine: payload.engine, payload: payload.payload})
					break
				}
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, fmt.Sprintf("%s (param=%s, engine=%s, payload=%q)", h.url, h.param, h.engine, h.payload))
	}
	steps := []string{
		fmt.Sprintf("Send GET %s — note the parameter %s carries the payload %q.", first.url, first.param, first.payload),
		"Inspect the response body and confirm the evaluated arithmetic result (49) appears WITHOUT the literal payload — the template engine evaluated the expression server-side.",
		"Confirm code execution scope by escalating to engine-specific payloads (e.g. {{config}} on Jinja2, ${T(java.lang.Runtime)} on SpEL).",
	}
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")
	return []model.Finding{{
		ID:                "active-ssti-arithmetic",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "Server-side template injection: arithmetic payload evaluated by template engine",
		Description:       "An arithmetic marker injected into a query parameter was evaluated server-side and returned in the response. SSTI typically allows arbitrary code execution in the language that backs the template engine (e.g. Python via Jinja2, Java via SpEL).",
		Evidence:          fmt.Sprintf("Evaluated marker observed at: %s", strings.Join(limitStrings(urls, 6), "; ")),
		Recommendation:    "Never pass untrusted input directly into a template render call. Use sandboxed/logic-less templates (e.g. Mustache) or strict allow-listing for any user-controlled fields. Disable template engine features that allow arbitrary attribute access.",
		Confidence:        0.9,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-1336",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType":  "active-probe",
			"reproStep":       "Replay the listed URL and confirm `49` appears in the response without the literal payload",
			"templateEngine":  first.engine,
			"injectedPayload": first.payload,
			"curlReproducer":  curl,
		},
	}}
}

// isSSTIEvaluation returns true when the body contains the expected
// evaluated value but does NOT also contain the literal payload — the
// strict requirement that distinguishes evaluation from reflection.
func isSSTIEvaluation(body, payload, expect string) bool {
	if body == "" || payload == "" || expect == "" {
		return false
	}
	if !strings.Contains(body, expect) {
		return false
	}
	if strings.Contains(body, payload) {
		return false
	}
	return true
}
