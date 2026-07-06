package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// xssiBodyLimit caps response body reads during XSSI/JSONP probing.
const xssiBodyLimit = 128 * 1024

// xssiMaxEndpoints caps how many endpoints are examined per scan.
const xssiMaxEndpoints = 12

// jsonpCallbackParams are the query parameter names commonly used as JSONP
// callback function names.
var jsonpCallbackParams = []string{
	"callback", "cb", "jsonp", "jsonpcallback", "call", "fn",
	"func", "function", "handler", "wrap", "callbackFn",
}

// jsonpFunctionPattern matches a JavaScript function-call wrapper around a
// JSON payload, which is the canonical JSONP response format:
// myFunc({...}) or myFunc([...])
var jsonpFunctionPattern = regexp.MustCompile(`(?m)^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\([\s\[{]`)

// xssiArrayPattern matches a top-level JSON array response, which is
// susceptible to XSSI via the Array constructor override attack in browsers
// that do not enforce per-origin array constructor isolation.
var xssiArrayPattern = regexp.MustCompile(`(?m)^\s*\[`)

// runXSSIJSONPProbe is an active probe covering WSTG-CLNT-13. It performs
// two checks:
//
//  1. JSONP endpoint detection — appends a callback parameter to candidate
//     endpoints and checks whether the response is wrapped in a JavaScript
//     function call. If so, the endpoint is a JSONP endpoint.
//     A JSONP endpoint that reflects attacker-controlled callback names is
//     vulnerable to arbitrary JavaScript injection (JSONP hijacking).
//
//  2. XSSI detection — checks whether an endpoint returns a JSON array or
//     object as a top-level JavaScript response without CSRF protection,
//     which allows cross-site script inclusion attacks in legacy browsers.
func (s *Service) runXSSIJSONPProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, bodyText, input.Scope, xssiMaxEndpoints)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("xssi-jsonp %s", input.Target),
			Message: "Probing for JSONP endpoints and XSSI vulnerabilities",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}
	dynamicParams := phase2DynamicParams(input.Session)
	callbackParams := phase2ProbeParams(dynamicParams, jsonpCallbackParams)

	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if err := safety.ValidateOutboundURL(raw); err != nil {
			continue
		}
		if !scope.IsURLInScope(raw, input.Scope) {
			continue
		}

		base, err := url.Parse(raw)
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}

		// ── JSONP detection ───────────────────────────────────────────────────
		for _, cbParam := range callbackParams {
			fid := "jsonp-" + cbParam + "-" + hhSlug(raw)
			if emitted[fid] {
				continue
			}

			// Use a distinctive probe callback name to distinguish reflected
			// JSONP from a generic function-wrapped response.
			probeCallback := "abh_jsonp_probe_7a3c1"
			q := base.Query()
			q.Set(cbParam, probeCallback)
			probeURL := url.URL{
				Scheme:   base.Scheme,
				Host:     base.Host,
				Path:     base.Path,
				RawQuery: q.Encode(),
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)

			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			RecordProbedKey(http.MethodGet, probeURL.String(), cbParam)
			if err != nil || resp == nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, xssiBodyLimit))
			respHeader := resp.Header
			_ = resp.Body.Close()
			respStr := string(respBody)

			// Phase 1 FP-reduction: JSONP responses must arrive as
			// JavaScript or JSON. HTML/binary responses that happen to
			// contain the probe callback string (e.g. inside a docs
			// page or an error template) would produce false positives.
			shape := ClassifyResponseShape(respHeader)
			if shape != ShapeJavaScript && shape != ShapeJSON {
				continue
			}
			isJS := shape == ShapeJavaScript || shape == ShapeJSON

			// Confirm JSONP: response wraps data in our probe callback function.
			if strings.HasPrefix(strings.TrimSpace(respStr), probeCallback+"(") ||
				strings.Contains(respStr, probeCallback+"(") {
				emitted[fid] = true
				findings = append(findings, model.Finding{
					ID:       fid,
					Category: "client-side",
					Severity: model.SeverityHigh,
					Title:    fmt.Sprintf("JSONP endpoint detected — callback parameter %q reflected", cbParam),
					Description: fmt.Sprintf(
						"The endpoint %s wraps its JSON response in a JavaScript function call using "+
							"an attacker-controlled callback name supplied via the %q parameter. "+
							"An attacker can use this to steal sensitive API response data by including "+
							"the JSONP endpoint as a <script src> from their own site: "+
							"the victim's browser executes the JSONP response in the attacker's context, "+
							"where a redefined function captures the data.",
						raw, cbParam,
					),
					Evidence: fmt.Sprintf(
						"GET %s → HTTP %d (Content-Type: %s); response begins with: %s",
						probeURL.String(), resp.StatusCode, resp.Header.Get("Content-Type"),
						strings.TrimSpace(respStr[:min(len(respStr), 100)]),
					),
					Recommendation: "Replace JSONP with CORS. If JSONP must be retained, " +
						"allowlist callback function names (e.g. alphanumeric only, max 32 chars) " +
						"and set Content-Type: application/json instead of application/javascript. " +
						"Require authentication for any endpoint returning sensitive user data.",
					Confidence:    0.90,
					AffectedURL:   raw,
					CWE:           "CWE-352",
					OWASPCategory: "A01:2021 - Broken Access Control",
					Sources:       []string{"active-scanner", "xssi-jsonp"},
					ReproductionSteps: []string{
						fmt.Sprintf("<script src=\"%s\"></script>", probeURL.String()),
						"From an attacker-controlled page, redefine the callback function before loading the script.",
						"Observe that the victim's sensitive data is passed to the attacker's function.",
					},
					EvidenceFields: map[string]string{
						"validationType":  "active-probe",
						"callbackParam":   cbParam,
						"probeCallback":   probeCallback,
						"contentType":     resp.Header.Get("Content-Type"),
						"responseStatus":  fmt.Sprintf("%d", resp.StatusCode),
						"responseShape":   shape.String(),
					},
				})
				break // one finding per endpoint is sufficient
			}

			// JSONP without explicit callback reflection: detect from content type.
			if isJS && (jsonpFunctionPattern.MatchString(respStr) && !emitted["xssi-jsonp-fn-"+hhSlug(raw)]) {
				emitted["xssi-jsonp-fn-"+hhSlug(raw)] = true
				findings = append(findings, model.Finding{
					ID:       "xssi-jsonp-fn-" + hhSlug(raw),
					Category: "client-side",
					Severity: model.SeverityMedium,
					Title:    "JSONP-style JavaScript response — potential XSSI",
					Description: fmt.Sprintf(
						"The endpoint %s returns a JSON payload wrapped in a JavaScript function call "+
							"with Content-Type: %s. Cross-site script inclusion (XSSI) allows an attacker to "+
							"steal this data by overriding the global function before loading the script. "+
							"Even without a reflected callback parameter, the response structure enables data exfiltration.",
						raw, resp.Header.Get("Content-Type"),
					),
					Evidence: fmt.Sprintf(
						"GET %s → HTTP %d (Content-Type: %s); response matches function-call pattern",
						raw, resp.StatusCode, resp.Header.Get("Content-Type"),
					),
					Recommendation: "Return JSON with Content-Type: application/json instead of application/javascript. " +
						"Add a CSRF token requirement or SameSite=Strict cookies to prevent cross-site inclusion.",
					Confidence:    0.75,
					AffectedURL:   raw,
					CWE:           "CWE-345",
					OWASPCategory: "A01:2021 - Broken Access Control",
					Sources:       []string{"active-scanner", "xssi-jsonp"},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"contentType":    resp.Header.Get("Content-Type"),
						"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
						"responseShape":  shape.String(),
					},
				})
			}
		}

		// ── XSSI: top-level array detection ───────────────────────────────────
		fidArr := "xssi-array-" + hhSlug(raw)
		if !emitted[fidArr] {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			RecordProbedKey(http.MethodGet, raw, "")
			if err != nil || resp == nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, xssiBodyLimit))
			respHeader := resp.Header
			_ = resp.Body.Close()
			respStr := string(respBody)

			// Phase 1 FP-reduction: only classify array-shaped bodies
			// when the response is served as JavaScript/JSON. HTML
			// bodies that happen to start with '[' are not XSSI sinks.
			shape := ClassifyResponseShape(respHeader)
			if shape != ShapeJavaScript && shape != ShapeJSON {
				continue
			}
			ct := strings.ToLower(respHeader.Get("Content-Type"))

			if xssiArrayPattern.MatchString(respStr) && shape == ShapeJavaScript {
				// Array-style XSSI is a meaningful risk only when the
				// endpoint is served with JavaScript content type
				// (application/json responses are XSSI-safe in modern
				// browsers).
				if strings.Contains(ct, "javascript") {
					emitted[fidArr] = true
					findings = append(findings, model.Finding{
						ID:       fidArr,
						Category: "client-side",
						Severity: model.SeverityMedium,
						Title:    "XSSI — top-level JSON array served as JavaScript",
						Description: fmt.Sprintf(
							"The endpoint %s returns a top-level JSON array with Content-Type: %s. "+
								"Serving array-typed JSON responses as JavaScript enables XSSI attacks: "+
								"an attacker can override the Array constructor or use other XSSI techniques "+
								"to capture the array contents from a <script src> inclusion on their site.",
							raw, resp.Header.Get("Content-Type"),
						),
						Evidence: fmt.Sprintf(
							"GET %s → HTTP %d (Content-Type: %s); response starts with '['",
							raw, resp.StatusCode, resp.Header.Get("Content-Type"),
						),
						Recommendation: "Change the Content-Type of JSON array responses to application/json. " +
							"Add a CSRF token or SameSite cookie requirement. Prefix JSON array responses with " +
							"the anti-XSSI prefix ')]}\\n' commonly used by Angular/Google APIs.",
						Confidence:    0.80,
						AffectedURL:   raw,
						CWE:           "CWE-345",
						OWASPCategory: "A01:2021 - Broken Access Control",
						Sources:       []string{"active-scanner", "xssi-jsonp"},
						EvidenceFields: map[string]string{
							"validationType": "active-probe",
							"contentType":    resp.Header.Get("Content-Type"),
							"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
							"responseShape":  shape.String(),
						},
					})
				}
			}
		}
	}

	return findings
}

// detectJSONPReflection checks if respBody contains the probe callback string,
// confirming JSONP callback reflection. Extracted for testability.
func detectJSONPReflection(respBody, probeCallback string) bool {
trimmed := strings.TrimSpace(respBody)
return strings.HasPrefix(trimmed, probeCallback+"(") ||
strings.Contains(respBody, probeCallback+"(")
}

// detectXSSIArray checks if a response body is a top-level JSON array and the
// content type is JavaScript (not application/json). Extracted for testability.
func detectXSSIArray(respBody, contentType string) bool {
ct := strings.ToLower(contentType)
if !strings.Contains(ct, "javascript") {
return false
}
return xssiArrayPattern.MatchString(respBody)
}
