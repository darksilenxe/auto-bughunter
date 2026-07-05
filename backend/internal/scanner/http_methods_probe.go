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

// httpMethodsBodyLimit caps response body reads during method probing.
const httpMethodsBodyLimit = 64 * 1024

// dangerousMethods is the set of HTTP methods that should never be enabled on
// a production endpoint. Their presence indicates a server misconfiguration
// that can be abused for information disclosure (TRACE/XST) or unauthorised
// data modification (PUT/DELETE).
var dangerousMethods = []string{"TRACE", "CONNECT"}

// verbOverrideHeaders are the de-facto standard headers used by frameworks and
// proxies to simulate HTTP methods that some clients cannot send natively.
// An endpoint that honours these without additional access-control checks is
// vulnerable to HTTP verb tampering.
var verbOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-Method-Override",
	"X-HTTP-Method",
	"_method",
}

// runHTTPMethodsProbe is an active probe covering WSTG-CONF-06 and WSTG-INPV-03.
// It performs three checks against each in-scope endpoint:
//
//  1. OPTIONS enumeration — sends an OPTIONS request and parses the
//     Allow/Access-Control-Allow-Methods header to detect dangerous verbs.
//  2. TRACE detection — sends a TRACE request and checks whether the server
//     echoes the request body (cross-site tracing / XST).
//  3. HTTP verb override — attempts to tunnel a DELETE/PUT via an override
//     header (e.g. X-HTTP-Method-Override: DELETE) on a GET request to detect
//     ACL bypass via method tunnelling.
func (s *Service) runHTTPMethodsProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, bodyText, input.Scope, 6)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("http-methods %s", input.Target),
			Message: "Probing for dangerous HTTP methods and verb override bypass",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

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

		// ── 1. OPTIONS enumeration ────────────────────────────────────────────
		fid := "http-methods-options-" + hhSlug(raw)
		if !emitted[fid] {
			optFindings := s.probeOptionsMethod(ctx, raw, input)
			for _, f := range optFindings {
				if !emitted[f.ID] {
					emitted[f.ID] = true
					findings = append(findings, f)
				}
			}
			emitted[fid] = true
		}

		// ── 2. TRACE / XST ───────────────────────────────────────────────────
		fid = "http-methods-trace-" + hhSlug(raw)
		if !emitted[fid] {
			emitted[fid] = true
			if f := s.probeTraceMethod(ctx, raw, input); f != nil {
				findings = append(findings, *f)
			}
		}

		// ── 3. Verb override bypass ───────────────────────────────────────────
		fid = "http-methods-override-" + hhSlug(raw)
		if !emitted[fid] {
			emitted[fid] = true
			if f := s.probeVerbOverride(ctx, raw, input); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings
}

func (s *Service) submitHTTPMethodsFinding(ctx context.Context, finding model.Finding, replay PoCReplayFunc, signals []EvidenceSignal) (model.Finding, bool) {
	out := SubmitVerifiedFinding(ctx, VerifyCandidate{
		Finding:   finding,
		Signals:   signals,
		PoCReplay: replay,
		ProbeName: "http-methods-probe",
	})
	if out.Suppressed {
		return model.Finding{}, false
	}
	return out.EmittedFinding, true
}

// probeOptionsMethod sends OPTIONS and inspects the Allow header for dangerous
// methods.
func (s *Service) probeOptionsMethod(ctx context.Context, target string, input RunInput) []model.Finding {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	safe := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, safe.String(), nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, input.AuthProfile)

	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	// Phase 2 coverage accounting: record this probe key so the
	// surface-gap detector subtracts it from the inventory.
	RecordProbedKey(http.MethodOptions, safe.String(), "")
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, httpMethodsBodyLimit))

	allowed := resp.Header.Get("Allow")
	if allowed == "" {
		allowed = resp.Header.Get("Access-Control-Allow-Methods")
	}
	if allowed == "" {
		return nil
	}

	var dangerous []string
	upper := strings.ToUpper(allowed)
	for _, m := range dangerousMethods {
		if strings.Contains(upper, m) {
			dangerous = append(dangerous, m)
		}
	}
	if len(dangerous) == 0 {
		return nil
	}

	var out []model.Finding
	for _, method := range dangerous {
		fid := "http-methods-dangerous-" + strings.ToLower(method) + "-" + hhSlug(target)
		finding := model.Finding{
			ID:       fid,
			Category: "configuration",
			Severity: model.SeverityMedium,
			Title:    fmt.Sprintf("Dangerous HTTP method %s is enabled", method),
			Description: fmt.Sprintf(
				"The server reports that the HTTP method %s is permitted on %s. "+
					"TRACE enables cross-site tracing (XST), which allows an attacker to steal cookies "+
					"that are marked HttpOnly via a browser-based TRACE request. CONNECT can proxy connections "+
					"through the target server to internal hosts.",
				method, target,
			),
			Evidence: fmt.Sprintf("OPTIONS %s → Allow: %s", target, allowed),
			Recommendation: "Disable TRACE and CONNECT at the web server or load-balancer level. " +
				"For Apache: 'TraceEnable Off'. For nginx: deny TRACE/CONNECT in location blocks. " +
				"Verify with: curl -X TRACE https://target/ -v",
			Confidence:    0.88,
			AffectedURL:   target,
			CWE:           "CWE-16",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"active-scanner", "http-methods"},
			ReproductionSteps: []string{
				fmt.Sprintf("Send: OPTIONS %s HTTP/1.1", target),
				fmt.Sprintf("Observe Allow header: %s", allowed),
				fmt.Sprintf("Send: %s %s HTTP/1.1 to confirm execution.", method, target),
			},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"method":         method,
				"allowHeader":    allowed,
			},
		}
		emitted, ok := s.submitHTTPMethodsFinding(ctx, finding, func(rctx context.Context) (bool, string, error) {
			replayReq, err := http.NewRequestWithContext(rctx, http.MethodOptions, safe.String(), nil)
			if err != nil {
				return false, "", err
			}
			ApplyAuthProfile(replayReq, input.AuthProfile)
			replayResp, err := s.doRequestWithRetry(rctx, replayReq, input.Options)
			if err != nil || replayResp == nil {
				return false, "", err
			}
			defer replayResp.Body.Close()
			_, _ = io.ReadAll(io.LimitReader(replayResp.Body, httpMethodsBodyLimit))
			replayAllow := replayResp.Header.Get("Allow")
			if replayAllow == "" {
				replayAllow = replayResp.Header.Get("Access-Control-Allow-Methods")
			}
			return strings.Contains(strings.ToUpper(replayAllow), method), fmt.Sprintf("OPTIONS replay -> Allow: %s", replayAllow), nil
		}, []EvidenceSignal{EvidenceHeaderDelta, EvidenceSinkObserved})
		if ok {
			out = append(out, emitted)
		}
	}
	return out
}

// probeTraceMethod sends a TRACE request with a custom header and checks whether
// the server echoes it back in the response body (XST confirmation).
func (s *Service) probeTraceMethod(ctx context.Context, target string, input RunInput) *model.Finding {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	safe := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}

	const traceMarker = "X-Abh-Trace-Probe"
	const traceMarkerValue = "abh_trace_9f3c2"

	req, err := http.NewRequestWithContext(ctx, "TRACE", safe.String(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set(traceMarker, traceMarkerValue)
	ApplyAuthProfile(req, input.AuthProfile)

	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	RecordProbedKey("TRACE", safe.String(), "")
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, httpMethodsBodyLimit))

	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), traceMarkerValue) {
		return nil
	}

	fid := "http-methods-trace-xst-" + hhSlug(target)
	finding := model.Finding{
		ID:       fid,
		Category: "configuration",
		Severity: model.SeverityMedium,
		Title:    "HTTP TRACE method enabled — Cross-Site Tracing (XST) possible",
		Description: fmt.Sprintf(
			"The server at %s responded to a TRACE request by echoing the request headers back in the response body. "+
				"An attacker can exploit this via a browser-based TRACE request (XmlHttpRequest or Fetch) to steal "+
				"HttpOnly cookie values that are ordinarily inaccessible to JavaScript, bypassing a key XSS mitigation.",
			target,
		),
		Evidence: fmt.Sprintf(
			"TRACE %s → HTTP %d; response body contained the probe marker %q",
			target, resp.StatusCode, traceMarkerValue,
		),
		Recommendation: "Disable the TRACE method in your web server or application: " +
			"Apache: 'TraceEnable Off'; nginx: deny TRACE in server block; IIS: remove TRACE from allowed verbs.",
		Confidence:    0.92,
		AffectedURL:   target,
		CWE:           "CWE-16",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		Sources:       []string{"active-scanner", "http-methods"},
		ReproductionSteps: []string{
			fmt.Sprintf("Send: TRACE %s HTTP/1.1", target),
			fmt.Sprintf("Set header: %s: %s", traceMarker, traceMarkerValue),
			"Confirm the marker appears in the response body.",
		},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"traceMarker":    traceMarkerValue,
			"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
		},
	}
	emitted, ok := s.submitHTTPMethodsFinding(ctx, finding, func(rctx context.Context) (bool, string, error) {
		replayReq, err := http.NewRequestWithContext(rctx, "TRACE", safe.String(), nil)
		if err != nil {
			return false, "", err
		}
		replayReq.Header.Set(traceMarker, traceMarkerValue)
		ApplyAuthProfile(replayReq, input.AuthProfile)
		replayResp, err := s.doRequestWithRetry(rctx, replayReq, input.Options)
		if err != nil || replayResp == nil {
			return false, "", err
		}
		defer replayResp.Body.Close()
		replayBody, _ := io.ReadAll(io.LimitReader(replayResp.Body, httpMethodsBodyLimit))
		return replayResp.StatusCode == http.StatusOK && strings.Contains(string(replayBody), traceMarkerValue), fmt.Sprintf("TRACE replay -> HTTP %d", replayResp.StatusCode), nil
	}, []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved})
	if !ok {
		return nil
	}
	return &emitted
}

// probeVerbOverride attempts to tunnel a DELETE request via X-HTTP-Method-Override
// headers sent on a GET request. A 2xx response (rather than 405 Method Not Allowed)
// on a sensitive path indicates that the ACL check is bypassed via method tunnelling.
func (s *Service) probeVerbOverride(ctx context.Context, target string, input RunInput) *model.Finding {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	safe := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}

	// First establish a baseline GET status code.
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, safe.String(), nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(baseReq, input.AuthProfile)
	baseResp, err := s.doRequestWithRetry(ctx, baseReq, input.Options)
	RecordProbedKey(http.MethodGet, safe.String(), "")
	if err != nil || baseResp == nil {
		return nil
	}
	defer baseResp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(baseResp.Body, httpMethodsBodyLimit))
	baseStatus := baseResp.StatusCode

	for _, overrideHeader := range verbOverrideHeaders {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, safe.String(), nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		req.Header.Set(overrideHeader, http.MethodDelete)

		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		// Phase 2 coverage accounting: the overridden method (DELETE) is
		// what is effectively under test here, even though the wire
		// method is GET, so the gap detector should attribute this
		// endpoint as having its DELETE surface exercised.
		RecordProbedKey(http.MethodDelete, safe.String(), "")
		if err != nil || resp == nil {
			continue
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(io.LimitReader(resp.Body, httpMethodsBodyLimit))

		// Signal: override produced a materially different status (e.g. 200→405
		// expected but override bypasses to 200, or 403→200 access bypass).
		if resp.StatusCode != baseStatus && (resp.StatusCode >= 200 && resp.StatusCode < 300) {
			fid := "http-methods-verb-override-" + strings.ToLower(strings.ReplaceAll(overrideHeader, "-", "_")) + "-" + hhSlug(target)
			finding := model.Finding{
				ID:       fid,
				Category: "access-control",
				Severity: model.SeverityMedium,
				Title:    fmt.Sprintf("HTTP verb override accepted via %s header", overrideHeader),
				Description: fmt.Sprintf(
					"The endpoint %s accepted an HTTP verb override via the '%s: DELETE' header. "+
						"A GET request with this override header returned HTTP %d, whereas the baseline GET returned HTTP %d. "+
						"This indicates the application or a proxy in front of it honours method tunnelling headers, "+
						"which attackers can use to bypass ACL checks that key on the HTTP verb.",
					target, overrideHeader, resp.StatusCode, baseStatus,
				),
				Evidence: fmt.Sprintf(
					"GET %s with %s: DELETE → HTTP %d (baseline GET → HTTP %d)",
					target, overrideHeader, resp.StatusCode, baseStatus,
				),
				Recommendation: "Reject or ignore X-HTTP-Method-Override and related tunnelling headers on endpoints " +
					"that enforce access control based on the HTTP method. Configure your framework/router to not " +
					"honour these headers, or add explicit ACL checks that ignore them.",
				Confidence:    0.80,
				AffectedURL:   target,
				CWE:           "CWE-650",
				OWASPCategory: "A01:2021 - Broken Access Control",
				Sources:       []string{"active-scanner", "http-methods"},
				ReproductionSteps: []string{
					fmt.Sprintf("GET %s HTTP/1.1", target),
					fmt.Sprintf("%s: DELETE", overrideHeader),
					fmt.Sprintf("Observe HTTP %d (expected method-not-allowed or identical to baseline).", resp.StatusCode),
				},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"overrideHeader": overrideHeader,
					"baseStatus":     fmt.Sprintf("%d", baseStatus),
					"overrideStatus": fmt.Sprintf("%d", resp.StatusCode),
				},
			}
			emitted, ok := s.submitHTTPMethodsFinding(ctx, finding, func(rctx context.Context) (bool, string, error) {
				replayBaseReq, err := http.NewRequestWithContext(rctx, http.MethodGet, safe.String(), nil)
				if err != nil {
					return false, "", err
				}
				ApplyAuthProfile(replayBaseReq, input.AuthProfile)
				replayBaseResp, err := s.doRequestWithRetry(rctx, replayBaseReq, input.Options)
				if err != nil || replayBaseResp == nil {
					return false, "", err
				}
				defer replayBaseResp.Body.Close()
				_, _ = io.ReadAll(io.LimitReader(replayBaseResp.Body, httpMethodsBodyLimit))
				replayReq, err := http.NewRequestWithContext(rctx, http.MethodGet, safe.String(), nil)
				if err != nil {
					return false, "", err
				}
				ApplyAuthProfile(replayReq, input.AuthProfile)
				replayReq.Header.Set(overrideHeader, http.MethodDelete)
				replayResp, err := s.doRequestWithRetry(rctx, replayReq, input.Options)
				if err != nil || replayResp == nil {
					return false, "", err
				}
				defer replayResp.Body.Close()
				_, _ = io.ReadAll(io.LimitReader(replayResp.Body, httpMethodsBodyLimit))
				return replayResp.StatusCode != replayBaseResp.StatusCode && replayResp.StatusCode >= 200 && replayResp.StatusCode < 300,
					fmt.Sprintf("override replay -> HTTP %d (baseline %d)", replayResp.StatusCode, replayBaseResp.StatusCode), nil
			}, []EvidenceSignal{EvidenceStatusDelta, EvidenceSinkObserved})
			if ok {
				return &emitted
			}
		}
	}
	return nil
}
