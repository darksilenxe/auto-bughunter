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

// domClobberingMarker is the unique id/name value injected into a reflected
// anchor element. HTML documents expose elements with matching id/name
// attributes as named properties on `window` and `document`
// (https://html.spec.whatwg.org/#named-access-on-the-window-object) — this is
// guaranteed browser behaviour, independent of any application JavaScript.
// If unescaped reflection of this marker into the raw HTML body is confirmed,
// any application script that reads `window.<marker>`/`document.<marker>`
// without first checking `typeof` can be clobbered by the injected element,
// which is the precondition for the PayloadsAllTheThings "DOM Clobbering"
// technique (attacker overwrites a config object, feature flag, or callback
// reference expected to be undefined/an object literal).
const domClobberingMarker = "abh_domclob_c9f4a"

// domClobberingPayload injects two same-id/name anchor elements — the
// canonical "DOM Clobbering via HTMLCollection" pattern (a single named
// element yields the element itself; two yields an HTMLCollection, which is
// truthy and array-like, clobbering `Array.isArray`/`typeof x === 'object'`
// guards in vulnerable code that only checks for object-ness).
var domClobberingPayload = fmt.Sprintf(
	`<a id="%s" name="%s"><a id="%s" name="%s" href="//abh-domclob-test.invalid">`,
	domClobberingMarker, domClobberingMarker, domClobberingMarker, domClobberingMarker,
)

// domClobberingOpenTag is the literal, unescaped opening tag we look for in
// the response body. Its presence verbatim (rather than HTML-entity-encoded)
// confirms the injected markup was parsed as a real element instead of being
// neutralised by output encoding.
var domClobberingOpenTag = fmt.Sprintf(`<a id="%s" name="%s">`, domClobberingMarker, domClobberingMarker)

// domClobberingMaxAttempts caps the probe budget.
const domClobberingMaxAttempts = 12

// runDOMClobberingProbe is an active probe for the PayloadsAllTheThings "DOM
// Clobbering" technique. It reuses the reflected-parameter injection
// strategy from active_xss.go, but instead of a script-execution payload it
// injects benign named HTML elements and uses ClassifyReflectionContext to
// confirm the payload lands in raw HTML text (i.e. parsed as real DOM
// elements, not escaped or confined to a script/attribute context).
//
// A raw-HTML reflection of same-id/name elements is sufficient to establish
// the vulnerability class regardless of specific application JavaScript,
// because named-element global exposure is standard HTML/DOM behaviour.
func (s *Service) runDOMClobberingProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 10)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("dom-clobbering %s", input.Target),
			Message: "Probing for DOM Clobbering via named-element HTML injection",
		})
	}

	params := techAwareXSSProbeParams(input.DetectedTech)

	attempts := 0
	for _, ep := range candidates {
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}
		for _, param := range params {
			if attempts >= domClobberingMaxAttempts {
				return nil
			}
			attempts++

			testURL, err := injectQueryParam(ep, param, domClobberingPayload)
			if err != nil {
				continue
			}
			// Phase 2 coverage accounting.
			RecordProbedKey(http.MethodGet, testURL, param)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			if err != nil || resp == nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			respHeader := resp.Header
			_ = resp.Body.Close()

			if !isHTMLLikeContentType(respHeader) {
				continue
			}
			respStr := string(respBody)
			if !strings.Contains(respStr, domClobberingOpenTag) {
				// The literal, unescaped opening tag must survive — this is
				// what confirms the injected markup was parsed as a real
				// element (an HTML-encoded reflection like `&lt;a id=...`
				// never clobbers anything).
				continue
			}

			return s.finishDOMClobberingFinding(ctx, input, ep, param, testURL, respHeader)
		}
	}

	return nil
}

// finishDOMClobberingFinding builds and pre-report-verifies the finding once
// a raw-HTML reflection of the clobbering marker has been confirmed.
func (s *Service) finishDOMClobberingFinding(ctx context.Context, input RunInput, ep, param, testURL string, header http.Header) []model.Finding {
	baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
		cleanURL, err := injectQueryParam(ep, param, "")
		if err != nil {
			return BaselineSample{}, err
		}
		return s.phase1GETSample(bctx, cleanURL, input, 256*1024)
	})
	if berr == nil && phase1BaselineContains(baselines, domClobberingOpenTag) {
		return nil
	}

	diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
		ProbeName:       "dom-clobbering-probe",
		OriginalPayload: domClobberingPayload,
		SafePayload:     "abh_domclob_safe_control",
		Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
			altURL, err := injectQueryParam(ep, param, altPayload)
			if err != nil {
				return nil, nil, err
			}
			req, err := http.NewRequestWithContext(dctx, http.MethodGet, altURL, nil)
			if err != nil {
				return nil, nil, err
			}
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(dctx, req, input.Options)
			if err != nil || resp == nil {
				return nil, nil, err
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			return resp, b, nil
		},
		Oracle: func(_ context.Context, _ string, _ *http.Response, respBody []byte) (bool, error) {
			return strings.Contains(string(respBody), domClobberingOpenTag), nil
		},
	})
	if diffOutcome.Ran && !diffOutcome.Confirmed {
		return nil
	}

	curl := buildCurlReproducer(http.MethodGet, testURL, input.AuthProfile, "", "")
	finding := model.Finding{
		ID:       "dom-clobbering",
		Category: "input-validation",
		Severity: model.SeverityMedium,
		Title:    "DOM Clobbering: unsanitised HTML injection permits named-element global overwrite",
		Description: fmt.Sprintf(
			"The parameter %q on %s reflects attacker-controlled HTML unescaped into the raw document body. "+
				"Injecting `<a id=%q name=%q>` elements creates named global bindings that HTML/DOM guarantees "+
				"expose as `window.%s` / `document.%s`. Any application JavaScript that reads a same-named global "+
				"or config property without first checking `instanceof`/`typeof` can be clobbered to an attacker-"+
				"controlled DOM element or HTMLCollection, bypassing default-value fallbacks, feature flags, or "+
				"CSRF-token/callback references — a common gadget for DOM-Clobbering-to-XSS chains.",
			param, ep, domClobberingMarker, domClobberingMarker, domClobberingMarker, domClobberingMarker,
		),
		Evidence: fmt.Sprintf(
			"GET %s reflected `id=%q name=%q` unescaped in raw HTML text (ClassifyReflectionContext=html_text)",
			testURL, domClobberingMarker, domClobberingMarker,
		),
		Recommendation: "Sanitise all HTML injected from user input (DOMPurify or an equivalent allowlisting " +
			"sanitizer) before it reaches the DOM. In application code, never rely on a bare `if (!window.X)` / " +
			"`if (!config.Y)` check to detect \"unset\" — validate with `typeof window.X === 'expected type'` or " +
			"use `Object.create(null)`-based namespaces that cannot be shadowed by DOM named-property access. " +
			"Deploy a strict Content-Security-Policy to limit the blast radius of any resulting script execution.",
		Confidence:    0.85,
		AffectedURL:   ep,
		CWE:           "CWE-79",
		OWASPCategory: "A03:2021 - Injection",
		Sources:       []string{"active-scanner", "dom-clobbering-probe"},
		PoC:           curl,
		ReproductionSteps: []string{
			fmt.Sprintf("Navigate to %s", testURL),
			fmt.Sprintf("Open devtools console and evaluate `window.%s` — observe it resolves to the injected element(s) instead of being undefined.", domClobberingMarker),
			"Identify application JavaScript reading the same global/config name and craft a clobbering payload that overwrites the expected value (e.g. a callback URL, feature flag, or CSRF token attribute).",
		},
		BusinessTags: []string{"dom-clobbering", "client-side", "input-validation"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"parameter":      param,
			"marker":         domClobberingMarker,
			"reflectionCtx":  ContextHTMLText.String(),
			"curlReproducer": curl,
			"responseShape":  ClassifyResponseShape(header).String(),
		},
	}
	AttachDifferentialEvidence(&finding, diffOutcome)
	emitted, ok := phase1SubmitVerified(ctx, finding, "xss", []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved, EvidenceBodyDelta}, "dom-clobbering-probe")
	if !ok {
		return nil
	}
	return []model.Finding{emitted}
}

// injectQueryParam returns rawURL with param set to value (or removed when
// value is empty), used for both the payload and control/baseline requests.
func injectQueryParam(rawURL, param, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if value == "" {
		q.Del(param)
	} else {
		q.Set(param, value)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
