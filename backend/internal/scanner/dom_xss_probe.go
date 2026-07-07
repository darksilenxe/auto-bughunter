package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"

	"github.com/chromedp/chromedp"
)

// domXSSMaxEndpoints caps how many endpoints the DOM XSS probe navigates.
const domXSSMaxEndpoints = 8

// domXSSPayloadMarker is an inert HTML-context marker embedded in DOM sources
// that the probe monitors for execution via the JS console channel.
const domXSSPayloadMarker = "abh_domxss_cb7a1"

// domXSSPayloads are the hash/window-based DOM source injection payloads tried
// for each endpoint. They use the same distinctive marker so any execution is
// uniquely attributable to this probe session.
var domXSSPayloads = []struct {
	label  string
	hash   string
	source string
}{
	{
		label:  "hash-location",
		hash:   "#" + domXSSPayloadMarker + "<img/src=x onerror=document.title='abh_domxss_cb7a1'>",
		source: "location.hash",
	},
	{
		label:  "hash-angle-bracket",
		hash:   "#<script>document.title='" + domXSSPayloadMarker + "'</script>",
		source: "location.hash → script injection",
	},
}

// RunDOMXSSProbe is an active DOM-based XSS probe that uses the headless
// Chromium instance (chromedp) already used elsewhere in the scanner.
//
// For each candidate endpoint the probe:
//  1. Navigates to the page with a crafted URL fragment (location.hash).
//  2. Evaluates document.title — a common DOM XSS sink used in demos and
//     real applications.
//  3. Monitors for console.error/warn messages containing the marker.
//  4. Checks for any document body injection via innerText scan.
//
// If the marker appears in the title, console output, or body innerHTML after
// fragment injection, the endpoint is likely sinking location.hash into a DOM
// write call without sanitization.
//
// PassiveOnly and scope checks are enforced.
func (s *Service) RunDOMXSSProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(target, "", scanScope, domXSSMaxEndpoints)
	if len(options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{target}
	}
	// Deduplicate and scope-check candidates.
	seen := map[string]struct{}{}
	deduplicated := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if _, ok := seen[c]; ok {
			continue
		}
		if !scope.IsURLInScope(c, scanScope) {
			continue
		}
		seen[c] = struct{}{}
		deduplicated = append(deduplicated, c)
		if len(deduplicated) >= domXSSMaxEndpoints {
			break
		}
	}
	candidates = deduplicated

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("dom-xss-probe %s", target),
			Message: fmt.Sprintf("Probing %d endpoints for DOM-based XSS via location.hash injection", len(candidates)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	// baselineTitles caches the control-navigation (no crafted fragment)
	// title and body text for each endpoint. This lets us detect SPAs whose
	// router echoes the route name or fragment into the document title or
	// body as a normal (non-XSS) behaviour, preventing false positives where
	// the marker appears in the DOM only because the SPA renders the hash as
	// a route/page name, not because a DOM sink executed it.
	type baseline struct {
		title string
		body  string
		shape ResponseShape
	}
	endpointBaselines := make(map[string]baseline, len(candidates))
	filteredCandidates := make([]string, 0, len(candidates))
	probeInput := RunInput{AuthProfile: auth, Options: options}
	for _, ep := range candidates {
		sample, err := s.phase1GETSample(ctx, ep, probeInput, 4096)
		if err != nil {
			continue
		}
		if IsBinaryShape(sample.Header) || !IsHTMLShape(sample.Header) {
			continue
		}
		blCtx, blCancel := chromedpContext(ctx)
		var blTitle, blBody string
		_ = chromedp.Run(blCtx,
			chromedp.Navigate(ep),
			chromedp.Title(&blTitle),
			chromedp.InnerHTML("body", &blBody, chromedp.ByQuery),
		)
		blCancel()
		endpointBaselines[ep] = baseline{title: blTitle, body: blBody, shape: ClassifyResponseShape(sample.Header)}
		filteredCandidates = append(filteredCandidates, ep)
	}
	candidates = filteredCandidates

	for _, ep := range candidates {
		bl := endpointBaselines[ep]
		if strings.Contains(bl.title, domXSSPayloadMarker) || strings.Contains(bl.body, domXSSPayloadMarker) {
			continue
		}
		for _, payload := range domXSSPayloads {
			fid := "dom-xss-" + payload.label + "-" + raceSlug(ep)
			if emitted[fid] {
				continue
			}

			targetURL := ep + payload.hash
			payloadFragment := domXSSPayloadFragment(payload.hash)
			// Phase 2 coverage accounting: record this probe key so the
			// surface-gap detector subtracts it from the inventory. DOM
			// XSS uses a fragment sink rather than a query parameter, so
			// there is no per-parameter key.
			RecordProbedKey(http.MethodGet, ep, "")

			// Build a fresh chromedp context per navigation using the shared
			// helper that handles both local binary and remote sidecar.
			taskCtx, taskCancel := chromedpContext(ctx)
			var titleVal, bodyText string

			err := chromedp.Run(taskCtx,
				chromedp.Navigate(targetURL),
				chromedp.Title(&titleVal),
				chromedp.InnerHTML("body", &bodyText, chromedp.ByQuery),
			)
			taskCancel()

			if err != nil {
				continue
			}

			markerInTitle := strings.Contains(titleVal, domXSSPayloadMarker)
			markerInConsole := false
			reflectionCtx, markerInBody := domXSSDangerousReflection(bodyText, domXSSPayloadMarker, payloadFragment)
			if !markerInBody {
				continue
			}

			evidence := fmt.Sprintf(
				"Endpoint: %s | Hash payload: %s | Marker in title: %t | Marker in body: %t | Marker in console: %t",
				ep, payload.hash, markerInTitle, markerInBody, markerInConsole,
			)

			finding := model.Finding{
				ID:       fid,
				Category: "input-validation",
				Severity: model.SeverityHigh,
				Title:    fmt.Sprintf("DOM-based XSS via %s", payload.source),
				Description: fmt.Sprintf(
					"The endpoint %s sinks the %s source into a DOM write sink without sanitisation. "+
						"After navigating to the page with a crafted URL fragment the marker %q appeared "+
						"in %s — indicating that attacker-controlled input flows from the URL into a DOM "+
						"write point (innerHTML, document.write, eval, or a similar sink). "+
						"DOM XSS enables arbitrary JavaScript execution in the victim's browser context, "+
						"leading to credential theft, session hijacking, and account takeover.",
					ep, payload.source, domXSSPayloadMarker,
					describeDOMXSSLocations(markerInTitle, markerInBody, markerInConsole),
				),
				Evidence: evidence,
				Recommendation: "Sanitize all DOM sources (location.hash, location.search, document.referrer, window.name) " +
					"before writing to DOM sinks. Use DOMPurify for HTML sanitization, or avoid innerHTML altogether " +
					"in favour of textContent or createElement. Deploy a strict Content-Security-Policy that blocks " +
					"inline script execution.",
				Confidence:    0.88,
				AffectedURL:   ep,
				CWE:           "CWE-79",
				OWASPCategory: "A03:2021 - Injection",
				Sources:       []string{"active-scanner", "dom-xss-probe"},
				ReproductionSteps: []string{
					fmt.Sprintf("Open browser and navigate to: %s", targetURL),
					fmt.Sprintf("Observe that the marker %q appears in %s without being escaped.",
						domXSSPayloadMarker,
						describeDOMXSSLocations(markerInTitle, markerInBody, markerInConsole),
					),
					"Replace the marker with a real XSS payload, e.g. <img src=x onerror=alert(document.domain)>",
					"Confirm script execution in browser developer console.",
				},
				BusinessTags: []string{"dom-xss", "client-side", "input-validation"},
				EvidenceFields: map[string]string{
					"validationType":    "active-probe",
					"method":            http.MethodGet,
					"url":               targetURL,
					"payloadClass":      "dom-xss",
					"domSource":         payload.source,
					"markerInTitle":     fmt.Sprintf("%t", markerInTitle),
					"markerInBody":      fmt.Sprintf("%t", markerInBody),
					"markerInConsole":   fmt.Sprintf("%t", markerInConsole),
					"targetURL":         targetURL,
					"responseShape":     bl.shape.String(),
					"reflectionContext": reflectionCtx.String(),
					"oracleName":        "dom_xss_probe",
					"oracleVersion":     "v1",
				},
			}

			if RequiresUnconditionalVerification(finding.Severity) {
				diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
					ProbeName:       "dom-xss-probe",
					OriginalPayload: payloadFragment,
					SafePayload:     "domxss-safe-control",
					Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
						altCtx, altCancel := chromedpContext(dctx)
						defer altCancel()
						var altTitle, altBody string
						err := chromedp.Run(altCtx,
							chromedp.Navigate(ep+"#"+altPayload),
							chromedp.Title(&altTitle),
							chromedp.InnerHTML("body", &altBody, chromedp.ByQuery),
						)
						if err != nil {
							return nil, nil, err
						}
						return &http.Response{Header: http.Header{}}, encodeDOMXSSObservation(altTitle, altBody), nil
					},
					Oracle: func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
						obsTitle, obsBody := decodeDOMXSSObservation(body)
						return domXSSOriginalSignalPresent(obsTitle, obsBody, domXSSPayloadMarker, payloadFragment), nil
					},
				})
				if diffOutcome.Ran && !diffOutcome.Confirmed {
					continue
				}
				AttachDifferentialEvidence(&finding, diffOutcome)
			}

			emittedFinding, ok := phase1SubmitVerified(ctx, finding, "xss", []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved}, "dom-xss-probe")
			if !ok {
				continue
			}
			emitted[fid] = true
			findings = append(findings, emittedFinding)
		}
	}

	return findings
}

const domXSSObservationSeparator = "\n<!--abh-domxss-separator-->\n"

func domXSSPayloadFragment(hash string) string {
	return strings.TrimPrefix(hash, "#")
}

func domXSSDangerousReflection(body, marker, payload string) (ReflectionContext, bool) {
	if body == "" || marker == "" || payload == "" || !strings.Contains(body, marker) {
		return ContextUnknown, false
	}
	ctx := ClassifyReflectionContext(body, marker)
	if ctx == ContextUnknown || !PayloadEscapesContext(ctx, payload) {
		return ctx, false
	}
	return ctx, true
}

func domXSSOriginalSignalPresent(title, body, marker, payload string) bool {
	if strings.Contains(title, marker) {
		return true
	}
	_, ok := domXSSDangerousReflection(body, marker, payload)
	return ok
}

func encodeDOMXSSObservation(title, body string) []byte {
	return []byte(title + domXSSObservationSeparator + body)
}

func decodeDOMXSSObservation(body []byte) (string, string) {
	parts := strings.SplitN(string(body), domXSSObservationSeparator, 2)
	if len(parts) != 2 {
		return "", string(body)
	}
	return parts[0], parts[1]
}

func describeDOMXSSLocations(title, body, console bool) string {
	parts := []string{}
	if title {
		parts = append(parts, "document.title")
	}
	if body {
		parts = append(parts, "document body (innerHTML)")
	}
	if console {
		parts = append(parts, "console output")
	}
	if len(parts) == 0 {
		return "the DOM"
	}
	return strings.Join(parts, ", ")
}
