package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// redosMaxAttempts caps the probe budget.
const redosMaxAttempts = 10

// redosTimeThreshold is the minimum absolute response latency (on top of
// clearing the baseline-variance check) required before a ReDoS candidate is
// considered. Chosen to comfortably exceed normal request jitter while still
// catching catastrophic-backtracking regexes, which typically blow up to
// multiple seconds even on short evil strings.
const redosTimeThreshold = 4 * time.Second

// redosPayloads are classic catastrophic-backtracking triggers
// (HackTricks "Regular expression Denial of Service (ReDoS)") built around
// common nested-quantifier vulnerable patterns seen in email/URL/whitespace
// validators (`^([a-zA-Z0-9])(([\.\-]|_+)?([a-zA-Z0-9]+))*@...`,
// `^(a+)+$`, `^(\s*)*$`). Each payload targets a different quantifier
// nesting family so the probe isn't blind to one specific validator style.
var redosPayloads = []struct {
	label string
	value string
}{
	{label: "nested-quantifier-a-bang", value: strings.Repeat("a", 40) + "!"},
	{label: "nested-quantifier-dot-at", value: strings.Repeat("a.", 30) + "!@x"},
	{label: "whitespace-quantifier", value: strings.Repeat(" ", 60) + "\t!"},
	{label: "alternation-blowup", value: strings.Repeat("a", 5) + strings.Repeat("aa", 20) + "!"},
}

// runReDoSProbe is an active probe for the HackTricks "Regular Expression
// Denial of Service (ReDoS)" technique. It submits known catastrophic-
// backtracking trigger strings into common reflective/validated parameter
// names and flags the endpoint when the response latency spikes well beyond
// two control baselines (empty parameter, and a benign value of comparable
// length) — the same differential-timing approach already used for blind
// time-based command injection (see command_injection_probe.go).
func (s *Service) runReDoSProbe(ctx context.Context, input RunInput, body string) []model.Finding {
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
			Command: fmt.Sprintf("redos-probe %s", input.Target),
			Message: "Probing for ReDoS via catastrophic-backtracking regex triggers",
		})
	}

	params := techAwareXSSProbeParams(input.DetectedTech)
	attempts := 0

	for _, ep := range candidates {
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}
		for _, param := range params {
			if attempts >= redosMaxAttempts {
				return nil
			}

			baselineControls, err := s.phase1QueryBaselines(ctx, ep, param, "abh_redos_baseline", true, input, 32*1024)
			if err != nil {
				continue
			}

			for _, payload := range redosPayloads {
				attempts++
				if attempts > redosMaxAttempts {
					return nil
				}

				start := time.Now()
				testURL := mustPhase1QueryURL(ep, param, payload.value)
				_, sampleErr := s.phase1GETSample(ctx, testURL, input, 32*1024)
				elapsed := time.Since(start)
				if sampleErr != nil {
					continue
				}

				if elapsed < redosTimeThreshold || !phase1TimingExceeds(elapsed, baselineControls.First.Duration, baselineControls.Second.Duration) {
					continue
				}

				diffOutcome := phase1DifferentialQuery(ctx, s, input, "redos-probe", ep, param, payload.value, "abh_redos_safe_control", 32*1024,
					func(dctx context.Context, alt string, _ *http.Response, _ []byte) (bool, error) {
						dstart := time.Now()
						_, err := s.phase1GETSample(dctx, mustPhase1QueryURL(ep, param, alt), input, 32*1024)
						return time.Since(dstart) >= redosTimeThreshold, err
					})
				if diffOutcome.Ran && !diffOutcome.Confirmed {
					continue
				}

				curl := buildCurlReproducer(http.MethodGet, testURL, input.AuthProfile, "", "")
				finding := model.Finding{
					ID:       "redos-" + payload.label + "-" + hhSlug(ep),
					Category: "denial-of-service",
					Severity: model.SeverityMedium,
					Title:    fmt.Sprintf("Possible Regular Expression Denial of Service (ReDoS) via parameter %q", param),
					Description: fmt.Sprintf(
						"The endpoint %s showed a large response-time increase (%dms vs baseline %dms/%dms) when the "+
							"%q parameter received a catastrophic-backtracking regex trigger (%s technique). This "+
							"pattern is consistent with a server-side validation regex (e.g. email, URL, or whitespace "+
							"pattern) that exhibits exponential backtracking on crafted input, allowing a single "+
							"request to consume disproportionate CPU and degrade availability for other users.",
						ep, elapsed.Milliseconds(), baselineControls.First.Duration.Milliseconds(), baselineControls.Second.Duration.Milliseconds(),
						param, payload.label,
					),
					Evidence: fmt.Sprintf(
						"GET %s → elapsed %dms (baselines: %dms, %dms; threshold: %dms)",
						testURL, elapsed.Milliseconds(), baselineControls.First.Duration.Milliseconds(), baselineControls.Second.Duration.Milliseconds(), redosTimeThreshold.Milliseconds(),
					),
					Recommendation: "Audit validation regexes for nested/overlapping quantifiers (e.g. `(a+)+`, `([a-zA-Z]+)*`) " +
						"that permit exponential backtracking. Replace them with linear-time equivalents, use a " +
						"regex engine with backtracking limits (RE2, or .NET's `Regex.MatchTimeout`), or enforce an " +
						"input-length cap and a per-request CPU/time budget before the regex is evaluated.",
					Confidence:        0.6,
					AffectedURL:       ep,
					AffectedParameter: param,
					CWE:               "CWE-1333",
					OWASPCategory:     "A05:2021 - Security Misconfiguration",
					Sources:           []string{"active-scanner", "redos-probe"},
					PoC:               curl,
					ReproductionSteps: []string{
						fmt.Sprintf("Send GET %s and time the response.", testURL),
						fmt.Sprintf("Compare against the same request with %q set to a short benign value — expect a sub-second baseline vs a multi-second response for the crafted payload.", param),
					},
					BusinessTags: []string{"redos", "denial-of-service", "regex"},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"technique":      payload.label,
						"parameter":      param,
						"elapsedMs":      fmt.Sprintf("%d", elapsed.Milliseconds()),
						"baselineMs":     phase1FormatBaselineMs(baselineControls),
						"curlReproducer": curl,
					},
				}
				AttachDifferentialEvidence(&finding, diffOutcome)
				emitted, ok := phase1SubmitVerified(ctx, finding, "redos", []EvidenceSignal{EvidenceTimingDelta}, "redos-probe")
				if !ok {
					continue
				}
				return []model.Finding{emitted}
			}
		}
	}

	return nil
}
