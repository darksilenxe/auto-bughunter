package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

const (
	// defaultAdaptiveStepBudget is the maximum number of AI-decided probes the
	// agent will execute. Each step costs one AI call and one HTTP request.
	// The AI can stop earlier if it determines the surface is adequately covered.
	defaultAdaptiveStepBudget = 20
)

// AdaptiveProbeAgent implements a true observe → reason → act loop for web
// application penetration testing. Unlike PentestLoopAgent (which generates a
// batch of hypotheses and runs them all) and ReasoningIterationAgent (which
// reflects after each batch), AdaptiveProbeAgent executes ONE probe at a time:
//
//  1. The AI sees the FULL history of probe results — including plain-English
//     HTTP observations (WAF blocks, near-misses, server errors, no-signal) —
//     and all currently confirmed findings.
//  2. The AI chooses the single most valuable next probe based on the actual
//     evidence, NOT a predefined playbook.
//  3. The probe is executed via ProbeHypothesis(), which captures the full
//     HTTP-level observation even for unconfirmed probes.
//  4. The result is added to the history and the loop repeats from step 1.
//  5. The AI can say "stop" at any point — when it has enough confirmed
//     findings, when the surface appears exhausted, or when the step budget
//     runs out.
//
// This is the adaptive, non-playbook-driven intelligence layer the application
// is designed around. The AI models already attached to the application make
// every probe decision; the agent is just the execution harness.
type AdaptiveProbeAgent struct {
	aiClient    *ai.Client
	scanService *scanner.Service
	StepBudget  int
	enabled     bool
}

// NewAdaptiveProbeAgent constructs an AdaptiveProbeAgent.
// stepBudget ≤ 0 defaults to defaultAdaptiveStepBudget.
func NewAdaptiveProbeAgent(aiClient *ai.Client, scanService *scanner.Service, stepBudget int, enabled bool) *AdaptiveProbeAgent {
	if stepBudget <= 0 {
		stepBudget = defaultAdaptiveStepBudget
	}
	return &AdaptiveProbeAgent{
		aiClient:    aiClient,
		scanService: scanService,
		StepBudget:  stepBudget,
		enabled:     enabled,
	}
}

func (a *AdaptiveProbeAgent) Name() string  { return "adaptive_probe" }
func (a *AdaptiveProbeAgent) Enabled() bool { return a.enabled }

// Run executes the adaptive probe loop. It returns all confirmed findings
// discovered across all AI-directed probe steps.
func (a *AdaptiveProbeAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if a.aiClient == nil || a.scanService == nil {
		output.DebugNotes = "AdaptiveProbeAgent: skipped — aiClient or scanService not configured"
		return output, nil
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   fmt.Sprintf("Adaptive probe agent starting — AI-directed, evidence-driven probe loop (budget: %d steps)", a.StepBudget),
	})

	// Seed endpoints from target + any runtime-discovered URLs.
	endpoints := append([]string{input.Target}, input.Options.SeedRuntimeEndpoints...)

	// probeHistory is the full observation record passed to the AI each step.
	probeHistory := make([]model.ProbeResult, 0, a.StepBudget)

	// allFindings accumulates confirmed findings from this agent and prior agents.
	allFindings := append([]model.Finding(nil), input.AllFindings...)

	stepsExecuted := 0
	stepsConfirmed := 0
	stepsWAFBlocked := 0
	stepsNearMiss := 0
	stopReason := ""

	for step := 1; step <= a.StepBudget; step++ {
		select {
		case <-ctx.Done():
			output.Status = "partial"
			output.DebugNotes = "AdaptiveProbeAgent: cancelled by context"
			a.writeMetadata(&output, stepsExecuted, stepsConfirmed, stepsWAFBlocked, stepsNearMiss)
			return output, ctx.Err()
		default:
		}

		budgetLeft := a.StepBudget - step + 1

		// ── AI decides what to probe next ─────────────────────────────────
		decision := a.aiClient.DecideNextProbe(
			ctx,
			input.Target,
			allFindings,
			probeHistory,
			endpoints,
			budgetLeft,
		)

		if decision.Action == "stop" {
			stopReason = decision.StopReason
			if stopReason == "" {
				stopReason = "AI determined no further probing is warranted"
			}
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventReasoningLoop,
				AgentName: a.Name(),
				Message:   fmt.Sprintf("[adaptive] AI stopped after %d step(s): %s", stepsExecuted, stopReason),
				Metadata: map[string]string{
					"step":        itoa(step),
					"status":      "ai_stopped",
					"stopReason":  stopReason,
					"stepsRun":    itoa(stepsExecuted),
					"confirmed":   itoa(stepsConfirmed),
					"wafBlocked":  itoa(stepsWAFBlocked),
					"nearMiss":    itoa(stepsNearMiss),
					"budgetLeft":  itoa(budgetLeft),
				},
			})
			break
		}

		if decision.Action != "probe" || decision.Category == "" || decision.Endpoint == "" {
			// Invalid decision — treat as stop to avoid infinite loop.
			stopReason = "AI returned an invalid probe decision; stopping early"
			break
		}

		// ── Emit the AI's reasoning before executing the probe ────────────
		// This is what the operator sees in real time: WHY the AI chose this.
		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventReasoningLoop,
			AgentName: a.Name(),
			Message: fmt.Sprintf(
				"[adaptive step %d] %s → %s %s — %s",
				step, strings.ToUpper(decision.Category), decision.Endpoint,
				formatParam(decision.ParamName, decision.Payload),
				decision.Rationale,
			),
			Metadata: map[string]string{
				"step":       itoa(step),
				"status":     "ai_decision",
				"category":   decision.Category,
				"endpoint":   decision.Endpoint,
				"paramName":  decision.ParamName,
				"payload":    decision.Payload,
				"rationale":  decision.Rationale,
				"budgetLeft": itoa(budgetLeft),
			},
		})

		// ── Execute the probe ─────────────────────────────────────────────
		pr := a.scanService.ProbeHypothesis(
			ctx,
			decision.Category,
			decision.Endpoint,
			decision.ParamName,
			decision.Payload,
			input.AuthProfile,
			input.Options,
		)
		stepsExecuted++

		// Track outcome counters for metadata.
		switch pr.Outcome {
		case model.ProbeWAFBlocked:
			stepsWAFBlocked++
		case model.ProbeNearMiss:
			stepsNearMiss++
		case model.ProbeConfirmed:
			stepsConfirmed++
		}

		// ── Emit the probe result ─────────────────────────────────────────
		outcomeLabel := outcomeEmoji(pr.Outcome)
		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventReasoningLoop,
			AgentName: a.Name(),
			Message: fmt.Sprintf(
				"[adaptive step %d result] %s %s — %s",
				step, outcomeLabel, string(pr.Outcome), pr.Observation,
			),
			Metadata: map[string]string{
				"step":        itoa(step),
				"status":      "probe_result",
				"outcome":     string(pr.Outcome),
				"statusCode":  itoa(pr.StatusCode),
				"observation": pr.Observation,
				"category":    pr.Category,
				"endpoint":    pr.Endpoint,
				"confirmed":   boolStr(pr.Confirmed),
			},
		})

		// Promote confirmed finding URL as a new endpoint candidate.
		if pr.Confirmed && pr.Finding != nil {
			if u := strings.TrimSpace(pr.Finding.AffectedURL); u != "" {
				endpoints = appendUnique(endpoints, u)
			}

			// Tag finding with step provenance.
			pr.Finding.ID = fmt.Sprintf("adaptive-step%d-%s", step, strings.ToLower(pr.Category))
			pr.Finding.Sources = appendUnique(pr.Finding.Sources, a.Name())
			if pr.Finding.EvidenceFields == nil {
				pr.Finding.EvidenceFields = map[string]string{}
			}
			pr.Finding.EvidenceFields["adaptiveStep"] = itoa(step)
			pr.Finding.EvidenceFields["aiRationale"] = decision.Rationale

			output.Findings = append(output.Findings, *pr.Finding)
			allFindings = append(allFindings, *pr.Finding)

			Emit(input.Emit, model.ScanEvent{
				Type:         model.ScanEventFinding,
				AgentName:    a.Name(),
				FindingTitle: pr.Finding.Title,
				Severity:     string(pr.Finding.Severity),
				Message:      fmt.Sprintf("[adaptive step %d] ✓ %s — %s", step, pr.Finding.Title, decision.Rationale),
			})
		}

		// Add the full probe result to history for the next AI decision call.
		probeHistory = append(probeHistory, pr)

		humanPacedSleep(ctx, input.Options)
	}

	// ── Exploit chain pass over all confirmed findings ────────────────────
	if len(output.Findings) > 0 {
		chainFindings := scanner.RunExploitChain(allFindings, nil)
		for i := range chainFindings {
			chainFindings[i].ID = fmt.Sprintf("adaptive-chain-%d", i+1)
			chainFindings[i].Sources = appendUnique(chainFindings[i].Sources, a.Name())
		}
		output.Findings = append(output.Findings, chainFindings...)
	}

	a.writeMetadata(&output, stepsExecuted, stepsConfirmed, stepsWAFBlocked, stepsNearMiss)
	output.DebugNotes = fmt.Sprintf(
		"AdaptiveProbeAgent: %d step(s) executed, %d confirmed, %d WAF-blocked, %d near-miss. Stop: %s",
		stepsExecuted, stepsConfirmed, stepsWAFBlocked, stepsNearMiss, stopReason,
	)
	return output, nil
}

func (a *AdaptiveProbeAgent) writeMetadata(out *AgentOutput, steps, confirmed, wafBlocked, nearMiss int) {
	out.Metadata["adaptive_steps"] = itoa(steps)
	out.Metadata["adaptive_confirmed"] = itoa(confirmed)
	out.Metadata["adaptive_waf_blocked"] = itoa(wafBlocked)
	out.Metadata["adaptive_near_miss"] = itoa(nearMiss)
	out.Metadata["adaptive_budget"] = itoa(a.StepBudget)
}

// outcomeEmoji returns a short visual indicator for each probe outcome.
func outcomeEmoji(o model.ProbeOutcome) string {
	switch o {
	case model.ProbeConfirmed:
		return "✓"
	case model.ProbeWAFBlocked:
		return "⛔"
	case model.ProbeNearMiss:
		return "◑"
	case model.ProbeServerError:
		return "⚠"
	case model.ProbeNoSignal:
		return "○"
	default:
		return "?"
	}
}

// formatParam returns a short display string for a parameter+payload pair.
func formatParam(param, payload string) string {
	if param == "" {
		return ""
	}
	p := payload
	if len(p) > 30 {
		p = p[:30] + "…"
	}
	return "[" + param + "=" + p + "]"
}
