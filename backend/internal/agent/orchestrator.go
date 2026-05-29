package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

const (
	novelFindingsNormalizationFactor = 3.0
	timeToSignalPenaltyThresholdMs   = 120000.0
	timeToSignalPenaltyWeight        = 0.25
	defaultCostWeight                = 0.25
	highSignalCostWeightCap          = 0.08
)

// Orchestrator drives a plan→build→run loop using a Planner to decide which
// agents to schedule next and a Factory to instantiate them on demand.
//
// It replaces the static Registry.RunAll execution model so the system can
// dynamically spawn agents in response to discoveries (e.g. running a second
// scanning pass after recon reveals a new attack surface).
type Orchestrator struct {
	Planner                     Planner
	Factory                     *Factory
	MaxRounds                   int
	MaxNoNoveltyRounds          int
	MaxConsecutiveFailureRounds int
	MinMarginalScore            float64
	MaxRoundCostUnits           int
	CostWeight                  float64
}

// NewOrchestrator constructs an Orchestrator. maxRounds bounds the number of
// planning iterations; zero or negative values default to 10. Each round may
// schedule several agents, so the actual number of agents executed can exceed
// maxRounds.
func NewOrchestrator(planner Planner, factory *Factory, maxRounds int) *Orchestrator {
	if maxRounds <= 0 {
		maxRounds = 10
	}
	return &Orchestrator{
		Planner:                     planner,
		Factory:                     factory,
		MaxRounds:                   maxRounds,
		MaxNoNoveltyRounds:          2,
		MaxConsecutiveFailureRounds: 2,
		MinMarginalScore:            0,
		MaxRoundCostUnits:           0,
		CostWeight:                  defaultCostWeight,
	}
}

// Run executes the autonomous loop and returns the per-agent outputs together
// with the deduplicated set of findings collected across the run.
func (o *Orchestrator) Run(ctx context.Context, input AgentInput) ([]AgentOutput, []model.Finding, error) {
	if o == nil || o.Planner == nil || o.Factory == nil {
		return nil, nil, fmt.Errorf("orchestrator not configured")
	}

	outputs := make([]AgentOutput, 0)
	allFindings := make([]model.Finding, 0)
	noNoveltyRounds := 0
	consecutiveFailureRounds := 0
	lowMarginalScoreRounds := 0
	forcePending := make(map[string]bool, len(input.Options.AutonomyForceRunAgents))
	for _, name := range input.Options.AutonomyForceRunAgents {
		name = strings.TrimSpace(name)
		if name != "" {
			forcePending[name] = true
		}
	}
	suppressed := make(map[string]bool, len(input.Options.AutonomySuppressAgents))
	for _, name := range input.Options.AutonomySuppressAgents {
		name = strings.TrimSpace(name)
		if name != "" {
			suppressed[name] = true
		}
	}

	for round := 0; round < o.MaxRounds; round++ {
		select {
		case <-ctx.Done():
			return outputs, combineFindingsWithDedup(allFindings), ctx.Err()
		default:
		}

		input.History = outputs
		input.AllFindings = combineFindingsWithDedup(allFindings)
		if len(outputs) > 0 {
			input.Previous = outputs[len(outputs)-1]
		} else {
			input.Previous = AgentOutput{}
		}

		decision, err, planTimedOut := runPlannerWithContext(ctx, o.Planner, input, outputs)
		if planTimedOut {
			// The scan context was cancelled (e.g. SCAN_TIMEOUT_SECONDS
			// elapsed) while the planner was still deciding the next batch of
			// agents. Without this guard a planner that blocks on a slow or
			// unresponsive dependency would stall the whole scan between
			// steps — the previous agent (e.g. analysis) completes but no
			// further agent is ever scheduled. Stop the loop instead of
			// blocking indefinitely.
			log.Printf("orchestrator: round %d planning cancelled (scan context ended): %v", round+1, ctx.Err())
			return outputs, combineFindingsWithDedup(allFindings), ctx.Err()
		}
		if err != nil {
			log.Printf("orchestrator: round %d planning failed: %v", round+1, err)
			return outputs, combineFindingsWithDedup(allFindings), err
		}
		if decision.IsDone || len(decision.Agents) == 0 {
			if len(forcePending) > 0 {
				extras := make([]AgentSpec, 0, len(forcePending))
				for name := range forcePending {
					if suppressed[name] {
						delete(forcePending, name)
						continue
					}
					extras = append(extras, AgentSpec{Name: name, Reason: "operator-force-run"})
					delete(forcePending, name)
				}
				if len(extras) > 0 {
					decision.Agents = extras
					decision.IsDone = false
				}
			}
		}
		if decision.IsDone || len(decision.Agents) == 0 {
			log.Printf("orchestrator: planner signalled completion after %d round(s); %d agent run(s) total", round, len(outputs))
			return outputs, combineFindingsWithDedup(allFindings), nil
		}
		filtered := make([]AgentSpec, 0, len(decision.Agents))
		for _, spec := range decision.Agents {
			name := strings.TrimSpace(spec.Name)
			if name == "" || suppressed[name] {
				continue
			}
			filtered = append(filtered, spec)
		}
		if len(filtered) == 0 {
			continue
		}
		decision.Agents = filtered
		scheduled := make([]string, 0, len(decision.Agents))
		for _, spec := range decision.Agents {
			scheduled = append(scheduled, spec.Name)
		}
		log.Printf("orchestrator: round %d/%d scheduling %d agent(s): %s", round+1, o.MaxRounds, len(scheduled), strings.Join(scheduled, ", "))
		beforeCount := len(combineFindingsWithDedup(allFindings))
		roundFailures := 0
		roundScoreSum := 0.0
		roundScoredActions := 0
		timeToSignalMs := int64(-1)
		roundDurationMs := int64(0)
		roundCostUnits := 0
		roundHighSignal := 0

		for _, spec := range decision.Agents {
			select {
			case <-ctx.Done():
				return outputs, combineFindingsWithDedup(allFindings), ctx.Err()
			default:
			}

			agent, err := o.Factory.Create(spec.Name)
			if err != nil {
				outputs = append(outputs, AgentOutput{
					AgentName:   spec.Name,
					Status:      "error",
					Error:       err.Error(),
					DebugNotes:  err.Error(),
					Metadata:    map[string]string{"orchestration_reason": spec.Reason},
					StartedAt:   time.Now().UTC(),
					CompletedAt: time.Now().UTC(),
				})
				continue
			}
			if !agent.Enabled() {
				continue
			}
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventAgentStart,
				AgentName: agent.Name(),
				Message:   fmt.Sprintf("Agent %q started", agent.Name()),
			})
			log.Printf("orchestrator: agent %q started", agent.Name())

			input.AllFindings = combineFindingsWithDedup(allFindings)
			if len(outputs) > 0 {
				input.Previous = outputs[len(outputs)-1]
			} else {
				input.Previous = AgentOutput{}
			}

			startedAt := time.Now().UTC()
			output, runErr, timedOut := runAgentWithContext(ctx, agent, input)
			completedAt := time.Now().UTC()

			if timedOut {
				// The scan context was cancelled (e.g. SCAN_TIMEOUT_SECONDS
				// elapsed) while this agent was still running. Record the
				// partial/empty result as a timeout and stop the loop instead
				// of blocking on the agent indefinitely.
				if output.AgentName == "" {
					output.AgentName = agent.Name()
				}
				output.Status = "error"
				output.TimedOut = true
				if runErr != nil {
					output.Error = runErr.Error()
					output.DebugNotes = runErr.Error()
				} else {
					output.Error = ctx.Err().Error()
					output.DebugNotes = fmt.Sprintf("agent %q cancelled: %s", agent.Name(), ctx.Err())
				}
				output.StartedAt = startedAt
				output.CompletedAt = completedAt
				output.DurationMs = completedAt.Sub(startedAt).Milliseconds()
				log.Printf("orchestrator: agent %q timed out after %dms (scan context cancelled): %s", agent.Name(), output.DurationMs, output.Error)
				outputs = append(outputs, output)
				return outputs, combineFindingsWithDedup(allFindings), ctx.Err()
			}

			if runErr != nil {
				output.Status = "error"
				output.DebugNotes = runErr.Error()
				output.Error = runErr.Error()
				output.TimedOut = strings.Contains(strings.ToLower(runErr.Error()), "deadline exceeded")
			}
			if output.Status == "error" || output.TimedOut {
				roundFailures++
			}
			if output.AgentName == "" {
				output.AgentName = agent.Name()
			}
			if output.Status == "" {
				output.Status = "completed"
			}
			output.StartedAt = startedAt
			output.CompletedAt = completedAt
			output.DurationMs = completedAt.Sub(startedAt).Milliseconds()
			if output.Metadata == nil {
				output.Metadata = map[string]string{}
			}
			if reason := strings.TrimSpace(spec.Reason); reason != "" {
				output.Metadata["orchestration_reason"] = reason
			}
			output.Metadata["findings"] = fmt.Sprintf("%d", len(output.Findings))
			costUnits := computeActionCostUnits(output)
			output.Metadata["cost_units"] = fmt.Sprintf("%d", costUnits)
			qualityScore := computeActionQuality(output)
			output.Metadata["decision_quality_score"] = formatScore(qualityScore)
			roundScoreSum += qualityScore
			roundScoredActions++
			roundDurationMs += output.DurationMs
			roundCostUnits += costUnits
			if timeToSignalMs < 0 && len(output.Findings) > 0 {
				timeToSignalMs = roundDurationMs
			}
			roundHighSignal += countHighSignalFindings(output.Findings)
			output.Telemetry = model.AgentRunTelemetry{
				AgentName:   output.AgentName,
				Status:      output.Status,
				StartedAt:   output.StartedAt,
				CompletedAt: output.CompletedAt,
				DurationMs:  output.DurationMs,
				TimedOut:    output.TimedOut,
				Error:       output.Error,
				Metadata:    output.Metadata,
			}
			for _, f := range output.Findings {
				Emit(input.Emit, model.ScanEvent{
					Type:         model.ScanEventFinding,
					AgentName:    output.AgentName,
					FindingTitle: f.Title,
					Severity:     string(f.Severity),
					Message:      fmt.Sprintf("[%s] %s", f.Severity, f.Title),
				})
			}
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventAgentComplete,
				AgentName: output.AgentName,
				Message:   fmt.Sprintf("Agent %q completed in %dms with %d finding(s)", output.AgentName, output.DurationMs, len(output.Findings)),
				Metadata:  output.Metadata,
			})
			if output.Status == "error" || output.TimedOut {
				log.Printf("orchestrator: agent %q finished with status %q in %dms (%d finding(s)): %s", output.AgentName, output.Status, output.DurationMs, len(output.Findings), output.Error)
			} else {
				log.Printf("orchestrator: agent %q completed in %dms with %d finding(s)", output.AgentName, output.DurationMs, len(output.Findings))
			}
			outputs = append(outputs, output)
			allFindings = append(allFindings, output.Findings...)
			delete(forcePending, output.AgentName)
		}

		afterCount := len(combineFindingsWithDedup(allFindings))
		novelFindings := maxInt(0, afterCount-beforeCount)
		roundScore := 0.0
		if roundScoredActions > 0 {
			roundScore = roundScoreSum / float64(roundScoredActions)
		}
		roundScore += clamp01(float64(novelFindings) / novelFindingsNormalizationFactor)
		if timeToSignalMs < 0 {
			timeToSignalMs = roundDurationMs
		}
		if timeToSignalMs > 0 {
			ttsWeight := timeToSignalPenaltyWeight
			// When high-signal findings are present the agent was clearly
			// productive despite being slow — cap the time-to-signal penalty
			// at half its normal weight so a critical finding is never
			// penalised more than a lightweight empty round.
			if roundHighSignal > 0 {
				ttsWeight *= 0.5
			}
			roundScore -= clamp01(float64(timeToSignalMs)/timeToSignalPenaltyThresholdMs) * ttsWeight
		}
		if o.MaxRoundCostUnits > 0 && roundCostUnits > o.MaxRoundCostUnits {
			excess := float64(roundCostUnits-o.MaxRoundCostUnits) / float64(o.MaxRoundCostUnits)
			weight := o.CostWeight
			if weight <= 0 {
				weight = defaultCostWeight
			}
			// Guardrail: when high-signal findings are present, apply only a small
			// cost penalty so risk/safety signal cannot be silently down-prioritized.
			if roundHighSignal > 0 {
				if weight > highSignalCostWeightCap {
					weight = highSignalCostWeightCap
				}
			}
			roundScore -= clamp01(excess) * weight
		}
		roundScore = clamp01(roundScore)
		if afterCount <= beforeCount {
			noNoveltyRounds++
		} else {
			noNoveltyRounds = 0
		}
		if roundFailures == len(decision.Agents) {
			consecutiveFailureRounds++
		} else {
			consecutiveFailureRounds = 0
		}
		if o.MaxNoNoveltyRounds > 0 && noNoveltyRounds >= o.MaxNoNoveltyRounds {
			log.Printf("orchestrator: stopping after %d round(s) — %d consecutive round(s) produced no novel findings", round+1, noNoveltyRounds)
			return outputs, combineFindingsWithDedup(allFindings), nil
		}
		if o.MaxConsecutiveFailureRounds > 0 && consecutiveFailureRounds >= o.MaxConsecutiveFailureRounds {
			log.Printf("orchestrator: stopping after %d round(s) — %d consecutive round(s) of agent failures", round+1, consecutiveFailureRounds)
			return outputs, combineFindingsWithDedup(allFindings), nil
		}
		if o.MinMarginalScore > 0 && roundScore < o.MinMarginalScore {
			lowMarginalScoreRounds++
		} else {
			lowMarginalScoreRounds = 0
		}
		if o.MinMarginalScore > 0 && lowMarginalScoreRounds >= 2 {
			log.Printf("orchestrator: stopping after %d round(s) — marginal score below %.2f for %d consecutive round(s)", round+1, o.MinMarginalScore, lowMarginalScoreRounds)
			return outputs, combineFindingsWithDedup(allFindings), nil
		}
	}

	log.Printf("orchestrator: reached max rounds (%d); pipeline complete with %d agent run(s)", o.MaxRounds, len(outputs))
	return outputs, combineFindingsWithDedup(allFindings), nil
}

// runPlannerWithContext runs Planner.Plan in a watchdog goroutine so the
// orchestrator honours ctx cancellation (e.g. the scan-wide timeout) even when
// a planner blocks on a slow/unresponsive dependency (AI provider, knowledge
// retrieval, learner RPC) and does not observe ctx itself. It returns the
// planner decision, any planning error, and a timedOut flag that is true when
// ctx fired before the planner returned.
//
// This mirrors runAgentWithContext: agents were already protected against
// hanging the scan, but the planning step that runs *between* agents was not.
// A blocking planner therefore manifested as "the previous step completed but
// no next step ever starts" — the exact symptom this guard prevents.
//
// When timedOut is true the watchdog goroutine is intentionally left to finish
// in the background; its result is discarded. This is safe because the scan
// context is already cancelled, so well-behaved downstream work unwinds and the
// orchestrator stops scheduling further agents.
func runPlannerWithContext(ctx context.Context, planner Planner, input AgentInput, history []AgentOutput) (PlannerDecision, error, bool) {
	type planResult struct {
		decision PlannerDecision
		err      error
	}
	done := make(chan planResult, 1)
	go func() {
		decision, err := planner.Plan(ctx, input, history)
		done <- planResult{decision: decision, err: err}
	}()

	select {
	case <-ctx.Done():
		// Give the planner a brief grace period to return its own
		// context-cancelled result before abandoning it.
		select {
		case res := <-done:
			return res.decision, res.err, true
		case <-time.After(agentCancelGracePeriod):
			return PlannerDecision{}, ctx.Err(), true
		}
	case res := <-done:
		return res.decision, res.err, false
	}
}

// runAgentWithContext runs agent.Run in a watchdog goroutine so the
// orchestrator honours ctx cancellation (e.g. the scan-wide timeout) even when
// an individual agent blocks on a slow external/AI call and does not observe
// ctx itself. It returns the agent output, any run error, and a timedOut flag
// that is true when ctx fired before the agent returned.
//
// When timedOut is true the watchdog goroutine is intentionally left to finish
// in the background; its result is discarded. This is safe because the scan
// context is already cancelled, so well-behaved downstream work unwinds, and
// the orchestrator stops scheduling further agents.
func runAgentWithContext(ctx context.Context, agent Agent, input AgentInput) (AgentOutput, error, bool) {
	type agentResult struct {
		output AgentOutput
		err    error
	}
	done := make(chan agentResult, 1)
	go func() {
		out, err := agent.Run(ctx, input)
		done <- agentResult{output: out, err: err}
	}()

	select {
	case <-ctx.Done():
		// Give the agent a brief grace period to return its own
		// context-cancelled result so we can preserve any partial output.
		select {
		case res := <-done:
			return res.output, res.err, true
		case <-time.After(agentCancelGracePeriod):
			return AgentOutput{AgentName: agent.Name()}, ctx.Err(), true
		}
	case res := <-done:
		return res.output, res.err, false
	}
}

// agentCancelGracePeriod bounds how long the orchestrator waits for a cancelled
// agent to return its own result before abandoning it and unwinding the scan.
const agentCancelGracePeriod = 2 * time.Second

func computeActionQuality(output AgentOutput) float64 {
	score := 0.0
	findings := len(output.Findings)
	if findings > 0 {
		score += clamp01(float64(findings) / 3.0)
	}
	highSignal := 0
	lowSignal := 0
	for _, f := range output.Findings {
		if f.Severity == model.SeverityCritical {
			// Critical findings carry more weight than High.
			highSignal += 2
		} else if f.Severity == model.SeverityHigh || f.Confidence >= 0.85 {
			highSignal++
		}
		if f.Confidence > 0 && f.Confidence < 0.4 {
			lowSignal++
		}
	}
	score += clamp01(float64(highSignal)/3.0) * 0.35
	if findings > 0 {
		score -= (float64(lowSignal) / float64(findings)) * 0.3
	}
	if output.Status == "error" || output.TimedOut || strings.TrimSpace(output.Error) != "" {
		score -= 0.6
	}
	if output.DurationMs > 0 {
		score -= clamp01(float64(output.DurationMs)/90000.0) * 0.2
	}
	return clamp01(score)
}

func computeActionCostUnits(output AgentOutput) int {
	cost := 1
	if output.DurationMs > 0 {
		cost += int(output.DurationMs / 10000)
	}
	if output.TimedOut || output.Status == "error" || strings.TrimSpace(output.Error) != "" {
		cost += 2
	}
	return maxInt(1, cost)
}

func countHighSignalFindings(findings []model.Finding) int {
	count := 0
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			// Critical counts double — it outweighs a single High finding.
			count += 2
		} else if f.Severity == model.SeverityHigh || f.Confidence >= 0.85 {
			count++
		}
	}
	return count
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func formatScore(v float64) string {
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	return fmt.Sprintf("%.3f", v)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
