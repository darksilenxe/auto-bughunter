package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"auto-bughunter/backend/internal/metrics"
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

		decision, err := o.Planner.Plan(ctx, input, outputs)
		if err != nil {
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
				outputs = append(outputs, AgentOutput{
					AgentName:   agent.Name(),
					Status:      "skipped",
					DebugNotes:  "agent disabled",
					Metadata:    map[string]string{"orchestration_reason": spec.Reason},
					StartedAt:   time.Now().UTC(),
					CompletedAt: time.Now().UTC(),
				})
				continue
			}
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventAgentStart,
				AgentName: agent.Name(),
				Message:   fmt.Sprintf("Agent %q started", agent.Name()),
			})

			input.AllFindings = combineFindingsWithDedup(allFindings)
			if len(outputs) > 0 {
				input.Previous = outputs[len(outputs)-1]
			} else {
				input.Previous = AgentOutput{}
			}

			startedAt := time.Now().UTC()
			output, runErr := agent.Run(ctx, input)
			completedAt := time.Now().UTC()

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
			// Emit per-agent metrics inline so the dashboard reflects live
			// progress instead of a batch update at the very end of the run.
			metrics.AgentRun(output.AgentName)
			metrics.AgentCompleted(output.AgentName, output.Status, float64(output.DurationMs)/1000.0, len(output.Findings))
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
			roundScore -= clamp01(float64(timeToSignalMs)/timeToSignalPenaltyThresholdMs) * timeToSignalPenaltyWeight
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
			return outputs, combineFindingsWithDedup(allFindings), nil
		}
		if o.MaxConsecutiveFailureRounds > 0 && consecutiveFailureRounds >= o.MaxConsecutiveFailureRounds {
			return outputs, combineFindingsWithDedup(allFindings), nil
		}
		if o.MinMarginalScore > 0 && roundScore < o.MinMarginalScore {
			lowMarginalScoreRounds++
		} else {
			lowMarginalScoreRounds = 0
		}
		if o.MinMarginalScore > 0 && lowMarginalScoreRounds >= 2 {
			return outputs, combineFindingsWithDedup(allFindings), nil
		}
	}

	return outputs, combineFindingsWithDedup(allFindings), nil
}

func computeActionQuality(output AgentOutput) float64 {
	score := 0.0
	findings := len(output.Findings)
	if findings > 0 {
		score += clamp01(float64(findings) / 3.0)
	}
	highSignal := 0
	lowSignal := 0
	for _, f := range output.Findings {
		if f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical || f.Confidence >= 0.85 {
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
		if f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical || f.Confidence >= 0.85 {
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
