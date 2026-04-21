package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
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
			outputs = append(outputs, output)
			allFindings = append(allFindings, output.Findings...)
			delete(forcePending, output.AgentName)
		}

		afterCount := len(combineFindingsWithDedup(allFindings))
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
	}

	return outputs, combineFindingsWithDedup(allFindings), nil
}
