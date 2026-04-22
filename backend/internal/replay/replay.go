// Package replay provides an offline planner replay harness.
//
// The harness drives an agent.Planner round-by-round against a recorded
// historical scan and compares the planner's chosen agents to the agents that
// actually ran. This lets us evaluate candidate planning strategies (for
// example a new AI planner or a tweaked static ordering) against a baseline
// without needing to execute live scans, satisfying the Wave 2 acceptance
// criterion that "planner replay can score and compare candidate strategies
// against baseline".
//
// The harness is intentionally pure: it never executes agents, never makes
// network calls, and never touches the database. All state is supplied via
// HistoricalRun values in memory, which makes it suitable both as a Go
// library used from tests and as the engine behind a small CLI binary.
package replay

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/model"
)

// RecordedAgentRun captures the relevant slice of a single agent execution
// from a historical scan. Only the fields that influence planner decisions
// (name, status, error, timeout, durations, metadata, findings) are recorded
// so the harness can rebuild realistic AgentInput.History snapshots without
// pulling in the full execution context.
type RecordedAgentRun struct {
	AgentName  string            `json:"agentName"`
	Status     string            `json:"status,omitempty"`
	Error      string            `json:"error,omitempty"`
	TimedOut   bool              `json:"timedOut,omitempty"`
	DurationMs int64             `json:"durationMs,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Findings   []model.Finding   `json:"findings,omitempty"`
}

// HistoricalRun is the recorded ground-truth for a single scan that the
// harness can replay against any Planner.
type HistoricalRun struct {
	ScanID          string               `json:"scanId,omitempty"`
	Target          string               `json:"target"`
	Options         model.ScanOptions    `json:"options,omitempty"`
	Scope           model.ScanScope      `json:"scope,omitempty"`
	AvailableAgents []string             `json:"availableAgents"`
	AutonomyMemory  model.AutonomyMemory `json:"autonomyMemory,omitempty"`
	Runs            []RecordedAgentRun   `json:"runs"`
}

// PlannerFactory builds a fresh Planner for a given HistoricalRun. It receives
// the run so that planner construction can depend on per-scan context such as
// available agents or scan options.
type PlannerFactory func(run HistoricalRun) (agent.Planner, error)

// RoundOutcome records what happened on a single planner round during replay.
type RoundOutcome struct {
	Round            int      `json:"round"`
	RecordedNext     string   `json:"recordedNext,omitempty"`
	PlannerProposed  []string `json:"plannerProposed,omitempty"`
	MatchedRecorded  bool     `json:"matchedRecorded"`
	FirstChoiceMatch bool     `json:"firstChoiceMatch"`
	PlannerDone      bool     `json:"plannerDone"`
	Notes            string   `json:"notes,omitempty"`
}

// RunReport is the per-historical-run replay outcome for one planner.
type RunReport struct {
	ScanID                string         `json:"scanId,omitempty"`
	Target                string         `json:"target"`
	RecordedAgents        []string       `json:"recordedAgents"`
	Rounds                []RoundOutcome `json:"rounds"`
	RecordedRunCount      int            `json:"recordedRunCount"`
	MatchedRoundCount     int            `json:"matchedRoundCount"`
	FirstChoiceMatchCount int            `json:"firstChoiceMatchCount"`
	PlannerStoppedEarly   bool           `json:"plannerStoppedEarly"`
	PlannerOnlyAgents     []string       `json:"plannerOnlyAgents,omitempty"`
	UnscheduledAgents     []string       `json:"unscheduledAgents,omitempty"`
	MatchRate             float64        `json:"matchRate"`
	FirstChoiceMatchRate  float64        `json:"firstChoiceMatchRate"`
}

// PlannerReport aggregates per-run reports for a single named planner.
type PlannerReport struct {
	Name                          string      `json:"name"`
	Runs                          []RunReport `json:"runs"`
	TotalRecordedRounds           int         `json:"totalRecordedRounds"`
	TotalMatchedRounds            int         `json:"totalMatchedRounds"`
	TotalFirstChoiceMatches       int         `json:"totalFirstChoiceMatches"`
	AggregateMatchRate            float64     `json:"aggregateMatchRate"`
	AggregateFirstChoiceMatchRate float64     `json:"aggregateFirstChoiceMatchRate"`
	EarlyStops                    int         `json:"earlyStops"`
}

// ComparisonReport is the top-level output of the harness; it is a
// baseline-vs-candidate comparison plus a small delta summary that downstream
// dashboards and CI gates can consume directly.
type ComparisonReport struct {
	Baseline  PlannerReport      `json:"baseline"`
	Candidate PlannerReport      `json:"candidate"`
	Delta     ComparisonDelta    `json:"delta"`
	PerRun    []PerRunComparison `json:"perRun,omitempty"`
}

// ComparisonDelta summarises candidate-minus-baseline aggregate metrics so
// callers can quickly tell whether the candidate planner is an improvement.
type ComparisonDelta struct {
	MatchRateDelta            float64 `json:"matchRateDelta"`
	FirstChoiceMatchRateDelta float64 `json:"firstChoiceMatchRateDelta"`
	EarlyStopsDelta           int     `json:"earlyStopsDelta"`
}

// PerRunComparison is a per-historical-run side-by-side view used by humans
// reading the JSON output.
type PerRunComparison struct {
	ScanID                   string  `json:"scanId,omitempty"`
	Target                   string  `json:"target"`
	BaselineMatchRate        float64 `json:"baselineMatchRate"`
	CandidateMatchRate       float64 `json:"candidateMatchRate"`
	BaselineFirstChoiceRate  float64 `json:"baselineFirstChoiceRate"`
	CandidateFirstChoiceRate float64 `json:"candidateFirstChoiceRate"`
	BaselineStoppedEarly     bool    `json:"baselineStoppedEarly"`
	CandidateStoppedEarly    bool    `json:"candidateStoppedEarly"`
}

// Compare runs each historical scan through both planners and produces a
// baseline comparison. The factories are called once per run so each replay
// gets a fresh planner instance with no leaked state across scans.
func Compare(ctx context.Context, runs []HistoricalRun, baselineName string, baseline PlannerFactory, candidateName string, candidate PlannerFactory) (ComparisonReport, error) {
	if len(runs) == 0 {
		return ComparisonReport{}, errors.New("replay: no historical runs supplied")
	}
	if baseline == nil {
		return ComparisonReport{}, errors.New("replay: baseline planner factory is required")
	}
	if candidate == nil {
		return ComparisonReport{}, errors.New("replay: candidate planner factory is required")
	}
	if strings.TrimSpace(baselineName) == "" {
		baselineName = "baseline"
	}
	if strings.TrimSpace(candidateName) == "" {
		candidateName = "candidate"
	}

	base := PlannerReport{Name: baselineName}
	cand := PlannerReport{Name: candidateName}
	perRun := make([]PerRunComparison, 0, len(runs))

	for _, run := range runs {
		baseRun, err := replayOne(ctx, run, baseline)
		if err != nil {
			return ComparisonReport{}, fmt.Errorf("replay baseline %q on %q: %w", baselineName, run.Target, err)
		}
		candRun, err := replayOne(ctx, run, candidate)
		if err != nil {
			return ComparisonReport{}, fmt.Errorf("replay candidate %q on %q: %w", candidateName, run.Target, err)
		}
		base.Runs = append(base.Runs, baseRun)
		cand.Runs = append(cand.Runs, candRun)
		perRun = append(perRun, PerRunComparison{
			ScanID:                   run.ScanID,
			Target:                   run.Target,
			BaselineMatchRate:        baseRun.MatchRate,
			CandidateMatchRate:       candRun.MatchRate,
			BaselineFirstChoiceRate:  baseRun.FirstChoiceMatchRate,
			CandidateFirstChoiceRate: candRun.FirstChoiceMatchRate,
			BaselineStoppedEarly:     baseRun.PlannerStoppedEarly,
			CandidateStoppedEarly:    candRun.PlannerStoppedEarly,
		})
	}

	finalize(&base)
	finalize(&cand)

	return ComparisonReport{
		Baseline:  base,
		Candidate: cand,
		Delta: ComparisonDelta{
			MatchRateDelta:            cand.AggregateMatchRate - base.AggregateMatchRate,
			FirstChoiceMatchRateDelta: cand.AggregateFirstChoiceMatchRate - base.AggregateFirstChoiceMatchRate,
			EarlyStopsDelta:           cand.EarlyStops - base.EarlyStops,
		},
		PerRun: perRun,
	}, nil
}

func replayOne(ctx context.Context, run HistoricalRun, factory PlannerFactory) (RunReport, error) {
	planner, err := factory(run)
	if err != nil {
		return RunReport{}, fmt.Errorf("build planner: %w", err)
	}
	if planner == nil {
		return RunReport{}, errors.New("planner factory returned nil planner")
	}

	recorded := make([]string, 0, len(run.Runs))
	for _, r := range run.Runs {
		name := strings.TrimSpace(r.AgentName)
		if name != "" {
			recorded = append(recorded, name)
		}
	}

	report := RunReport{
		ScanID:           run.ScanID,
		Target:           run.Target,
		RecordedAgents:   recorded,
		RecordedRunCount: len(recorded),
	}

	history := make([]agent.AgentOutput, 0, len(run.Runs))
	cumulative := make([]model.Finding, 0)
	plannerSuggested := map[string]struct{}{}
	stoppedEarly := false

	for round := 0; round < len(run.Runs); round++ {
		input := agent.AgentInput{
			Target:         run.Target,
			Options:        run.Options,
			Scope:          run.Scope,
			AutonomyMemory: run.AutonomyMemory,
			History:        append([]agent.AgentOutput(nil), history...),
			AllFindings:    append([]model.Finding(nil), cumulative...),
		}
		if len(history) > 0 {
			input.Previous = history[len(history)-1]
		}

		decision, err := planner.Plan(ctx, input, history)
		if err != nil {
			return RunReport{}, fmt.Errorf("planner returned error at round %d: %w", round+1, err)
		}

		recordedNext := recorded[round]
		proposed := make([]string, 0, len(decision.Agents))
		for _, spec := range decision.Agents {
			name := strings.TrimSpace(spec.Name)
			if name == "" {
				continue
			}
			proposed = append(proposed, name)
			plannerSuggested[name] = struct{}{}
		}

		matched := false
		firstMatch := false
		for i, name := range proposed {
			if name == recordedNext {
				matched = true
				if i == 0 {
					firstMatch = true
				}
				break
			}
		}

		report.Rounds = append(report.Rounds, RoundOutcome{
			Round:            round + 1,
			RecordedNext:     recordedNext,
			PlannerProposed:  proposed,
			MatchedRecorded:  matched,
			FirstChoiceMatch: firstMatch,
			PlannerDone:      decision.IsDone,
			Notes:            decision.Notes,
		})
		if matched {
			report.MatchedRoundCount++
		}
		if firstMatch {
			report.FirstChoiceMatchCount++
		}
		if decision.IsDone && !matched {
			stoppedEarly = true
			report.PlannerStoppedEarly = true
			break
		}

		// Advance history with the recorded outcome regardless of whether the
		// planner agreed; the harness models "what would the planner have
		// chosen if the recorded scan had run as observed?".
		recordedRun := run.Runs[round]
		out := agent.AgentOutput{
			AgentName:  recordedRun.AgentName,
			Status:     recordedRun.Status,
			Error:      recordedRun.Error,
			TimedOut:   recordedRun.TimedOut,
			DurationMs: recordedRun.DurationMs,
			Metadata:   recordedRun.Metadata,
			Findings:   append([]model.Finding(nil), recordedRun.Findings...),
		}
		if out.Status == "" {
			if out.Error != "" {
				out.Status = "error"
			} else {
				out.Status = "completed"
			}
		}
		history = append(history, out)
		cumulative = append(cumulative, recordedRun.Findings...)
	}

	if !stoppedEarly && len(report.Rounds) < len(recorded) {
		report.PlannerStoppedEarly = true
	}

	recordedSet := map[string]struct{}{}
	for _, name := range recorded {
		recordedSet[name] = struct{}{}
	}
	for name := range plannerSuggested {
		if _, ok := recordedSet[name]; !ok {
			report.PlannerOnlyAgents = append(report.PlannerOnlyAgents, name)
		}
	}
	for _, name := range recorded {
		if _, ok := plannerSuggested[name]; !ok {
			report.UnscheduledAgents = append(report.UnscheduledAgents, name)
		}
	}
	sort.Strings(report.PlannerOnlyAgents)
	report.UnscheduledAgents = dedupePreserveOrder(report.UnscheduledAgents)

	if report.RecordedRunCount > 0 {
		report.MatchRate = float64(report.MatchedRoundCount) / float64(report.RecordedRunCount)
		report.FirstChoiceMatchRate = float64(report.FirstChoiceMatchCount) / float64(report.RecordedRunCount)
	}

	return report, nil
}

func finalize(report *PlannerReport) {
	for _, r := range report.Runs {
		report.TotalRecordedRounds += r.RecordedRunCount
		report.TotalMatchedRounds += r.MatchedRoundCount
		report.TotalFirstChoiceMatches += r.FirstChoiceMatchCount
		if r.PlannerStoppedEarly {
			report.EarlyStops++
		}
	}
	if report.TotalRecordedRounds > 0 {
		report.AggregateMatchRate = float64(report.TotalMatchedRounds) / float64(report.TotalRecordedRounds)
		report.AggregateFirstChoiceMatchRate = float64(report.TotalFirstChoiceMatches) / float64(report.TotalRecordedRounds)
	}
}

func dedupePreserveOrder(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// StaticPlannerFactory returns a PlannerFactory that builds a StaticPlanner
// over the run's AvailableAgents in their declared order. This is the default
// "registered order" baseline used by the harness when no explicit factory is
// supplied.
func StaticPlannerFactory() PlannerFactory {
	return func(run HistoricalRun) (agent.Planner, error) {
		return agent.NewStaticPlanner(run.AvailableAgents), nil
	}
}

// RecordedOrderPlannerFactory returns a PlannerFactory that builds a
// StaticPlanner using the agent execution order observed in the recorded run.
// It serves as an oracle baseline: a perfect candidate would match the
// recorded sequence exactly.
func RecordedOrderPlannerFactory() PlannerFactory {
	return func(run HistoricalRun) (agent.Planner, error) {
		order := make([]string, 0, len(run.Runs))
		for _, r := range run.Runs {
			name := strings.TrimSpace(r.AgentName)
			if name != "" {
				order = append(order, name)
			}
		}
		return agent.NewStaticPlanner(order), nil
	}
}
