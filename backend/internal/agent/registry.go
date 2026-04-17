package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

type Agent interface {
	Name() string
	Enabled() bool
	Run(ctx context.Context, input AgentInput) (AgentOutput, error)
}

// Emitter is a function that publishes a ScanEvent to the live event bus.
// It is nil-safe: callers may call it unconditionally and it is a no-op when nil.
type Emitter func(model.ScanEvent)

// Emit is a nil-safe helper that calls e if it is non-nil.
func Emit(e Emitter, evt model.ScanEvent) {
	if e != nil {
		e(evt)
	}
}

type AgentInput struct {
	Target      string
	AuthProfile model.ScanAuthProfile
	Options     model.ScanOptions
	Scope       model.ScanScope
	Previous    AgentOutput
	History     []AgentOutput
	AllFindings []model.Finding
	// Emit is an optional callback for publishing live scan events to the event bus.
	// Agents should use the package-level Emit helper to call it safely.
	Emit Emitter
}

type AgentOutput struct {
	AgentName   string
	Findings    []model.Finding
	Metadata    map[string]string
	Status      string
	DebugNotes  string
	StartedAt   time.Time
	CompletedAt time.Time
	DurationMs  int64
	TimedOut    bool
	Error       string
	Telemetry   model.AgentRunTelemetry
}

type Registry struct {
	agents map[string]Agent
	order  []string
}

func NewRegistry() *Registry {
	return &Registry{
		agents: make(map[string]Agent),
		order:  make([]string, 0),
	}
}

func (r *Registry) Register(agent Agent) {
	if agent == nil {
		return
	}
	r.agents[agent.Name()] = agent
	r.order = append(r.order, agent.Name())
}

func (r *Registry) Get(name string) Agent {
	return r.agents[name]
}

func (r *Registry) RunAll(ctx context.Context, input AgentInput) ([]AgentOutput, []model.Finding, error) {
	outputs := make([]AgentOutput, 0, len(r.order))
	allFindings := make([]model.Finding, 0)
	cumulativeFindings := make([]model.Finding, 0)

	// Build a mutable work queue starting from the registered agent order so
	// that the orchestrator can dynamically append follow-up agents.
	queue := make([]string, len(r.order))
	copy(queue, r.order)
	seen := make(map[string]bool, len(r.order))

	for i := 0; i < len(queue); i++ {
		name := queue[i]
		ag := r.agents[name]
		if ag == nil || !ag.Enabled() {
			continue
		}

		select {
		case <-ctx.Done():
			return outputs, allFindings, ctx.Err()
		default:
		}

		input.Previous = AgentOutput{}
		if len(outputs) > 0 {
			input.Previous = outputs[len(outputs)-1]
		}
		input.AllFindings = append([]model.Finding(nil), cumulativeFindings...)

		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventAgentStart,
			AgentName: ag.Name(),
			Message:   fmt.Sprintf("Agent %q started", ag.Name()),
		})

		startedAt := time.Now().UTC()
		output, err := ag.Run(ctx, input)
		completedAt := time.Now().UTC()
		if err != nil {
			output.Status = "error"
			output.DebugNotes = err.Error()
			output.Error = err.Error()
			output.TimedOut = strings.Contains(strings.ToLower(err.Error()), "deadline exceeded")
		}
		if output.AgentName == "" {
			output.AgentName = ag.Name()
		}
		if output.Status == "" {
			output.Status = "completed"
		}
		output.StartedAt = startedAt
		output.CompletedAt = completedAt
		output.DurationMs = completedAt.Sub(startedAt).Milliseconds()
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

		// Emit individual finding events so the frontend can show them live.
		for _, f := range output.Findings {
			Emit(input.Emit, model.ScanEvent{
				Type:         model.ScanEventFinding,
				AgentName:    ag.Name(),
				FindingTitle: f.Title,
				Severity:     string(f.Severity),
				Message:      fmt.Sprintf("[%s] %s", f.Severity, f.Title),
			})
		}

		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventAgentComplete,
			AgentName: ag.Name(),
			Message:   fmt.Sprintf("Agent %q completed in %dms with %d finding(s)", ag.Name(), output.DurationMs, len(output.Findings)),
			Metadata:  output.Metadata,
		})

		outputs = append(outputs, output)
		cumulativeFindings = append(cumulativeFindings, output.Findings...)
		allFindings = append(allFindings, output.Findings...)
		seen[name] = true

		// Autonomous orchestration: decide which follow-up agents to spawn based
		// on what was discovered. Only add agents that exist in the registry and
		// have not already run or been queued.
		for _, spawned := range r.orchestrate(ag.Name(), output, cumulativeFindings) {
			if !seen[spawned] && r.agents[spawned] != nil {
				alreadyQueued := false
				for _, q := range queue[i+1:] {
					if q == spawned {
						alreadyQueued = true
						break
					}
				}
				if !alreadyQueued {
					queue = append(queue, spawned)
					Emit(input.Emit, model.ScanEvent{
						Type:      model.ScanEventAgentSpawned,
						AgentName: spawned,
						Message:   fmt.Sprintf("Autonomous decision: queuing agent %q based on findings from %q", spawned, ag.Name()),
					})
				}
			}
		}
	}

	return outputs, combineFindingsWithDedup(allFindings), nil
}

// orchestrate returns the names of agents that should be spawned autonomously
// after completedAgent finishes, given the accumulated findings so far.
func (r *Registry) orchestrate(completedAgent string, output AgentOutput, allFindings []model.Finding) []string {
	spawned := make([]string, 0)

	hasHigh := false
	hasSQLi := false
	hasWordPress := false
	hasManyForms := false
	for _, f := range allFindings {
		if f.Severity == model.SeverityHigh {
			hasHigh = true
		}
		cat := strings.ToLower(f.Category)
		title := strings.ToLower(f.Title)
		ev := strings.ToLower(f.Evidence)
		if strings.Contains(cat, "injection") || strings.Contains(title, "sql") || strings.Contains(ev, "sql") {
			hasSQLi = true
		}
		if strings.Contains(title, "wordpress") || strings.Contains(ev, "wordpress") || strings.Contains(ev, "wp-content") {
			hasWordPress = true
		}
		if strings.Contains(title, "form") && (strings.Contains(title, "csrf") || strings.Contains(ev, "forms=")) {
			hasManyForms = true
		}
	}

	_ = hasSQLi
	_ = hasWordPress

	switch completedAgent {
	case "scanning":
		if hasHigh {
			// Escalate immediately with ML-based attack path analysis for high findings.
			spawned = append(spawned, "attack_path")
		}
	case "input_validation":
		// After input validation, if forms are found without CSRF, ensure
		// the CORS/redirect agent runs for a deeper look.
		if hasManyForms {
			spawned = append(spawned, "cors_redirect")
		}
	case "wordlist":
		// If wordlist discovered new endpoints, run a fresh analysis pass.
		if len(output.Findings) > 0 {
			spawned = append(spawned, "analysis")
		}
	case "analysis":
		// If analysis surfaces high-severity items, escalate with ML triage.
		if hasHigh {
			spawned = append(spawned, "ml_triage")
		}
	}

	return spawned
}

func combineFindingsWithDedup(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{})
	deduped := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%s", f.Category, f.Title, f.Evidence)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, f)
	}
	return deduped
}
