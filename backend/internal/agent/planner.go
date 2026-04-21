package agent

import (
	"context"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// AgentSpec describes a single agent the planner has decided to run next.
// Reason is informational and is recorded into the agent's metadata so that
// downstream telemetry can explain why an agent was scheduled.
type AgentSpec struct {
	Name   string
	Reason string
}

// PlannerDecision is what a Planner returns at each orchestration round.
// When IsDone is true the orchestrator stops scheduling further agents.
type PlannerDecision struct {
	Agents []AgentSpec
	IsDone bool
	Notes  string
}

// Planner decides which agents should run next given the current findings
// and execution history.
type Planner interface {
	Plan(ctx context.Context, input AgentInput, history []AgentOutput) (PlannerDecision, error)
}

// StaticPlanner reproduces the historical "run every registered agent in order
// once" behavior. It is used when no AI provider is configured or when
// autonomous orchestration is disabled.
type StaticPlanner struct {
	Order []string
}

// NewStaticPlanner returns a StaticPlanner that walks the supplied agent names
// in order. Empty names are filtered out so callers can pass registry order
// directly.
func NewStaticPlanner(order []string) *StaticPlanner {
	cleaned := make([]string, 0, len(order))
	for _, name := range order {
		name = strings.TrimSpace(name)
		if name != "" {
			cleaned = append(cleaned, name)
		}
	}
	return &StaticPlanner{Order: cleaned}
}

// Plan returns the next not-yet-run agent and signals done when the static
// pipeline has been fully executed.
func (p *StaticPlanner) Plan(_ context.Context, _ AgentInput, history []AgentOutput) (PlannerDecision, error) {
	completed := map[string]struct{}{}
	for _, h := range history {
		if h.AgentName != "" {
			completed[h.AgentName] = struct{}{}
		}
	}
	for _, name := range p.Order {
		if _, done := completed[name]; done {
			continue
		}
		return PlannerDecision{
			Agents: []AgentSpec{{Name: name, Reason: "static-pipeline"}},
		}, nil
	}
	return PlannerDecision{IsDone: true, Notes: "static pipeline exhausted"}, nil
}

// AIPlanCaller is the minimal contract the AIPlanner needs from the AI client.
// It is satisfied by *ai.Client.Plan and is declared here to avoid an import
// cycle between the agent and ai packages.
type AIPlanCaller interface {
	Plan(ctx context.Context, target string, findings []any, history []map[string]string, availableAgents []string) ([]map[string]string, bool, error)
}

// AIPlanner asks the configured AI provider what to run next, falling back to
// the supplied StaticPlanner when the provider is unavailable, returns an
// error, or yields no actionable agents.
type AIPlanner struct {
	Caller            AIPlanCaller
	AvailableAgents   []string
	Fallback          *StaticPlanner
	MaxAgentsPerRound int
}

const (
	minRunsBeforeAdaptiveBlock  = 2
	minRunsForHighErrorBlock    = 3
	highErrorRateBlockThreshold = 0.66
)

// NewAIPlanner constructs an AIPlanner. availableAgents should list every
// agent name the factory can build; fallback is required.
func NewAIPlanner(caller AIPlanCaller, availableAgents []string, fallback *StaticPlanner) *AIPlanner {
	cleaned := make([]string, 0, len(availableAgents))
	for _, name := range availableAgents {
		name = strings.TrimSpace(name)
		if name != "" {
			cleaned = append(cleaned, name)
		}
	}
	if fallback == nil {
		fallback = NewStaticPlanner(cleaned)
	}
	return &AIPlanner{
		Caller:            caller,
		AvailableAgents:   cleaned,
		Fallback:          fallback,
		MaxAgentsPerRound: 3,
	}
}

// Plan asks the AI provider for the next batch of agents to run; on any error
// or empty response it delegates to the static fallback so the scan still
// completes deterministically.
func (p *AIPlanner) Plan(ctx context.Context, input AgentInput, history []AgentOutput) (PlannerDecision, error) {
	if p == nil || p.Caller == nil {
		if p != nil && p.Fallback != nil {
			return p.Fallback.Plan(ctx, input, history)
		}
		return PlannerDecision{IsDone: true}, nil
	}

	findings := make([]any, 0, len(input.AllFindings))
	for _, f := range input.AllFindings {
		findings = append(findings, map[string]string{
			"id":       f.ID,
			"category": f.Category,
			"severity": string(f.Severity),
			"title":    f.Title,
		})
	}

	historySummary := make([]map[string]string, 0, len(history))
	stats := computeAgentRunStats(history)
	for _, h := range history {
		historySummary = append(historySummary, map[string]string{
			"agent":      h.AgentName,
			"status":     h.Status,
			"findings":   itoa(len(h.Findings)),
			"errors":     itoa(stats[h.AgentName].Errors),
			"runs":       itoa(stats[h.AgentName].Runs),
			"novelty":    itoa(stats[h.AgentName].NovelFindings),
			"durationMs": itoa(int(h.DurationMs)),
		})
	}

	specs, done, err := p.Caller.Plan(ctx, input.Target, findings, historySummary, p.AvailableAgents)
	if err != nil {
		if p.Fallback != nil {
			return p.Fallback.Plan(ctx, input, history)
		}
		return PlannerDecision{IsDone: true, Notes: "ai planner error: " + err.Error()}, nil
	}

	available := map[string]struct{}{}
	for _, name := range p.AvailableAgents {
		available[name] = struct{}{}
	}
	blocked := buildBlockedAgents(stats, input.AutonomyMemory)

	agents := make([]AgentSpec, 0, len(specs))
	for _, s := range specs {
		name := strings.TrimSpace(s["name"])
		if name == "" {
			continue
		}
		if _, ok := available[name]; !ok {
			continue
		}
		if blocked[name] && !isUrgentReason(s["reason"]) {
			continue
		}
		agents = append(agents, AgentSpec{Name: name, Reason: strings.TrimSpace(s["reason"])})
		if p.MaxAgentsPerRound > 0 && len(agents) >= p.MaxAgentsPerRound {
			break
		}
	}

	if len(agents) == 0 && !done {
		if p.Fallback != nil {
			return p.Fallback.Plan(ctx, input, history)
		}
		return PlannerDecision{IsDone: true, Notes: "ai planner returned no actionable agents"}, nil
	}

	return PlannerDecision{Agents: agents, IsDone: done, Notes: "ai-planned"}, nil
}

type agentRunStats struct {
	Runs          int
	Errors        int
	Timeouts      int
	Findings      int
	NovelFindings int
}

func computeAgentRunStats(history []AgentOutput) map[string]agentRunStats {
	stats := map[string]agentRunStats{}
	type findingKey struct {
		Category string
		Title    string
		Evidence string
	}
	seen := map[findingKey]struct{}{}
	for _, h := range history {
		name := strings.TrimSpace(h.AgentName)
		if name == "" {
			continue
		}
		cur := stats[name]
		cur.Runs++
		if h.Status == "error" || strings.TrimSpace(h.Error) != "" {
			cur.Errors++
		}
		if h.TimedOut {
			cur.Timeouts++
		}
		cur.Findings += len(h.Findings)
		for _, f := range h.Findings {
			key := findingKey{Category: f.Category, Title: f.Title, Evidence: f.Evidence}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			cur.NovelFindings++
		}
		stats[name] = cur
	}
	return stats
}

func buildBlockedAgents(stats map[string]agentRunStats, memory model.AutonomyMemory) map[string]bool {
	blocked := map[string]bool{}
	for _, name := range memory.SuppressedAgents {
		name = strings.TrimSpace(name)
		if name != "" {
			blocked[name] = true
		}
	}
	for name, st := range stats {
		if st.Runs < minRunsBeforeAdaptiveBlock {
			continue
		}
		errorRate := float64(st.Errors) / float64(st.Runs)
		if st.Findings == 0 && (st.Errors > 0 || st.Timeouts > 0) {
			blocked[name] = true
			continue
		}
		if shouldBlockForHighErrorRate(st, errorRate) {
			blocked[name] = true
		}
	}
	return blocked
}

// shouldBlockForHighErrorRate suppresses an agent only when repeated runs show
// mostly failures and no novelty, which indicates the agent is currently
// expensive noise rather than a useful follow-up.
func shouldBlockForHighErrorRate(st agentRunStats, errorRate float64) bool {
	return st.Runs >= minRunsForHighErrorBlock &&
		errorRate >= highErrorRateBlockThreshold &&
		st.NovelFindings == 0
}

func isUrgentReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	return strings.Contains(reason, "critical") ||
		strings.Contains(reason, "high") ||
		strings.Contains(reason, "rce") ||
		strings.Contains(reason, "exploit") ||
		strings.Contains(reason, "auth")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
