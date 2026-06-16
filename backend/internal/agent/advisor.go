package agent

// advisor.go — AI-guided agent advisor that teaches static security agents how
// to be fully agentic.
//
// The core idea mirrors how a skilled senior pentester mentors a junior one:
// before running, the advisor reads everything known about the target so far
// (prior findings, shared blackboard) and tells the agent which checks matter
// most right now and which can safely be skipped. After the run, it synthesises
// what the agent learned and writes a compact lesson back to the blackboard so
// that every subsequent agent benefits.
//
// Architecture:
//
//	AgentAdvisor  – holds the AI client; provides Wrap() to decorate any Agent.
//	AdvisedAgent  – transparent decorator; adds pre-run thinking + post-run
//	                lesson synthesis without touching the wrapped agent's logic.
//	ParseAdviceNote – decodes a SharedScanContext note written by AdvisedAgent
//	                  so static agents can reorder/skip their checks.
//	OrderChecks   – reorders a check list according to advice priorities and
//	                removes checks in the skip list.
//	ShouldSkip    – single-check skip predicate.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
)

// AdviserCaller is the minimal interface an AI client must satisfy to provide
// agent advice. It is implemented by *ai.Client and exists here to allow tests
// to inject stub advisers without depending on a live AI provider.
type AdviserCaller interface {
	AdviseAgent(
		ctx context.Context,
		agentName string,
		target string,
		availableChecks []string,
		findings []model.Finding,
		blackboard string,
	) ai.AgentAdvice
}

// AgentAdvisor provides AI-guided pre-run focus and post-run lesson synthesis
// for static security agents. Use Wrap to decorate any Agent with these hooks.
type AgentAdvisor struct {
	caller AdviserCaller
}

// NewAgentAdvisor constructs an AgentAdvisor backed by the given AI client.
// When caller is nil the advisor is a no-op that returns zero-value advice for
// all calls, preserving default agent behaviour exactly.
func NewAgentAdvisor(caller AdviserCaller) *AgentAdvisor {
	return &AgentAdvisor{caller: caller}
}

// Wrap decorates agent with advisor-driven pre/post hooks and returns the
// result as an Agent. checks should list the canonical check names the agent
// performs (e.g. "sqli", "xss") so the advisor can advise on ordering and
// skipping. When a is nil, the original agent is returned unchanged.
func (a *AgentAdvisor) Wrap(agent Agent, checks []string) Agent {
	if a == nil || agent == nil {
		return agent
	}
	return &AdvisedAgent{Agent: agent, advisor: a, checks: checks}
}

// advise asks the AI caller for guidance on what the named agent should focus
// on given the current scan input. Returns zero-value AgentAdvice when no
// caller is available.
func (a *AgentAdvisor) advise(ctx context.Context, agentName string, checks []string, input AgentInput) ai.AgentAdvice {
	if a == nil || a.caller == nil {
		return ai.AgentAdvice{}
	}
	blackboard := ""
	if input.SharedScanContext != nil {
		blackboard = input.SharedScanContext.DiscoverySummary()
	}
	return a.caller.AdviseAgent(ctx, agentName, input.Target, checks, input.AllFindings, blackboard)
}

// AdvisedAgent is a transparent decorator that adds AI-guided pre-run focus
// and post-run lesson synthesis around any static Agent.
//
// Pre-run:
//  1. The advisor asks the fast AI model what checks to prioritise or skip.
//  2. Advice is written to the SharedScanContext note (keyed by agent name)
//     so the wrapped agent can read it via SharedScanContext.GetNote(name).
//  3. A ScanEventThinking event is emitted so the operator can see why the
//     agent is about to focus on specific checks.
//
// Post-run:
//  4. A short lesson is synthesised from the findings and written back to
//     the blackboard so subsequent agents know what this agent confirmed.
type AdvisedAgent struct {
	Agent
	advisor *AgentAdvisor
	checks  []string
}

// Run executes the pre-run advisory, the wrapped agent, and the post-run
// lesson synthesis. It is safe to call with a nil SharedScanContext.
func (a *AdvisedAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	// ── 1. Get AI advice ──────────────────────────────────────────────────
	advice := a.advisor.advise(ctx, a.Name(), a.checks, input)

	// ── 2. Emit thinking event so the operator can see the pre-run logic ──
	if thinking := strings.TrimSpace(advice.Thinking); thinking != "" {
		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventThinking,
			AgentName: a.Name(),
			Message:   fmt.Sprintf("[%s] pre-run advisory: %s", a.Name(), thinking),
			Metadata: map[string]string{
				"stage":          "pre_run_advice",
				"agent":          a.Name(),
				"priorityChecks": strings.Join(advice.PriorityChecks, ","),
				"skipChecks":     strings.Join(advice.SkipChecks, ","),
			},
		})
	} else if rationale := strings.TrimSpace(advice.Rationale); rationale != "" {
		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventThinking,
			AgentName: a.Name(),
			Message:   fmt.Sprintf("[%s] pre-run advisory: %s", a.Name(), rationale),
			Metadata: map[string]string{
				"stage":          "pre_run_advice",
				"agent":          a.Name(),
				"priorityChecks": strings.Join(advice.PriorityChecks, ","),
				"skipChecks":     strings.Join(advice.SkipChecks, ","),
			},
		})
	}

	// ── 3. Write advice to blackboard so the wrapped agent can read it ────
	if input.SharedScanContext != nil {
		if encoded := encodeAdvice(advice); encoded != "" {
			input.SharedScanContext.SetNote(a.Name(), encoded)
		}
		// Seed any focus endpoints the advisor identified.
		for _, ep := range advice.FocusEndpoints {
			ep = strings.TrimSpace(ep)
			if ep != "" {
				input.SharedScanContext.AddEndpoint(ep)
			}
		}
	}

	// ── 4. Run the wrapped agent ──────────────────────────────────────────
	output, err := a.Agent.Run(ctx, input)

	// ── 5. Post-run: write lesson to blackboard for subsequent agents ─────
	if input.SharedScanContext != nil {
		if lesson := buildLesson(a.Name(), output.Findings, advice.Rationale); lesson != "" {
			input.SharedScanContext.SetNote(a.Name()+":learned", lesson)
			input.SharedScanContext.AddDiscovery(DiscoveryEvent{
				Kind:        DiscoveryGeneric,
				Value:       lesson,
				SourceAgent: a.Name(),
				Confidence:  0.75,
			}, input.Emit)
		}
	}

	return output, err
}

// ── Helpers shared by static agents ─────────────────────────────────────────

// ParseAdviceNote decodes a SharedScanContext note written by AdvisedAgent into
// an AgentAdvice struct. Returns zero-value AgentAdvice when the note is absent
// or unparseable — callers should proceed with their default check order.
func ParseAdviceNote(note string) ai.AgentAdvice {
	note = strings.TrimSpace(note)
	if note == "" {
		return ai.AgentAdvice{}
	}
	var advice ai.AgentAdvice
	if err := json.Unmarshal([]byte(note), &advice); err != nil {
		return ai.AgentAdvice{}
	}
	return advice
}

// OrderChecks reorders checks so that items in advice.PriorityChecks come
// first (in priority order) followed by all remaining checks in their original
// order. Items in advice.SkipChecks are removed entirely.
//
// When advice is the zero value, the original order is returned unchanged.
func OrderChecks(advice ai.AgentAdvice, checks []string) []string {
	if len(advice.PriorityChecks) == 0 && len(advice.SkipChecks) == 0 {
		return checks
	}

	skip := make(map[string]bool, len(advice.SkipChecks))
	for _, s := range advice.SkipChecks {
		skip[strings.ToLower(strings.TrimSpace(s))] = true
	}

	priorityRank := make(map[string]int, len(advice.PriorityChecks))
	for i, p := range advice.PriorityChecks {
		priorityRank[strings.ToLower(strings.TrimSpace(p))] = i + 1
	}

	prioritised := make([]string, 0, len(advice.PriorityChecks))
	remainder := make([]string, 0, len(checks))

	for _, c := range checks {
		key := strings.ToLower(strings.TrimSpace(c))
		if skip[key] {
			continue
		}
		if _, isPriority := priorityRank[key]; isPriority {
			prioritised = append(prioritised, c)
		} else {
			remainder = append(remainder, c)
		}
	}

	// Stable-sort prioritised slice by rank.
	for i := 0; i < len(prioritised)-1; i++ {
		for j := i + 1; j < len(prioritised); j++ {
			ri := priorityRank[strings.ToLower(prioritised[i])]
			rj := priorityRank[strings.ToLower(prioritised[j])]
			if ri > rj {
				prioritised[i], prioritised[j] = prioritised[j], prioritised[i]
			}
		}
	}

	return append(prioritised, remainder...)
}

// ShouldSkip reports whether the named check appears in the skip list.
// The comparison is case-insensitive. Always returns false for zero advice.
func ShouldSkip(advice ai.AgentAdvice, check string) bool {
	check = strings.ToLower(strings.TrimSpace(check))
	for _, s := range advice.SkipChecks {
		if strings.ToLower(strings.TrimSpace(s)) == check {
			return true
		}
	}
	return false
}

// encodeAdvice serialises AgentAdvice to JSON for storage as a SharedScanContext
// note. Returns empty string when the advice carries no actionable content.
func encodeAdvice(advice ai.AgentAdvice) string {
	if len(advice.PriorityChecks) == 0 && len(advice.SkipChecks) == 0 &&
		len(advice.FocusEndpoints) == 0 && advice.Rationale == "" && advice.Thinking == "" {
		return ""
	}
	b, err := json.Marshal(advice)
	if err != nil {
		return ""
	}
	return string(b)
}

// buildLesson synthesises a concise, blackboard-ready string describing what
// the named agent confirmed so that subsequent agents can read it and avoid
// duplicating work or can pivot to exploit confirmed weaknesses.
func buildLesson(agentName string, findings []model.Finding, adviceRationale string) string {
	if len(findings) == 0 {
		if strings.TrimSpace(adviceRationale) != "" {
			return fmt.Sprintf("%s: no new findings (context: %s)", agentName, adviceRationale)
		}
		return ""
	}
	cats := make([]string, 0, len(findings))
	seen := map[string]bool{}
	for _, f := range findings {
		c := strings.ToLower(strings.TrimSpace(f.Category))
		if c != "" && !seen[c] {
			cats = append(cats, c)
			seen[c] = true
		}
	}
	return fmt.Sprintf("%s confirmed %d finding(s) in: %s",
		agentName, len(findings), strings.Join(cats, ", "))
}
