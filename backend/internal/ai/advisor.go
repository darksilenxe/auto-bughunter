package ai

import (
	"context"
	"encoding/json"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// AgentAdvice is the structured guidance the AI advisor generates for a
// specific agent before it runs. It steers the agent toward the highest-value
// checks given what prior agents found and what the shared blackboard reports.
type AgentAdvice struct {
	// PriorityChecks lists check names to run first (highest-value given
	// current evidence). Order matters: index 0 = highest priority. All
	// names must come from the availableChecks list supplied to AdviseAgent.
	PriorityChecks []string `json:"priorityChecks"`
	// SkipChecks lists check names to omit entirely because they are already
	// confirmed by prior agents, clearly inapplicable to the detected tech
	// stack, or historically no-signal on this target class.
	SkipChecks []string `json:"skipChecks"`
	// FocusEndpoints are specific URLs the agent should target first when it
	// has endpoint-level granularity. May be empty.
	FocusEndpoints []string `json:"focusEndpoints"`
	// Rationale is a 1-2 sentence plain-English explanation of the guidance.
	Rationale string `json:"rationale"`
	// Thinking is the AI's chain-of-thought reasoning produced before it
	// committed to the guidance. Shown in the operator console as a
	// ScanEventThinking event so operators can follow the agent's reasoning.
	Thinking string `json:"thinking"`
}

// AdviseAgent asks the fast AI model what the named agent should prioritise
// given the current scan findings and shared blackboard context. The response
// is returned as a structured AgentAdvice so any static agent can reorder and
// filter its checks accordingly.
//
// Returns zero-value AgentAdvice (not an error) when the AI provider is
// unavailable, returns an unrecognised response, or the context is cancelled.
// Callers should proceed with their default check order in that case.
func (c *Client) AdviseAgent(
	ctx context.Context,
	agentName string,
	target string,
	availableChecks []string,
	findings []model.Finding,
	blackboard string,
) AgentAdvice {
	if c == nil || !c.shouldCallProvider() {
		return AgentAdvice{}
	}

	// Build a compact finding summary to keep the prompt small.
	findingSummary := make([]map[string]string, 0, len(findings))
	for _, f := range findings {
		findingSummary = append(findingSummary, map[string]string{
			"category": f.Category,
			"severity": string(f.Severity),
			"title":    f.Title,
		})
	}

	systemPrompt := "You are an expert penetration tester advising a security scanning agent. " +
		"Reply with strict JSON only."

	instructions := "You are advising the '" + agentName + "' security-scanning agent before it runs. " +
		"Given the prior findings and scan context, decide:\n" +
		"1. Which checks from availableChecks should run FIRST (highest business-impact signal).\n" +
		"2. Which checks can be SKIPPED entirely (already confirmed by a prior agent, clearly inapplicable " +
		"to the detected tech stack, or consistently no-signal on this target type).\n" +
		"3. Any specific endpoint URLs to focus on (may be empty).\n" +
		"Rules:\n" +
		"- priorityChecks and skipChecks must only contain names from availableChecks.\n" +
		"- A check that is in skipChecks must not also appear in priorityChecks.\n" +
		"- When in doubt, include a check rather than skipping it (false negatives are worse than redundancy).\n" +
		"- Bias toward checks that match tech-stack signals in the blackboard or categories already " +
		"partially signalled by prior findings (e.g. near-miss or WAF-blocked).\n" +
		"Reply with strict JSON only: " +
		`{"thinking":string,"priorityChecks":[string],"skipChecks":[string],"focusEndpoints":[string],"rationale":string}`

	payload := map[string]any{
		"agentName":       agentName,
		"target":          target,
		"availableChecks": availableChecks,
		"priorFindings":   findingSummary,
		"blackboard":      strings.TrimSpace(blackboard),
		"instructions":    instructions,
	}

	userJSON, err := json.Marshal(payload)
	if err != nil {
		return AgentAdvice{}
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: string(userJSON)},
	}

	content, err := c.fastComplete(ctx, messages, 0.1, true)
	if err != nil || strings.TrimSpace(content) == "" {
		return AgentAdvice{}
	}

	var advice AgentAdvice
	if err := json.Unmarshal([]byte(stripCodeFence(content)), &advice); err != nil {
		return AgentAdvice{}
	}

	// Sanitise: ensure every returned name is actually in availableChecks.
	avail := make(map[string]bool, len(availableChecks))
	for _, c := range availableChecks {
		avail[strings.ToLower(strings.TrimSpace(c))] = true
	}
	advice.PriorityChecks = filterToAvailable(advice.PriorityChecks, avail)
	advice.SkipChecks = filterToAvailable(advice.SkipChecks, avail)

	return advice
}

// filterToAvailable removes any check name that is not in the available set,
// and deduplicates. Returns nil when the result would be empty.
func filterToAvailable(checks []string, avail map[string]bool) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		key := strings.ToLower(strings.TrimSpace(c))
		if key == "" || !avail[key] || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
