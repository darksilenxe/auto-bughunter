package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/impact"
	"auto-bughunter/backend/internal/model"
)

// Plan asks the configured AI provider which agents should run next given the
// current findings, agent execution history, and the menu of available
// agents. It returns the parsed agent specs (each a map with name/reason
// keys) and a done flag that signals the orchestration loop should stop.
//
// The method always returns done=true with a nil error when the AI provider
// is not configured so callers can fall back to a deterministic planner
// without needing to special-case the offline mode.
func (c *Client) Plan(ctx context.Context, target string, findings []any, history []map[string]string, availableAgents []string, goals []model.ImpactGoal) ([]map[string]string, bool, error) {
	if c == nil {
		return nil, true, nil
	}
	if !c.shouldCallProvider() {
		return nil, true, nil
	}
	if len(availableAgents) == 0 {
		return nil, true, nil
	}

	userPayload := map[string]any{
		"target":           target,
		"findings":         findings,
		"history":          history,
		"available_agents": availableAgents,
		"impact_goals":     impact.GoalPrompt(goals),
		"impact_playbooks": impact.PlaybookPrompt(goals),
		"instructions": "Pick zero or more agents to run next from the available_agents list. " +
			"You may repeat agents from history when new findings warrant it. " +
			"Bias toward agents that can prove business impact matching impact_goals. " +
			"Set done=true once additional agents are unlikely to surface new value. " +
			"Reply with strict JSON only: {\"agents\":[{\"name\":string,\"reason\":string}],\"done\":bool}",
	}
	userJSON, err := json.Marshal(userPayload)
	if err != nil {
		return nil, true, err
	}

	messages := []Message{
		{Role: "system", Content: buildPlannerSystemPrompt(target, goals)},
		{Role: "user", Content: string(userJSON)},
	}
	content, err := c.planningComplete(ctx, messages, 0.1, true)
	if err != nil {
		return nil, true, err
	}
	if content == "" {
		return nil, true, nil
	}

	var parsed struct {
		Agents []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"agents"`
		Done bool `json:"done"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil, true, fmt.Errorf("ai planner: parse: %w", err)
	}

	specs := make([]map[string]string, 0, len(parsed.Agents))
	for _, a := range parsed.Agents {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			continue
		}
		specs = append(specs, map[string]string{
			"name":   name,
			"reason": strings.TrimSpace(a.Reason),
		})
	}
	return specs, parsed.Done, nil
}

// buildPlannerSystemPrompt builds the AI planner system prompt, injecting a
// domain-specific profile pack when the target URL matches a known domain.
func buildPlannerSystemPrompt(target string, goals []model.ImpactGoal) string {
	base := "You are an autonomous defensive AppSec orchestrator. Decide which scanning/analysis agents to run next. Reply with strict JSON."
	base += "\n\nCurrent impact goals: " + impact.GoalPrompt(goals) + "."
	if playbooks := impact.PlaybookPrompt(goals); playbooks != "" {
		base += "\nReusable impact playbooks: " + playbooks
	}
	if pack := SelectDomainProfile(target); pack != nil {
		base += "\n\nDOMAIN CONTEXT (" + pack.Name + "): " + pack.SystemInstruction
	}
	return base
}

func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```JSON")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
