package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Plan asks the configured AI provider which agents should run next given the
// current findings, agent execution history, and the menu of available
// agents. It returns the parsed agent specs (each a map with name/reason
// keys) and a done flag that signals the orchestration loop should stop.
//
// The method always returns done=true with a nil error when the AI provider
// is not configured so callers can fall back to a deterministic planner
// without needing to special-case the offline mode.
func (c *Client) Plan(ctx context.Context, target string, findings []any, history []map[string]string, availableAgents []string) ([]map[string]string, bool, error) {
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
		"instructions": "Pick zero or more agents to run next from the available_agents list. " +
			"You may repeat agents from history when new findings warrant it. " +
			"Set done=true once additional agents are unlikely to surface new value. " +
			"Reply with strict JSON only: {\"agents\":[{\"name\":string,\"reason\":string}],\"done\":bool}",
	}
	userJSON, err := json.Marshal(userPayload)
	if err != nil {
		return nil, true, err
	}

	payload := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are an autonomous defensive AppSec orchestrator. Decide which scanning/analysis agents to run next. Reply with strict JSON.",
			},
			{
				"role":    "user",
				"content": string(userJSON),
			},
		},
		"temperature":     0.1,
		"response_format": map[string]string{"type": "json_object"},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, true, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, true, err
	}
	if strings.TrimSpace(c.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, true, fmt.Errorf("ai planner: unexpected status %d", resp.StatusCode)
	}

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, true, err
	}
	if len(apiResp.Choices) == 0 {
		return nil, true, nil
	}

	content := strings.TrimSpace(apiResp.Choices[0].Message.Content)
	if content == "" {
		return nil, true, nil
	}
	content = stripCodeFence(content)

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

// stripCodeFence removes ```json ... ``` wrappers some providers add even when
// asked for a JSON response.
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
