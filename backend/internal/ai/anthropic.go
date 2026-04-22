package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// anthropicProvider implements Provider for the Anthropic Messages API.
// Reference: https://docs.anthropic.com/en/api/messages
//
// Wire differences from OpenAI:
//   - URL:  POST {baseURL}/messages
//   - Auth: x-api-key header (not Bearer)
//   - system messages are a top-level field, not an item in messages[]
//   - Response shape: {"content":[{"type":"text","text":"..."}]}
type anthropicProvider struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

const anthropicVersion = "2023-06-01"
const anthropicMaxTokens = 4096

func (p *anthropicProvider) Complete(ctx context.Context, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
	// Extract leading system message(s); the Anthropic API takes system as a
	// separate top-level string, not as a message role.
	var systemContent string
	userMessages := make([]map[string]string, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			if systemContent != "" {
				systemContent += "\n"
			}
			systemContent += m.Content
			continue
		}
		userMessages = append(userMessages, map[string]string{
			"role":    m.Role,
			"content": m.Content,
		})
	}

	// When JSON mode is requested, append an instruction to the last user
	// message.  Anthropic does not have a dedicated response_format field
	// in the same way, but injecting the instruction is highly effective.
	if jsonMode && len(userMessages) > 0 {
		last := userMessages[len(userMessages)-1]
		if !strings.Contains(strings.ToLower(last["content"]), "json") {
			last["content"] += "\n\nReply with strict JSON only."
			userMessages[len(userMessages)-1] = last
		}
	}

	payload := map[string]any{
		"model":       model,
		"max_tokens":  anthropicMaxTokens,
		"temperature": temperature,
		"messages":    userMessages,
	}
	if systemContent != "" {
		payload["system"] = systemContent
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("anthropic: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("anthropic: request: %w", err)
	}
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("anthropic: status %d", resp.StatusCode)
	}

	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("anthropic: decode: %w", err)
	}
	for _, block := range out.Content {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			return strings.TrimSpace(block.Text), nil
		}
	}
	return "", fmt.Errorf("anthropic: no text block in response")
}
