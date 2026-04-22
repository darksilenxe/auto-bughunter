package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// openAIProvider implements Provider for OpenAI-compatible chat/completions
// endpoints.  This covers OpenAI itself, Azure OpenAI, local Ollama, and any
// other endpoint that exposes the /chat/completions route with OpenAI-style
// request/response JSON.
type openAIProvider struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func (p *openAIProvider) Complete(ctx context.Context, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
	msgs := make([]map[string]string, 0, len(messages))
	for _, m := range messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	payload := map[string]any{
		"model":       model,
		"messages":    msgs,
		"temperature": temperature,
	}
	if jsonMode {
		payload["response_format"] = map[string]string{"type": "json_object"}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("openai: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("openai: request: %w", err)
	}
	if strings.TrimSpace(p.apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("openai: status %d", resp.StatusCode)
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("openai: decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("openai: empty choices")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}
