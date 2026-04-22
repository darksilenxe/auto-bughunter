package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// geminiProvider implements Provider for the Google Gemini generateContent API.
// Reference: https://ai.google.dev/api/generate-content
//
// Wire differences from OpenAI:
//   - URL:  POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={apiKey}
//   - Auth: API key in query parameter (not Authorization header)
//   - Request shape: {systemInstruction:{parts:[{text}]}, contents:[{role, parts:[{text}]}]}
//   - Response shape: {candidates:[{content:{parts:[{text}]}}]}
type geminiProvider struct {
	apiKey string
	http   *http.Client
}

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/models"

func (p *geminiProvider) Complete(ctx context.Context, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
	// Separate system instructions from conversation turns.
	var systemText string
	contents := make([]map[string]any, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			if systemText != "" {
				systemText += "\n"
			}
			systemText += m.Content
			continue
		}
		// Gemini uses "user" and "model" (not "assistant").
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		contents = append(contents, map[string]any{
			"role":  role,
			"parts": []map[string]string{{"text": m.Content}},
		})
	}

	if jsonMode && len(contents) > 0 {
		last := contents[len(contents)-1]
		parts, _ := last["parts"].([]map[string]string)
		if len(parts) > 0 && !strings.Contains(strings.ToLower(parts[0]["text"]), "json") {
			parts[0]["text"] += "\n\nReply with strict JSON only."
		}
	}

	payload := map[string]any{
		"contents": contents,
		"generationConfig": map[string]any{
			"temperature": temperature,
		},
	}
	if systemText != "" {
		payload["systemInstruction"] = map[string]any{
			"parts": []map[string]string{{"text": systemText}},
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("gemini: marshal: %w", err)
	}

	url := fmt.Sprintf("%s/%s:generateContent?key=%s", geminiBaseURL, model, p.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("gemini: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("gemini: status %d", resp.StatusCode)
	}

	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("gemini: decode: %w", err)
	}
	for _, cand := range out.Candidates {
		for _, part := range cand.Content.Parts {
			if t := strings.TrimSpace(part.Text); t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("gemini: no text in response")
}
