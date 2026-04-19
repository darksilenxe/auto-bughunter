package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

type Client struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
}

func NewClient(baseURL, apiKey, model string) *Client {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Model:   model,
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) Summarize(ctx context.Context, target string, findings []model.Finding) string {
	return c.SummarizeWithKnowledge(ctx, target, findings, nil)
}

func (c *Client) SummarizeWithKnowledge(ctx context.Context, target string, findings []model.Finding, knowledge *model.SecurityKnowledgeContext) string {
	if !c.shouldCallProvider() {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}

	payload := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a defensive AppSec assistant. Summarize scanner findings for authorized remediation only. Use supplied curated references as supporting context, and preserve citations as source titles plus URLs.",
			},
			{
				"role":    "user",
				"content": fmt.Sprintf("Target: %s\nFindings JSON: %s\nKnowledge Context JSON: %s\nProvide: 1) risk summary 2) top 3 priorities 3) remediation sequence 4) supporting citations when knowledge context is present.", target, mustJSON(findings), mustJSON(knowledge)),
			},
		},
		"temperature": 0.2,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}
	if strings.TrimSpace(c.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}
	return out.Choices[0].Message.Content
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func (c *Client) shouldCallProvider() bool {
	// Keep OpenAI default behavior: require an API key.
	const defaultOpenAIBase = "https://api.openai.com/v1"
	base := strings.TrimRight(strings.ToLower(strings.TrimSpace(c.BaseURL)), "/")
	if strings.TrimSpace(c.APIKey) != "" {
		return true
	}
	return base != strings.ToLower(defaultOpenAIBase)
}
