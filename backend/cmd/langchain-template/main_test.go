package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tmc/langchaingo/llms"
)

func TestParseConfigUsesRepositoryEnvFallbacks(t *testing.T) {
	t.Parallel()

	cfg, err := parseConfig(nil, []string{
		"AI_API_KEY=test-key",
		"AI_MODEL=test-model",
		"AI_API_BASE=https://llm.example.test/v1",
	})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if cfg.APIToken != "test-key" {
		t.Fatalf("APIToken = %q", cfg.APIToken)
	}
	if cfg.Model != "test-model" {
		t.Fatalf("Model = %q", cfg.Model)
	}
	if cfg.BaseURL != "https://llm.example.test/v1" {
		t.Fatalf("BaseURL = %q", cfg.BaseURL)
	}
}

func TestParseConfigRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	_, err := parseConfig([]string{"-max-tool-rounds=0"}, nil)
	if err == nil || !strings.Contains(err.Error(), "max-tool-rounds") {
		t.Fatalf("expected max-tool-rounds error, got %v", err)
	}

	_, err = parseConfig([]string{"-timeout=0s"}, nil)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestExecuteToolCallsAppendsResponses(t *testing.T) {
	t.Parallel()

	registry := starterTools()
	history, err := registry.executeToolCalls(context.Background(), nil, []llms.ToolCall{
		{
			ID:   "call-1",
			Type: "function",
			FunctionCall: &llms.FunctionCall{
				Name:      "echo",
				Arguments: `{"text":"hello"}`,
			},
		},
		{
			ID:   "call-2",
			Type: "function",
			FunctionCall: &llms.FunctionCall{
				Name:      "current_time",
				Arguments: `{"timezone":"UTC"}`,
			},
		},
	})
	if err != nil {
		t.Fatalf("executeToolCalls() error = %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history length = %d, want 2", len(history))
	}
	if history[0].Role != llms.ChatMessageTypeTool {
		t.Fatalf("history[0].Role = %v", history[0].Role)
	}
	got := history[0].Parts[0].(llms.ToolCallResponse).Content
	if !strings.Contains(got, `"echo": "hello"`) {
		t.Fatalf("unexpected echo content: %s", got)
	}
	timePayload := history[1].Parts[0].(llms.ToolCallResponse).Content
	if !strings.Contains(timePayload, `"timezone": "UTC"`) {
		t.Fatalf("unexpected current_time content: %s", timePayload)
	}
}

func TestExecuteToolCallsRejectsUnknownTool(t *testing.T) {
	t.Parallel()

	_, err := starterTools().executeToolCalls(context.Background(), nil, []llms.ToolCall{
		{
			ID:   "call-1",
			Type: "function",
			FunctionCall: &llms.FunctionCall{
				Name:      "missing_tool",
				Arguments: `{}`,
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `unsupported tool "missing_tool"`) {
		t.Fatalf("expected unsupported tool error, got %v", err)
	}
}

func TestAppendAssistantMessageKeepsToolCalls(t *testing.T) {
	t.Parallel()

	history := appendAssistantMessage(nil, &llms.ContentChoice{
		Content: "thinking",
		ToolCalls: []llms.ToolCall{
			{
				ID:           "call-1",
				Type:         "function",
				FunctionCall: &llms.FunctionCall{Name: "echo", Arguments: `{"text":"hi"}`},
			},
		},
	})
	if len(history) != 1 {
		t.Fatalf("history length = %d", len(history))
	}
	if history[0].Role != llms.ChatMessageTypeAI {
		t.Fatalf("history role = %v", history[0].Role)
	}
	if len(history[0].Parts) != 2 {
		t.Fatalf("assistant parts = %d", len(history[0].Parts))
	}
}

func TestDefaultValue(t *testing.T) {
	t.Parallel()

	if got := defaultValue("", "fallback"); got != "fallback" {
		t.Fatalf("defaultValue empty = %q", got)
	}
	if got := defaultValue("set", "fallback"); got != "set" {
		t.Fatalf("defaultValue set = %q", got)
	}
}

func TestCurrentTimeToolAcceptsUTC(t *testing.T) {
	t.Parallel()

	result, err := starterTools()["current_time"].Handler(context.Background(), []byte(`{"timezone":"UTC"}`))
	if err != nil {
		t.Fatalf("current_time handler error = %v", err)
	}
	if !strings.Contains(result, `"timezone": "UTC"`) {
		t.Fatalf("current_time result = %s", result)
	}
	if _, err := time.Parse(time.RFC3339, extractTimestamp(result)); err != nil {
		t.Fatalf("timestamp parse error = %v", err)
	}
}

func extractTimestamp(payload string) string {
	const marker = `"timestamp": "`
	start := strings.Index(payload, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.Index(payload[start:], `"`)
	if end < 0 {
		return ""
	}
	return payload[start : start+end]
}
