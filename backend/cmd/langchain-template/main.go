package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/openai"
)

const defaultSystemPrompt = "You are a helpful Go tooling assistant. Use the available tools when they add concrete value, and keep responses concise and actionable."

type config struct {
	APIToken      string
	BaseURL       string
	Model         string
	SystemPrompt  string
	UserPrompt    string
	MaxToolRounds int
	Timeout       time.Duration
	ListToolsOnly bool
}

type toolDefinition struct {
	Name        string
	Description string
	Parameters  map[string]any
	Handler     func(context.Context, json.RawMessage) (string, error)
}

type toolRegistry map[string]toolDefinition

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "langchain-template:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseConfig(args, os.Environ())
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	registry := starterTools()
	if cfg.ListToolsOnly {
		printTools(stdout, registry)
		return nil
	}

	if strings.TrimSpace(cfg.APIToken) == "" {
		return errors.New("set AI_API_KEY or OPENAI_API_KEY before running the template")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	llm, err := openai.New(buildModelOptions(cfg)...)
	if err != nil {
		return fmt.Errorf("create llm: %w", err)
	}

	history := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, cfg.SystemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, cfg.UserPrompt),
	}

	for round := 0; round < cfg.MaxToolRounds; round++ {
		resp, err := llm.GenerateContent(ctx, history, llms.WithTools(registry.specs()))
		if err != nil {
			return fmt.Errorf("generate content: %w", err)
		}
		if len(resp.Choices) == 0 {
			return errors.New("model returned no choices")
		}

		history = appendAssistantMessage(history, resp.Choices[0])
		if len(resp.Choices[0].ToolCalls) == 0 {
			_, err := fmt.Fprintln(stdout, strings.TrimSpace(resp.Choices[0].Content))
			return err
		}

		history, err = registry.executeToolCalls(ctx, history, resp.Choices[0].ToolCalls)
		if err != nil {
			return err
		}
	}

	return fmt.Errorf("stopped after %d tool rounds; increase -max-tool-rounds if needed", cfg.MaxToolRounds)
}

func parseConfig(args, env []string) (config, error) {
	cfg := config{
		APIToken:      envValue(env, "AI_API_KEY", "OPENAI_API_KEY"),
		BaseURL:       envValue(env, "AI_API_BASE", "OPENAI_BASE_URL", "OPENAI_API_BASE"),
		Model:         defaultValue(envValue(env, "AI_MODEL", "OPENAI_MODEL"), "gpt-4o-mini"),
		SystemPrompt:  defaultSystemPrompt,
		UserPrompt:    "Use the available tools to explain this starter template and suggest the next custom tool to implement.",
		MaxToolRounds: 3,
		Timeout:       60 * time.Second,
	}

	fs := flag.NewFlagSet("langchain-template", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.APIToken, "api-key", cfg.APIToken, "OpenAI-compatible API key")
	fs.StringVar(&cfg.BaseURL, "base-url", cfg.BaseURL, "OpenAI-compatible base URL")
	fs.StringVar(&cfg.Model, "model", cfg.Model, "Model name")
	fs.StringVar(&cfg.SystemPrompt, "system", cfg.SystemPrompt, "System prompt")
	fs.StringVar(&cfg.UserPrompt, "prompt", cfg.UserPrompt, "User prompt")
	fs.IntVar(&cfg.MaxToolRounds, "max-tool-rounds", cfg.MaxToolRounds, "Maximum tool call rounds")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Overall request timeout")
	fs.BoolVar(&cfg.ListToolsOnly, "list-tools", false, "Print the starter tools and exit")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	cfg.APIToken = strings.TrimSpace(cfg.APIToken)
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.Model = strings.TrimSpace(cfg.Model)
	cfg.SystemPrompt = strings.TrimSpace(cfg.SystemPrompt)
	cfg.UserPrompt = strings.TrimSpace(cfg.UserPrompt)
	if cfg.UserPrompt == "" {
		return config{}, errors.New("prompt cannot be empty")
	}
	if cfg.MaxToolRounds <= 0 {
		return config{}, errors.New("max-tool-rounds must be greater than zero")
	}
	if cfg.Timeout <= 0 {
		return config{}, errors.New("timeout must be greater than zero")
	}
	return cfg, nil
}

func buildModelOptions(cfg config) []openai.Option {
	opts := []openai.Option{
		openai.WithToken(cfg.APIToken),
		openai.WithModel(cfg.Model),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, openai.WithBaseURL(cfg.BaseURL))
	}
	return opts
}

func starterTools() toolRegistry {
	return toolRegistry{
		"echo": {
			Name:        "echo",
			Description: "Return text so you can verify tool-calling and argument parsing end-to-end.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "Text to echo back to the model.",
					},
				},
				"required": []string{"text"},
			},
			Handler: func(_ context.Context, raw json.RawMessage) (string, error) {
				var args struct {
					Text string `json:"text"`
				}
				if err := json.Unmarshal(raw, &args); err != nil {
					return "", fmt.Errorf("decode echo args: %w", err)
				}
				return marshalToolResult(map[string]any{"echo": strings.TrimSpace(args.Text)})
			},
		},
		"current_time": {
			Name:        "current_time",
			Description: "Return the current time in UTC or in a supplied IANA timezone.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"timezone": map[string]any{
						"type":        "string",
						"description": "Optional IANA timezone such as America/New_York.",
					},
				},
			},
			Handler: func(_ context.Context, raw json.RawMessage) (string, error) {
				var args struct {
					Timezone string `json:"timezone"`
				}
				if err := json.Unmarshal(raw, &args); err != nil {
					return "", fmt.Errorf("decode current_time args: %w", err)
				}
				location := time.UTC
				if tz := strings.TrimSpace(args.Timezone); tz != "" {
					loaded, err := time.LoadLocation(tz)
					if err != nil {
						return "", fmt.Errorf("load timezone %q: %w", tz, err)
					}
					location = loaded
				}
				now := time.Now().In(location)
				return marshalToolResult(map[string]any{
					"timestamp": now.Format(time.RFC3339),
					"timezone":  location.String(),
				})
			},
		},
		"repo_overview": {
			Name:        "repo_overview",
			Description: "Return a compact summary of this repository so you can wire context-aware tools later.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			Handler: func(_ context.Context, _ json.RawMessage) (string, error) {
				return marshalToolResult(map[string]any{
					"name":    "auto-bughunter",
					"backend": "Go API orchestrator under backend/",
					"services": []string{
						"frontend/ React + Vite UI",
						"ml-service/ FastAPI ML scoring service",
						"langchain-service/ FastAPI LangChain sidecar",
					},
					"starter_hint": "Replace these sample tools with your own API clients, database calls, or internal automation.",
				})
			},
		},
	}
}

func (r toolRegistry) specs() []llms.Tool {
	names := make([]string, 0, len(r))
	for name := range r {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]llms.Tool, 0, len(names))
	for _, name := range names {
		tool := r[name]
		out = append(out, llms.Tool{
			Type: "function",
			Function: &llms.FunctionDefinition{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  tool.Parameters,
			},
		})
	}
	return out
}

func (r toolRegistry) executeToolCalls(ctx context.Context, history []llms.MessageContent, calls []llms.ToolCall) ([]llms.MessageContent, error) {
	for _, call := range calls {
		if call.FunctionCall == nil {
			return nil, errors.New("tool call missing function payload")
		}
		tool, ok := r[call.FunctionCall.Name]
		if !ok {
			return nil, fmt.Errorf("unsupported tool %q", call.FunctionCall.Name)
		}

		result, err := tool.Handler(ctx, json.RawMessage(call.FunctionCall.Arguments))
		if err != nil {
			return nil, fmt.Errorf("tool %q failed: %w", call.FunctionCall.Name, err)
		}

		history = append(history, llms.MessageContent{
			Role: llms.ChatMessageTypeTool,
			Parts: []llms.ContentPart{
				llms.ToolCallResponse{
					ToolCallID: call.ID,
					Name:       call.FunctionCall.Name,
					Content:    result,
				},
			},
		})
	}
	return history, nil
}

func appendAssistantMessage(history []llms.MessageContent, choice *llms.ContentChoice) []llms.MessageContent {
	message := llms.MessageContent{Role: llms.ChatMessageTypeAI}
	if content := strings.TrimSpace(choice.Content); content != "" {
		message.Parts = append(message.Parts, llms.TextContent{Text: content})
	}
	for _, call := range choice.ToolCalls {
		message.Parts = append(message.Parts, call)
	}
	return append(history, message)
}

func printTools(w io.Writer, registry toolRegistry) {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tool := registry[name]
		fmt.Fprintf(w, "%s: %s\n", tool.Name, tool.Description)
	}
}

func marshalToolResult(v any) (string, error) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func envValue(env []string, keys ...string) string {
	for _, key := range keys {
		prefix := key + "="
		for _, item := range env {
			if strings.HasPrefix(item, prefix) {
				return strings.TrimSpace(strings.TrimPrefix(item, prefix))
			}
		}
	}
	return ""
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
