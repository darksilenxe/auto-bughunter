package ai

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Message is a single turn in a multi-turn chat conversation.
type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
}

// Provider abstracts an LLM backend.  Implementations translate the
// provider-agnostic Message slice into the backend's native wire format,
// make the HTTP request, and return the model's first-choice text response.
//
// jsonMode is a best-effort hint: providers that support JSON-only output
// natively (OpenAI response_format, Anthropic prefilling) honour it; others
// receive an extra instruction in the final user message.
type Provider interface {
	Complete(ctx context.Context, model string, messages []Message, temperature float64, jsonMode bool) (string, error)
}

// ProviderName identifies the LLM backend.
type ProviderName string

const (
	ProviderOpenAI    ProviderName = "openai"
	ProviderAnthropic ProviderName = "anthropic"
	ProviderGemini    ProviderName = "gemini"
	ProviderBedrock   ProviderName = "bedrock"
)

// defaultHTTPClient is shared across provider instances when the caller does
// not supply a custom client.
var defaultHTTPClient = &http.Client{Timeout: 20 * time.Second}

// DetectProvider infers the ProviderName from the base URL and API key.
// Heuristics (in order):
//  1. API key starting with "sk-ant-"  → Anthropic
//  2. API key starting with "AIzaSy"   → Gemini
//  3. Base URL containing "bedrock"    → Bedrock
//  4. Explicit name match in baseURL   → e.g. "gemini", "anthropic"
//  5. Everything else                  → OpenAI-compatible (covers Ollama)
func DetectProvider(baseURL, apiKey string) ProviderName {
	key := strings.TrimSpace(apiKey)
	if strings.HasPrefix(key, "sk-ant-") {
		return ProviderAnthropic
	}
	if strings.HasPrefix(key, "AIzaSy") {
		return ProviderGemini
	}
	lower := strings.ToLower(strings.TrimSpace(baseURL))
	if strings.Contains(lower, "bedrock-runtime") || strings.Contains(lower, "bedrock") {
		return ProviderBedrock
	}
	if strings.Contains(lower, "anthropic.com") {
		return ProviderAnthropic
	}
	if strings.Contains(lower, "generativelanguage.googleapis.com") || strings.Contains(lower, "gemini") {
		return ProviderGemini
	}
	return ProviderOpenAI
}

// NewProvider constructs the appropriate Provider implementation.
// httpClient may be nil (uses a package-level default).
func NewProvider(name ProviderName, baseURL, apiKey string, httpClient *http.Client) Provider {
	if httpClient == nil {
		httpClient = defaultHTTPClient
	}
	switch name {
	case ProviderAnthropic:
		u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if u == "" {
			u = "https://api.anthropic.com/v1"
		}
		return &anthropicProvider{baseURL: u, apiKey: apiKey, http: httpClient}
	case ProviderGemini:
		return &geminiProvider{apiKey: apiKey, http: httpClient}
	case ProviderBedrock:
		// baseURL is reused as the AWS region for Bedrock.
		region := strings.TrimSpace(baseURL)
		if region == "" {
			region = "us-east-1"
		}
		return &bedrockProvider{region: region, http: httpClient}
	default:
		u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if u == "" {
			u = "https://api.openai.com/v1"
		}
		return &openAIProvider{baseURL: u, apiKey: apiKey, http: httpClient}
	}
}
