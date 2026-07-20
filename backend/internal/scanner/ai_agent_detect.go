package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// aiAgentEndpoints are URL path suffixes commonly exposed by LLM-backed web
// applications. Presence of a 200/405/401 response on any of these paths is
// treated as a strong signal that the target uses an AI agent backend.
var aiAgentEndpoints = []string{
	"/api/chat",
	"/api/ask",
	"/api/agent",
	"/api/complete",
	"/api/query",
	"/api/generate",
	"/chat",
	"/v1/chat/completions",
	"/v1/completions",
	"/api/v1/chat",
	"/api/v1/agent",
	"/api/copilot",
	"/api/assistant",
}

// aiAgentResponseHeaders are HTTP response header names whose presence
// indicates the response was generated or routed by an LLM service.
var aiAgentResponseHeaders = []string{
	"x-openai-model",
	"x-llm-provider",
	"x-model",
	"x-ai-model",
	"openai-model",
	"anthropic-version",
	"x-anthropic-model",
	"x-groq-model",
	"x-cohere-version",
}

// aiAgentJSKeywords are identifiers that appear in JavaScript bundles of
// applications that embed LLM toolkits. Detected in the baseline HTML body or
// any discovered JavaScript resources.
var aiAgentJSKeywords = []string{
	`require('openai'`,
	`require("openai"`,
	`from 'openai'`,
	`from "openai"`,
	`from '@langchain/`,
	`from "@langchain/`,
	"langchain",
	"llmchain",
	"langsmith",
	"openai.chat.completions",
	"client.chat.completions.create",
	"anthropic.messages.create",
	"assistant_id",
	`"gpt-`,
	`"claude-`,
}

// aiAgentHTMLIndicators are UI-level patterns found in pages that embed an
// AI chat widget or assistant interface.
var aiAgentHTMLIndicators = []string{
	"chat with ai",
	"ai assistant",
	"ai chat",
	`data-ai-widget`,
	`class="chat-widget`,
	`id="ai-assistant`,
	`data-testid="ai-chat`,
}

// aiAgentStreamingMarkers appear in streaming HTTP responses produced by LLM
// APIs (Server-Sent Events or plain chunked bodies).
var aiAgentStreamingMarkers = []string{
	`data: {"choices":`,
	`data: {"id":"chatcmpl`,
	`data: [DONE]`,
	`"object":"chat.completion.chunk"`,
	`"object": "chat.completion"`,
}

var aiAgentEndpointBodyMarkers = []string{
	`"choices"`,
	`"messages"`,
	`"model"`,
	`"usage"`,
	`"object":"chat.completion`,
	`"object": "chat.completion`,
	`"prompt_tokens"`,
}

// AIAgentSignal records a single evidence item collected during fingerprinting.
type AIAgentSignal struct {
	Source  string // e.g. "header", "js-keyword", "endpoint", "html", "streaming"
	Detail  string
	Weight  int // relative confidence contribution
}

// DetectAIAgent fingerprints the target for LLM/AI agent indicators using the
// baseline response body and headers already fetched by Run(), plus lightweight
// probes to known AI endpoint paths. It returns the list of signals found and
// whether the confidence is high enough to classify the target as AI-backed.
//
// The function is deliberately non-blocking: each endpoint probe is bounded by
// a short timeout and the total number of probes is capped.
func (s *Service) DetectAIAgent(ctx context.Context, input RunInput, baseBody string) (signals []AIAgentSignal, detected bool) {
	bodyLower := strings.ToLower(baseBody)

	// 1. JavaScript keyword scan in baseline body.
	for _, kw := range aiAgentJSKeywords {
		if strings.Contains(bodyLower, strings.ToLower(kw)) {
			signals = append(signals, AIAgentSignal{Source: "js-keyword", Detail: kw, Weight: 4})
		}
	}

	// 2. HTML indicator scan.
	for _, ind := range aiAgentHTMLIndicators {
		if strings.Contains(bodyLower, strings.ToLower(ind)) {
			signals = append(signals, AIAgentSignal{Source: "html", Detail: ind, Weight: 1})
		}
	}

	// 3. Streaming body marker scan.
	for _, m := range aiAgentStreamingMarkers {
		if strings.Contains(bodyLower, strings.ToLower(m)) {
			signals = append(signals, AIAgentSignal{Source: "streaming", Detail: m, Weight: 4})
		}
	}

	// 4. Probe well-known AI endpoint paths (cap at 6 to limit noise).
	probeLimit := 6
	tried := 0
	for _, suffix := range aiAgentEndpoints {
		if tried >= probeLimit {
			break
		}
		ep := resolveEndpoint(input.Target, suffix)
		if ep == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		tried++
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if isLikelyAIEndpointResponse(resp, respBody) {
			signals = append(signals, AIAgentSignal{
				Source:  "endpoint",
				Detail:  fmt.Sprintf("%s → HTTP %d (%s)", suffix, resp.StatusCode, sanitizeContentType(resp.Header.Get("Content-Type"))),
				Weight:  4,
			})
		}
		// Header check on each probed response.
		for _, h := range aiAgentResponseHeaders {
			if resp.Header.Get(h) != "" {
				signals = append(signals, AIAgentSignal{
					Source:  "header",
					Detail:  fmt.Sprintf("%s: %s", h, resp.Header.Get(h)),
					Weight:  5,
				})
			}
		}
	}

	// Also check baseline response headers via a fresh HEAD request.
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, input.Target, nil)
	if err == nil {
		ApplyAuthProfile(headReq, input.AuthProfile)
		if headResp, herr := s.doRequestWithRetry(ctx, headReq, input.Options); herr == nil && headResp != nil {
			_ = headResp.Body.Close()
			for _, h := range aiAgentResponseHeaders {
				if headResp.Header.Get(h) != "" {
					signals = append(signals, AIAgentSignal{
						Source:  "header",
						Detail:  fmt.Sprintf("%s: %s", h, headResp.Header.Get(h)),
						Weight:  5,
					})
				}
			}
		}
	}

	// Compute total confidence weight.
	total := 0
	for _, sig := range signals {
		total += sig.Weight
	}
	detected = hasStrongAIAgentSignal(signals) || (len(aiAgentSignalSources(signals)) >= 2 && total >= 5)
	return signals, detected
}

// runAIAgentDetectProbe runs the AI agent fingerprinter as a scanner probe and
// surfaces a low-severity informational finding when the target is confirmed to
// expose an LLM-backed interface. The finding annotates DetectedTech so
// downstream probes (prompt injection, disclosure, etc.) can gate themselves.
func (s *Service) runAIAgentDetectProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		signals := collectPassiveAIAgentSignals(body)
		if !(hasStrongAIAgentSignal(signals) || (len(aiAgentSignalSources(signals)) >= 2 && signalWeight(signals) >= 5)) {
			return nil
		}
		if input.DetectedTech.techs == nil {
			input.DetectedTech.techs = make(map[string]struct{})
		}
		input.DetectedTech.techs["ai-agent"] = struct{}{}
		details := make([]string, 0, len(signals))
		for _, sig := range signals {
			details = append(details, fmt.Sprintf("[%s] %s", sig.Source, sig.Detail))
		}
		return []model.Finding{{
			ID:             "ai-agent-detected-passive",
			Category:       "ai-agent",
			Severity:       model.SeverityInfo,
			Title:          "LLM/AI agent interface detected (passive signals)",
			Description:    "The target page body contains JavaScript keywords or HTML patterns associated with LLM toolkits, indicating an AI agent interface. Active AI vulnerability probes (prompt injection, disclosure, tool abuse) should be run against this target.",
			Evidence:       fmt.Sprintf("Passive signals: %s", strings.Join(details, ", ")),
			Recommendation: "Review all AI-powered endpoints for prompt injection, insecure output handling, and data disclosure vulnerabilities.",
			Confidence:     0.6,
			AffectedURL:    input.Target,
			OWASPCategory:  "OWASP LLM Top 10",
			Sources:        []string{"passive-ai-detect"},
		}}
	}

	func collectPassiveAIAgentSignals(body string) []AIAgentSignal {
		bodyLower := strings.ToLower(body)
		signals := make([]AIAgentSignal, 0, len(aiAgentJSKeywords)+len(aiAgentHTMLIndicators)+len(aiAgentStreamingMarkers))
		for _, kw := range aiAgentJSKeywords {
			if strings.Contains(bodyLower, strings.ToLower(kw)) {
				signals = append(signals, AIAgentSignal{Source: "js-keyword", Detail: kw, Weight: 4})
			}
		}
		for _, ind := range aiAgentHTMLIndicators {
			if strings.Contains(bodyLower, strings.ToLower(ind)) {
				signals = append(signals, AIAgentSignal{Source: "html", Detail: ind, Weight: 1})
			}
		}
		for _, m := range aiAgentStreamingMarkers {
			if strings.Contains(bodyLower, strings.ToLower(m)) {
				signals = append(signals, AIAgentSignal{Source: "streaming", Detail: m, Weight: 4})
			}
		}
		return signals
	}

	func isLikelyAIEndpointResponse(resp *http.Response, body []byte) bool {
		if resp == nil {
			return false
		}
		switch resp.StatusCode {
		case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusMethodNotAllowed:
		default:
			return false
		}
		for _, h := range aiAgentResponseHeaders {
			if resp.Header.Get(h) != "" {
				return true
			}
		}
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		bodyLower := strings.ToLower(string(body))
		if strings.Contains(contentType, "text/event-stream") {
			return true
		}
		if strings.Contains(contentType, "application/json") || strings.Contains(contentType, "application/problem+json") {
			for _, marker := range aiAgentEndpointBodyMarkers {
				if strings.Contains(bodyLower, strings.ToLower(marker)) {
					return true
				}
			}
		}
		return false
	}

	func hasStrongAIAgentSignal(signals []AIAgentSignal) bool {
		for _, sig := range signals {
			switch sig.Source {
			case "header", "streaming", "js-keyword":
				return true
			}
		}
		return false
	}

	func aiAgentSignalSources(signals []AIAgentSignal) map[string]struct{} {
		out := make(map[string]struct{}, len(signals))
		for _, sig := range signals {
			out[sig.Source] = struct{}{}
		}
		return out
	}

	func signalWeight(signals []AIAgentSignal) int {
		total := 0
		for _, sig := range signals {
			total += sig.Weight
		}
		return total
	}

	func sanitizeContentType(contentType string) string {
		if idx := strings.IndexByte(contentType, ';'); idx >= 0 {
			contentType = contentType[:idx]
		}
		return strings.TrimSpace(contentType)
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("ai-detect %s", input.Target),
			Message: "Fingerprinting target for LLM/AI agent indicators",
		})
	}

	signals, detected := s.DetectAIAgent(ctx, input, body)
	if !detected {
		return nil
	}

	// Mark the detection in DetectedTech so subsequent probes gate correctly.
	if input.DetectedTech.techs == nil {
		input.DetectedTech.techs = make(map[string]struct{})
	}
	input.DetectedTech.techs["ai-agent"] = struct{}{}

	// Build evidence summary.
	details := make([]string, 0, len(signals))
	for _, sig := range signals {
		details = append(details, fmt.Sprintf("[%s] %s (w=%d)", sig.Source, sig.Detail, sig.Weight))
	}

	return []model.Finding{{
		ID:             "ai-agent-detected",
		Category:       "ai-agent",
		Severity:       model.SeverityInfo,
		Title:          "LLM/AI agent interface detected",
		Description:    "The target exposes an LLM-backed chat, assistant, or completion interface. Agentic AI applications introduce a distinct class of vulnerabilities including prompt injection, insecure output handling, system prompt disclosure, and excessive agency. All AI-specific probes will now be activated.",
		Evidence:       strings.Join(details, "; "),
		Recommendation: "Apply OWASP LLM Top 10 mitigations: validate and sanitize all user inputs before passing to the model, enforce output encoding on LLM-generated content, restrict agent tool permissions to the minimum required, and protect system prompts from extraction.",
		Confidence:     0.85,
		AffectedURL:    input.Target,
		OWASPCategory:  "OWASP LLM Top 10",
		Sources:        []string{"active-ai-detect"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"signals":        strings.Join(details, "; "),
		},
	}}
}
