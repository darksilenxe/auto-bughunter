package scanner

import (
	"context"
	"fmt"
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
	"langchain",
	"openai",
	"anthropic",
	"\"gpt-",
	"\"claude-",
	"chatgpt",
	"copilot",
	"llm",
	"llmchain",
	"embeddings",
	"langsmith",
	"huggingface",
	"cohere",
	"mistral",
	"ollama",
	"bedrock",
	"vertexai",
	"generativeai",
}

// aiAgentHTMLIndicators are UI-level patterns found in pages that embed an
// AI chat widget or assistant interface.
var aiAgentHTMLIndicators = []string{
	"chat with ai",
	"ask ai",
	"ai assistant",
	"powered by openai",
	"powered by claude",
	"powered by gpt",
	"chatgpt",
	"your ai",
	"ai chat",
	`data-ai-widget`,
	`class="chat-widget`,
	`id="ai-assistant`,
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
	// 1. Check baseline response headers.
	if input.Session != nil {
		// We don't have direct access to the baseline response headers here,
		// but callers may pre-populate DetectedTech or we re-probe below.
	}

	bodyLower := strings.ToLower(baseBody)

	// 2. JavaScript keyword scan in baseline body.
	for _, kw := range aiAgentJSKeywords {
		if strings.Contains(bodyLower, strings.ToLower(kw)) {
			signals = append(signals, AIAgentSignal{Source: "js-keyword", Detail: kw, Weight: 2})
		}
	}

	// 3. HTML indicator scan.
	for _, ind := range aiAgentHTMLIndicators {
		if strings.Contains(bodyLower, strings.ToLower(ind)) {
			signals = append(signals, AIAgentSignal{Source: "html", Detail: ind, Weight: 2})
		}
	}

	// 4. Streaming body marker scan.
	for _, m := range aiAgentStreamingMarkers {
		if strings.Contains(bodyLower, strings.ToLower(m)) {
			signals = append(signals, AIAgentSignal{Source: "streaming", Detail: m, Weight: 4})
		}
	}

	// 5. Probe well-known AI endpoint paths (cap at 6 to limit noise).
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
		_ = resp.Body.Close()
		// 200, 401, or 405 all indicate the path exists behind the server.
		if resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusMethodNotAllowed ||
			resp.StatusCode == http.StatusForbidden {
			signals = append(signals, AIAgentSignal{
				Source:  "endpoint",
				Detail:  fmt.Sprintf("%s → HTTP %d", suffix, resp.StatusCode),
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
	// Threshold: ≥4 combined weight → confident detection.
	detected = total >= 4
	return signals, detected
}

// runAIAgentDetectProbe runs the AI agent fingerprinter as a scanner probe and
// surfaces a low-severity informational finding when the target is confirmed to
// expose an LLM-backed interface. The finding annotates DetectedTech so
// downstream probes (prompt injection, disclosure, etc.) can gate themselves.
func (s *Service) runAIAgentDetectProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		// Passive-only scans: still run the body/header analysis but skip
		// active endpoint probes by temporarily forcing that limit to zero.
		// We achieve this by scanning keywords only.
		bodyLower := strings.ToLower(body)
		weight := 0
		var details []string
		for _, kw := range aiAgentJSKeywords {
			if strings.Contains(bodyLower, strings.ToLower(kw)) {
				weight += 2
				details = append(details, kw)
			}
		}
		for _, ind := range aiAgentHTMLIndicators {
			if strings.Contains(bodyLower, strings.ToLower(ind)) {
				weight += 2
				details = append(details, ind)
			}
		}
		if weight < 4 {
			return nil
		}
		if input.DetectedTech.techs == nil {
			input.DetectedTech.techs = make(map[string]struct{})
		}
		input.DetectedTech.techs["ai-agent"] = struct{}{}
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
