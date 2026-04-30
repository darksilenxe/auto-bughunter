package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/impact"
	"auto-bughunter/backend/internal/model"
)

const toolCallDecisionSchema = `{"action":"stop|run_command|run_hacktricks|generate_tool","binary":string,"args":[string],"category":string,"findingId":string,"task":string,"rationale":string,"stopReason":string}`

type Client struct {
	BaseURL string
	APIKey  string
	Model   string
	// Optional larger coding-focused model for orchestration/planning calls.
	CodingBaseURL string
	CodingAPIKey  string
	CodingModel   string
	HTTP          *http.Client

	// provider and codingProvider are the resolved LLM adapters.  They are
	// initialised by NewClient and updated by ConfigureCodingModel.  When nil,
	// the legacy direct-HTTP path (OpenAI-compatible) is used as a fallback so
	// existing deployments that construct Client via field assignment keep working.
	provider       Provider
	codingProvider Provider
}

// NewClient constructs a Client and auto-detects the LLM provider from the
// base URL and API key using DetectProvider.
func NewClient(baseURL, apiKey, model string) *Client {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	httpClient := &http.Client{Timeout: 20 * time.Second}
	providerName := DetectProvider(baseURL, apiKey)
	prov := NewProvider(providerName, baseURL, apiKey, httpClient)
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		APIKey:   apiKey,
		Model:    model,
		HTTP:     httpClient,
		provider: prov,
	}
}

func (c *Client) ConfigureCodingModel(baseURL, apiKey, model string) {
	if c == nil {
		return
	}
	model = strings.TrimSpace(model)
	if model == "" {
		c.CodingBaseURL = ""
		c.CodingAPIKey = ""
		c.CodingModel = ""
		c.codingProvider = nil
		return
	}

	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = c.BaseURL
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		apiKey = c.APIKey
	}

	c.CodingBaseURL = strings.TrimRight(baseURL, "/")
	c.CodingAPIKey = apiKey
	c.CodingModel = model

	providerName := DetectProvider(baseURL, apiKey)
	c.codingProvider = NewProvider(providerName, baseURL, apiKey, c.HTTP)
}

// completeWith delegates an LLM completion to the given provider, stripping
// any markdown code fence from the response so callers receive clean text.
func (c *Client) completeWith(ctx context.Context, p Provider, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
	if p == nil {
		// Fallback: use the legacy OpenAI-compatible path via c.HTTP directly.
		return c.legacyComplete(ctx, c.BaseURL, c.APIKey, model, messages, temperature, jsonMode)
	}
	text, err := p.Complete(ctx, model, messages, temperature, jsonMode)
	if err != nil {
		return "", err
	}
	return stripCodeFence(text), nil
}

// primaryComplete runs a completion using the primary provider/model.
func (c *Client) primaryComplete(ctx context.Context, messages []Message, temperature float64, jsonMode bool) (string, error) {
	p := c.provider
	if p == nil {
		return c.legacyComplete(ctx, c.BaseURL, c.APIKey, c.Model, messages, temperature, jsonMode)
	}
	return c.completeWith(ctx, p, c.Model, messages, temperature, jsonMode)
}

// planningComplete runs a completion using the coding/planning provider (if
// configured) or falls back to the primary provider.
func (c *Client) planningComplete(ctx context.Context, messages []Message, temperature float64, jsonMode bool) (string, error) {
	if strings.TrimSpace(c.CodingModel) != "" {
		p := c.codingProvider
		if p == nil {
			p = c.provider
		}
		if p != nil {
			return c.completeWith(ctx, p, c.CodingModel, messages, temperature, jsonMode)
		}
		bURL, apiKey, model := c.planningProvider()
		return c.legacyComplete(ctx, bURL, apiKey, model, messages, temperature, jsonMode)
	}
	return c.primaryComplete(ctx, messages, temperature, jsonMode)
}

// legacyComplete is the original direct-HTTP OpenAI-compatible implementation,
// retained as a fallback for Clients constructed without using NewClient().
func (c *Client) legacyComplete(ctx context.Context, baseURL, apiKey, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
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
		return "", fmt.Errorf("legacy complete: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("legacy complete: request: %w", err)
	}
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("legacy complete: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("legacy complete: status %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("legacy complete: decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("legacy complete: empty choices")
	}
	return stripCodeFence(strings.TrimSpace(out.Choices[0].Message.Content)), nil
}

func (c *Client) Summarize(ctx context.Context, target string, findings []model.Finding) string {
	return c.SummarizeWithKnowledge(ctx, target, findings, nil)
}

// NarrativeReport represents a domain-aware, business-function-mapped report
// generated by the narrative report engine.
type NarrativeReport struct {
	// ExecutiveSummary is a 2-4 sentence risk story linking findings to
	// the application's business function.
	ExecutiveSummary string `json:"executiveSummary"`
	// AttackNarrative describes the end-to-end attack scenario in plain
	// language (e.g. "An attacker could purchase goods for free, then
	// escalate to account takeover via…").
	AttackNarrative string `json:"attackNarrative,omitempty"`
	// ComplianceFramework is the auto-selected compliance standard
	// (PCI-DSS, HIPAA, SOC2) based on domain context signals.
	ComplianceFramework string `json:"complianceFramework,omitempty"`
	// ComplianceMapping maps finding IDs to relevant compliance controls.
	ComplianceMapping map[string]string `json:"complianceMapping,omitempty"`
	// TopPriorities is an ordered list of the 3 most impactful remediation actions.
	TopPriorities []string `json:"topPriorities,omitempty"`
}

// GenerateNarrativeReport generates a domain-aware security report that:
//  1. Maps findings to the application's specific business function (inferred
//     from discovered routes and target domain).
//  2. Constructs a risk story in plain language.
//  3. Auto-selects the appropriate compliance framework (PCI-DSS, HIPAA, SOC2)
//     based on domain context signals.
//
// Falls back to a structured local report when no AI provider is configured.
func (c *Client) GenerateNarrativeReport(ctx context.Context, target string, findings []model.Finding) NarrativeReport {
	if c == nil {
		return buildLocalNarrativeReport(target, findings)
	}
	if !c.shouldCallProvider() {
		return buildLocalNarrativeReport(target, findings)
	}

	// Build a lightweight finding summary for the prompt.
	type findingSummary struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Category string `json:"category"`
		URL      string `json:"url"`
		CWE      string `json:"cwe,omitempty"`
	}
	summaries := make([]findingSummary, 0, len(findings))
	for _, f := range findings {
		summaries = append(summaries, findingSummary{
			ID:       f.ID,
			Title:    f.Title,
			Severity: string(f.Severity),
			Category: f.Category,
			URL:      f.AffectedURL,
			CWE:      f.CWE,
		})
	}

	domainCtx := "general web application"
	complianceHint := "SOC2"
	if pack := SelectDomainProfile(target); pack != nil {
		domainCtx = pack.Name + " application (" + strings.Join(pack.PriorityAreas[:minInt(3, len(pack.PriorityAreas))], ", ") + ")"
		switch pack.Name {
		case "fintech":
			complianceHint = "PCI-DSS"
		case "healthcare":
			complianceHint = "HIPAA"
		default:
			complianceHint = "SOC2"
		}
	}

	systemPrompt := "You are a senior penetration testing report writer. Write clear, concise, business-context-aware security reports. Reply with strict JSON."
	userPrompt := fmt.Sprintf(
		`Target: %s
Domain context: %s
Likely compliance framework: %s
Finding count: %d
Findings: %s

Write a narrative security report in strict JSON:
{
  "executiveSummary": "<2-4 sentence risk summary linking findings to business function>",
  "attackNarrative": "<end-to-end attack scenario in plain language>",
  "complianceFramework": "<auto-selected framework name>",
  "complianceMapping": {"<finding_id>": "<control reference>"},
  "topPriorities": ["<action 1>", "<action 2>", "<action 3>"]
}`,
		target, domainCtx, complianceHint, len(findings), mustJSON(summaries),
	)

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}
	content, err := c.planningComplete(ctx, messages, 0.2, true)
	if err != nil || content == "" {
		return buildLocalNarrativeReport(target, findings)
	}
	var result NarrativeReport
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return buildLocalNarrativeReport(target, findings)
	}
	if strings.TrimSpace(result.ExecutiveSummary) == "" {
		return buildLocalNarrativeReport(target, findings)
	}
	return result
}

// buildLocalNarrativeReport constructs a rule-based NarrativeReport without AI.
func buildLocalNarrativeReport(target string, findings []model.Finding) NarrativeReport {
	if len(findings) == 0 {
		return NarrativeReport{
			ExecutiveSummary:    fmt.Sprintf("No vulnerabilities were identified during the assessment of %s.", target),
			ComplianceFramework: complianceFrameworkForTarget(target),
		}
	}

	// Count by severity.
	counts := map[string]int{}
	for _, f := range findings {
		counts[string(f.Severity)]++
	}
	exec := fmt.Sprintf(
		"Assessment of %s identified %d finding(s): %d critical/high, %d medium, %d low/info. "+
			"The most significant risks relate to %s and require immediate remediation.",
		target,
		len(findings),
		counts["critical"]+counts["high"],
		counts["medium"],
		counts["low"]+counts["info"],
		topCategories(findings),
	)

	priorities := topRemediationPriorities(findings)
	framework := complianceFrameworkForTarget(target)

	return NarrativeReport{
		ExecutiveSummary:    exec,
		AttackNarrative:     buildAttackNarrative(findings),
		ComplianceFramework: framework,
		TopPriorities:       priorities,
	}
}

// complianceFrameworkForTarget picks the most relevant compliance framework
// for a target URL based on domain keyword signals.
func complianceFrameworkForTarget(target string) string {
	if pack := SelectDomainProfile(target); pack != nil {
		switch pack.Name {
		case "fintech":
			return "PCI-DSS"
		case "healthcare":
			return "HIPAA"
		}
	}
	return "SOC2"
}

// topCategories returns a comma-separated string of the 2 most frequent
// finding categories to include in the executive summary.
func topCategories(findings []model.Finding) string {
	cats := map[string]int{}
	for _, f := range findings {
		if f.Severity == model.SeverityHigh {
			cats[f.Category]++
		}
	}
	if len(cats) == 0 {
		for _, f := range findings {
			cats[f.Category]++
		}
	}
	type kv struct {
		k string
		v int
	}
	sorted := make([]kv, 0, len(cats))
	for k, v := range cats {
		sorted = append(sorted, kv{k, v})
	}
	// Simple insertion sort for small slices.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].v > sorted[j-1].v; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	names := make([]string, 0, 2)
	for i, item := range sorted {
		if i >= 2 {
			break
		}
		names = append(names, item.k)
	}
	return strings.Join(names, " and ")
}

// topRemediationPriorities derives the top 3 remediation actions from finding data.
func topRemediationPriorities(findings []model.Finding) []string {
	seen := map[string]bool{}
	priorities := make([]string, 0, 3)
	// High/critical first.
	for _, f := range findings {
		if (f.Severity == model.SeverityHigh) &&
			strings.TrimSpace(f.Recommendation) != "" && !seen[f.ID] {
			seen[f.ID] = true
			// Take first sentence of recommendation.
			rec := strings.SplitN(f.Recommendation, ".", 2)[0]
			priorities = append(priorities, rec)
			if len(priorities) >= 3 {
				break
			}
		}
	}
	// Fill with medium if needed.
	for _, f := range findings {
		if len(priorities) >= 3 {
			break
		}
		if strings.TrimSpace(f.Recommendation) != "" && !seen[f.ID] {
			seen[f.ID] = true
			rec := strings.SplitN(f.Recommendation, ".", 2)[0]
			priorities = append(priorities, rec)
		}
	}
	return priorities
}

// buildAttackNarrative constructs a plain-language attack chain description
// from the most impactful findings.
func buildAttackNarrative(findings []model.Finding) string {
	// Look for a chain finding first — it already has a pre-built narrative.
	for _, f := range findings {
		if strings.HasPrefix(f.ID, "chain-") || strings.HasPrefix(f.ID, "llm-chain-") {
			return f.Description
		}
	}
	// Build a simple "attacker can do X then Y" narrative from top findings.
	var highFindings []model.Finding
	for _, f := range findings {
		if f.Severity == model.SeverityHigh {
			highFindings = append(highFindings, f)
			if len(highFindings) >= 2 {
				break
			}
		}
	}
	if len(highFindings) == 0 {
		return ""
	}
	if len(highFindings) == 1 {
		return fmt.Sprintf("An attacker exploiting %s (%s) could %s",
			highFindings[0].Title, highFindings[0].AffectedURL,
			strings.ToLower(firstSentence(highFindings[0].Description)))
	}
	return fmt.Sprintf(
		"An attacker could first exploit %s (%s), then leverage %s (%s) to achieve a greater impact.",
		highFindings[0].Title, highFindings[0].AffectedURL,
		highFindings[1].Title, highFindings[1].AffectedURL,
	)
}

func firstSentence(s string) string {
	if idx := strings.Index(s, "."); idx > 0 {
		return s[:idx+1]
	}
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *Client) SummarizeWithKnowledge(ctx context.Context, target string, findings []model.Finding, knowledge *model.SecurityKnowledgeContext) string {
	if !c.shouldCallProvider() {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}

	messages := []Message{
		{
			Role:    "system",
			Content: "You are a defensive AppSec assistant. Summarize scanner findings for authorized remediation only. Use supplied curated references as supporting context, and preserve citations as source titles plus URLs.",
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("Target: %s\nFindings JSON: %s\nKnowledge Context JSON: %s\nProvide: 1) risk summary 2) top 3 priorities 3) remediation sequence 4) supporting citations when knowledge context is present.", target, mustJSON(findings), mustJSON(knowledge)),
		},
	}
	content, err := c.primaryComplete(ctx, messages, 0.2, false)
	if err != nil || strings.TrimSpace(content) == "" {
		return localReasonerSummaryWithKnowledge(target, findings, knowledge)
	}
	return content
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// VulnerabilityHypothesis is a single testable vulnerability hypothesis
// generated by the AI provider and intended for deterministic scanner
// verification. The scanner executes a targeted probe based on the
// category/endpoint/payload hint and only surfaces a finding when the
// oracle confirms the vulnerability.
type VulnerabilityHypothesis struct {
	ID          string `json:"id"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	ParamName   string `json:"paramName,omitempty"`
	PayloadHint string `json:"payloadHint"`
	Category    string `json:"category"`
	Rationale   string `json:"rationale"`
}

// Hypothesize asks the configured AI provider to generate testable
// vulnerability hypotheses for the given target given the current finding
// set and known surface endpoints. Each hypothesis describes a specific
// probe (endpoint, parameter, payload) that the scanner verifies with a
// deterministic oracle. Only scanner-confirmed hypotheses are surfaced as
// findings, preventing hallucinated reports.
//
// Falls back to a rule-based local reasoner when no AI provider is configured.
func (c *Client) Hypothesize(ctx context.Context, target string, findings []model.Finding, endpoints []string) []VulnerabilityHypothesis {
	if c == nil {
		return localReasonerHypotheses(target, findings, endpoints)
	}
	if !c.shouldCallProvider() {
		return localReasonerHypotheses(target, findings, endpoints)
	}

	type hypothesisRequest struct {
		Target       string          `json:"target"`
		Findings     []model.Finding `json:"findings"`
		Endpoints    []string        `json:"endpoints"`
		Instructions string          `json:"instructions"`
	}
	hreq := hypothesisRequest{
		Target:    target,
		Findings:  findings,
		Endpoints: endpoints,
		Instructions: "Generate up to 5 testable vulnerability hypotheses. For each, specify: " +
			"a concrete endpoint URL, HTTP method (GET/POST), optional parameter name, " +
			"a payload hint (e.g. \"' OR 1=1 --\", \"<script>\", \"/../etc/passwd\"), " +
			"category (one of: sqli|xss|open_redirect|ssrf|cors|auth_bypass|idor|ssti|business_logic), " +
			"and a rationale. Only propose hypotheses verifiable by a deterministic scanner oracle. " +
			"Reply with strict JSON only: " +
			"{\"hypotheses\":[{\"id\":string,\"endpoint\":string,\"method\":string,\"paramName\":string,\"payloadHint\":string,\"category\":string,\"rationale\":string}]}",
	}
	userJSON, err := json.Marshal(hreq)
	if err != nil {
		return localReasonerHypotheses(target, findings, endpoints)
	}

	messages := []Message{
		{Role: "system", Content: "You are an autonomous security researcher generating testable vulnerability hypotheses. Reply with strict JSON."},
		{Role: "user", Content: string(userJSON)},
	}
	content, err := c.primaryComplete(ctx, messages, 0.3, true)
	if err != nil || content == "" {
		return localReasonerHypotheses(target, findings, endpoints)
	}
	var parsed struct {
		Hypotheses []VulnerabilityHypothesis `json:"hypotheses"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return localReasonerHypotheses(target, findings, endpoints)
	}
	return parsed.Hypotheses
}

func (c *Client) shouldCallProvider() bool {
	return shouldCallProviderFor(c.BaseURL, c.APIKey)
}

func (c *Client) planningProvider() (baseURL, apiKey, model string) {
	baseURL = c.BaseURL
	apiKey = c.APIKey
	model = c.Model

	if strings.TrimSpace(c.CodingModel) == "" {
		return baseURL, apiKey, model
	}
	if shouldCallProviderFor(c.CodingBaseURL, c.CodingAPIKey) {
		return c.CodingBaseURL, c.CodingAPIKey, c.CodingModel
	}
	return baseURL, apiKey, model
}

func shouldCallProviderFor(baseURL, apiKey string) bool {
	// Keep OpenAI default behavior: require an API key.
	const defaultOpenAIBase = "https://api.openai.com/v1"
	base := strings.TrimRight(strings.ToLower(strings.TrimSpace(baseURL)), "/")
	if strings.TrimSpace(apiKey) != "" {
		return true
	}
	return base != strings.ToLower(defaultOpenAIBase)
}

// GeneratedToolSpec is the Python tool source returned by the coding LLM.
// It mirrors toolbuilder.ToolSpec but is defined here to avoid a circular
// import — the toolbuilder package imports ai indirectly through the agent
// layer.
type GeneratedToolSpec struct {
	// Name is a short identifier used as the script filename (no extension).
	Name string
	// Code is the full Python 3 script source. The script must accept a
	// target URL as its first positional argument and write JSON-lines
	// findings to stdout.
	Code string
	// Rationale is the LLM's explanation for why this tool was chosen.
	Rationale string
}

// ToolCallHistory summarizes one prior tool-calling round for the AI model.
type ToolCallHistory struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

// ToolCallRequest is the bounded JSON contract for the AI tool-calling loop.
type ToolCallRequest struct {
	Target            string            `json:"target"`
	Findings          []map[string]any  `json:"findings,omitempty"`
	RecentToolOutputs []ToolCallHistory `json:"recentToolOutputs,omitempty"`
	AllowedBinaries   []string          `json:"allowedBinaries,omitempty"`
	HackTricksTopics  []string          `json:"hacktricksTopics,omitempty"`
	BuiltInTools      []string          `json:"builtInTools,omitempty"`
	ImpactGoals       []string          `json:"impactGoals,omitempty"`
	ImpactPlaybooks   string            `json:"impactPlaybooks,omitempty"`
}

// ToolCallDecision is the next bounded action chosen by the AI tool-calling planner.
type ToolCallDecision struct {
	Action     string   `json:"action"`
	Binary     string   `json:"binary,omitempty"`
	Args       []string `json:"args,omitempty"`
	Category   string   `json:"category,omitempty"`
	FindingID  string   `json:"findingId,omitempty"`
	Task       string   `json:"task,omitempty"`
	Rationale  string   `json:"rationale,omitempty"`
	StopReason string   `json:"stopReason,omitempty"`
}

// GenerateTool asks the configured coding LLM to write a Python 3 pen testing
// tool for the described task on the given target. The script must:
//   - accept a target URL as sys.argv[1]
//   - output zero or more JSON-lines findings to stdout, each with keys:
//     id, category, severity, title, description, evidence, recommendation
//   - use only the Python 3 standard library (no third-party packages)
//   - contain no subprocess, os.system, eval, exec, or raw socket calls
//
// Falls back to a nil result (no code generated) when the coding LLM is not
// configured or the request fails, allowing callers to gracefully skip
// AI-generated tooling.
func (c *Client) GenerateTool(ctx context.Context, taskDescription string, target string, contextFindings []string) *GeneratedToolSpec {
	if c == nil {
		return nil
	}
	if !c.shouldCallProvider() {
		return nil
	}

	systemPrompt := "You are an expert Python 3 security tool developer. " +
		"Write a concise, self-contained Python 3 pen testing script. " +
		"Rules: accept target URL as sys.argv[1]; print zero or more " +
		"JSON-lines findings to stdout, each with keys id, category, severity, " +
		"title, description, evidence, recommendation; use only the Python 3 " +
		"standard library (urllib, json, sys, re, base64, hashlib, hmac, ssl, " +
		"socket — but no subprocess, os.system, eval, exec, or raw socket.connect). " +
		"Output strict JSON only: {\"name\":string,\"code\":string,\"rationale\":string}"

	userPayload := map[string]any{
		"task":             taskDescription,
		"target":           target,
		"context_findings": contextFindings,
	}
	userJSON, err := json.Marshal(userPayload)
	if err != nil {
		return nil
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: string(userJSON)},
	}
	content, err := c.planningComplete(ctx, messages, 0.2, true)
	if err != nil || content == "" {
		return nil
	}
	var parsed struct {
		Name      string `json:"name"`
		Code      string `json:"code"`
		Rationale string `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}
	name := strings.TrimSpace(parsed.Name)
	code := strings.TrimSpace(parsed.Code)
	if name == "" || code == "" {
		return nil
	}
	return &GeneratedToolSpec{
		Name:      name,
		Code:      code,
		Rationale: strings.TrimSpace(parsed.Rationale),
	}
}

// PlanToolCall asks the configured planning model to choose the next bounded
// tool action. It returns nil when no provider is configured, the response is
// invalid, or the model does not choose an actionable step.
func (c *Client) PlanToolCall(ctx context.Context, req ToolCallRequest) *ToolCallDecision {
	if c == nil {
		return nil
	}
	if !c.shouldCallProvider() {
		return nil
	}

	systemPrompt := buildToolCallSystemPrompt(req)

	userJSON, err := json.Marshal(req)
	if err != nil {
		return nil
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: string(userJSON)},
	}
	content, err := c.planningComplete(ctx, messages, 0.1, true)
	if err != nil || content == "" {
		return nil
	}

	var parsed ToolCallDecision
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}
	parsed.Action = strings.ToLower(strings.TrimSpace(parsed.Action))
	parsed.Binary = strings.TrimSpace(parsed.Binary)
	parsed.Category = strings.TrimSpace(parsed.Category)
	parsed.FindingID = strings.TrimSpace(parsed.FindingID)
	parsed.Task = strings.TrimSpace(parsed.Task)
	parsed.Rationale = strings.TrimSpace(parsed.Rationale)
	parsed.StopReason = strings.TrimSpace(parsed.StopReason)

	switch parsed.Action {
	case "stop":
		if parsed.StopReason == "" {
			parsed.StopReason = "model requested stop"
		}
		return &parsed
	case "run_command":
		if parsed.Binary == "" || len(parsed.Args) == 0 {
			return nil
		}
		return &parsed
	case "run_hacktricks":
		if parsed.Category == "" {
			return nil
		}
		return &parsed
	case "generate_tool":
		if parsed.Task == "" {
			return nil
		}
		return &parsed
	default:
		return nil
	}
}

func buildToolCallSystemPrompt(req ToolCallRequest) string {
	goals := strings.TrimSpace(strings.Join(req.ImpactGoals, ", "))
	if goals == "" {
		goals = impact.GoalPrompt(impact.DefaultGoals())
	}
	playbooks := strings.TrimSpace(req.ImpactPlaybooks)
	if playbooks == "" {
		playbooks = "none provided"
	}

	return strings.Join([]string{
		"You are an autonomous bug bounty operator.",
		"Your overarching theme is IMPACT-FIRST validation, not generic vulnerability counting.",
		"Prioritize exploitability, account takeover, auth bypass, sensitive data access, payment abuse, tenant breakout, meaningful escalation, or other bug-bounty-relevant impact.",
		"Current scan goals: " + goals + ".",
		"Reusable impact playbooks: " + playbooks + ".",
		"Choose exactly one next action using this strict JSON schema: " + toolCallDecisionSchema + ".",
		"Rules:",
		"(1) Prefer the smallest next action that increases confidence in real-world impact.",
		"(2) For run_command, choose only from allowedBinaries and include concrete args.",
		"(3) For run_hacktricks, choose a category from hacktricksTopics and optionally a findingId.",
		"(4) For generate_tool, request a focused sandboxed probe task tied to a concrete impact hypothesis.",
		"(5) If recent results show low value or the evidence is already sufficient, return stop.",
		"(6) Never emit markdown or extra text.",
	}, " ")
}

// AdaptedCommand is a single concrete command that the coding LLM has adapted
// from a HackTricks command template to the specific finding and target.
type AdaptedCommand struct {
	Binary    string   `json:"binary"`
	Args      []string `json:"args"`
	Rationale string   `json:"rationale"`
}

// AdaptTechniqueCommands asks the coding LLM to fill in the {{TARGET}},
// {{HOST}}, {{PATH}}, and {{PARAM}} placeholders in each template string with
// values extracted from the finding evidence and target URL.  The LLM may also
// augment the commands (e.g. tightening sqlmap flags based on DBMS hints in
// the evidence, or adding the correct cookie header when credentials are known).
//
// Each element of templates should be the human-readable form of one command
// invocation, e.g. "sqlmap -u {{TARGET}}?{{PARAM}}=1 --batch".
//
// Returns nil when the coding LLM is not configured or the request fails;
// callers should fall back to simple string substitution in that case.
func (c *Client) AdaptTechniqueCommands(ctx context.Context, templates []string, findingTitle, findingEvidence, target string) []AdaptedCommand {
	if c == nil {
		return nil
	}
	if !c.shouldCallProvider() {
		return nil
	}

	systemPrompt := "You are an expert penetration tester. " +
		"You receive a list of HackTricks command templates with placeholders " +
		"({{TARGET}}, {{HOST}}, {{PATH}}, {{PARAM}}) and a finding with its evidence. " +
		"For each template, produce a concrete, ready-to-run command adapted to the actual target and finding. " +
		"Rules: " +
		"(1) Replace {{TARGET}} with the exact target URL. " +
		"(2) Replace {{HOST}} with the target hostname. " +
		"(3) Replace {{PATH}} with the relevant path extracted from the evidence, or / if unknown. " +
		"(4) Replace {{PARAM}} with the vulnerable parameter name from the evidence, or 'id' if unknown. " +
		"(5) Only use binaries from this list: sqlmap curl dalfox gobuster ffuf nikto nmap nuclei subfinder httpx cloudlist vulnx python3 wafw00f wpscan arjun. " +
		"(5a) You may choose any tool-specific flags that best fit the finding evidence and target context. " +
		// NOTE: this list mirrors cmdbuilder.allowedBinaries. If that list
		// changes, update here too so the LLM prompt stays in sync.
		"(6) Do NOT add shell operators (&&, ||, ;, |, $(), backticks, or redirects). " +
		"(7) Output strict JSON only: {\"commands\":[{\"binary\":string,\"args\":[string,...],\"rationale\":string}]}"

	type adaptRequest struct {
		Target          string   `json:"target"`
		FindingTitle    string   `json:"finding_title"`
		FindingEvidence string   `json:"finding_evidence"`
		Templates       []string `json:"templates"`
	}
	reqBody := adaptRequest{
		Target:          target,
		FindingTitle:    findingTitle,
		FindingEvidence: findingEvidence,
		Templates:       templates,
	}
	userJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: string(userJSON)},
	}
	content, err := c.planningComplete(ctx, messages, 0.1, true)
	if err != nil || content == "" {
		return nil
	}
	var parsed struct {
		Commands []AdaptedCommand `json:"commands"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}
	out := make([]AdaptedCommand, 0, len(parsed.Commands))
	for _, cmd := range parsed.Commands {
		if strings.TrimSpace(cmd.Binary) != "" && len(cmd.Args) > 0 {
			out = append(out, cmd)
		}
	}
	return out
}

// SynthesizedChain is a novel multi-step attack chain proposed by the LLM.
type SynthesizedChain struct {
	// ID is a short machine-readable label (e.g. "jwt-cors-token-theft").
	ID string `json:"id"`
	// Title is the one-line chain description.
	Title string `json:"title"`
	// Steps is the ordered list of exploitation steps.
	Steps []string `json:"steps"`
	// Impact is a one-sentence description of the attacker's gain.
	Impact string `json:"impact"`
	// SourceIDs lists the Finding IDs that triggered this chain.
	SourceIDs []string `json:"sourceIds,omitempty"`
	// Confidence is the model's self-assessed confidence in 0.0–1.0.
	Confidence float64 `json:"confidence"`
}

// SynthesizeChains sends the full finding set to the AI and asks it to reason
// about novel multi-step attack chains that the static rules do not cover.
// Results are filtered to only include chains with Confidence >= 0.60 so
// low-quality hallucinations are suppressed before they become findings.
//
// Falls back to nil when no AI provider is configured.
func (c *Client) SynthesizeChains(ctx context.Context, target string, findingSet []map[string]string, goals []model.ImpactGoal) []SynthesizedChain {
	if c == nil {
		return nil
	}
	if !c.shouldCallProvider() {
		return nil
	}
	if len(findingSet) == 0 {
		return nil
	}

	userPayload := map[string]any{
		"target":           target,
		"findings":         findingSet,
		"impact_goals":     impact.GoalPrompt(goals),
		"impact_playbooks": impact.PlaybookPrompt(goals),
		"instructions": "You are an elite penetration tester. Analyse the provided finding set and reason about " +
			"novel multi-step attack chains NOT already represented in the findings. " +
			"Focus on chaining 2–4 findings together to achieve a higher-impact outcome than any individual finding. " +
			"Prefer business outcomes that match the supplied impact_goals and impact_playbooks. " +
			"For each chain: assign a short machine-readable id, a one-line title, ordered exploitation steps (3–6), " +
			"a one-sentence impact statement, list the source finding IDs involved, and a confidence score (0.0–1.0). " +
			"Reply with strict JSON only: " +
			`{"chains":[{"id":string,"title":string,"steps":[string],"impact":string,"sourceIds":[string],"confidence":number}]}`,
	}
	userJSON, err := json.Marshal(userPayload)
	if err != nil {
		return nil
	}

	messages := []Message{
		{Role: "system", Content: "You are an expert penetration tester generating multi-step exploit chains. Reply with strict JSON."},
		{Role: "user", Content: string(userJSON)},
	}
	content, err := c.planningComplete(ctx, messages, 0.3, true)
	if err != nil || content == "" {
		return nil
	}
	var parsed struct {
		Chains []SynthesizedChain `json:"chains"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil
	}

	out := make([]SynthesizedChain, 0, len(parsed.Chains))
	for _, ch := range parsed.Chains {
		if strings.TrimSpace(ch.ID) == "" || strings.TrimSpace(ch.Title) == "" {
			continue
		}
		if ch.Confidence < 0.60 {
			continue
		}
		out = append(out, ch)
	}
	return out
}

// DomainProfilePack contains domain-specific instructions injected into the AI
// planner's system prompt to tune its decisions to the target's business context.
type DomainProfilePack struct {
	// Name identifies the pack (e.g. "fintech", "healthcare").
	Name string
	// HostPatterns are domain suffix patterns that trigger this pack.
	HostPatterns []string
	// PriorityAreas are the highest-value vulnerability classes for this domain.
	PriorityAreas []string
	// SystemInstruction is injected into the AI planner's system message.
	SystemInstruction string
}

// domainProfilePacks maps known domain profiles to contextual AI instructions.
var domainProfilePacks = []DomainProfilePack{
	{
		Name:         "fintech",
		HostPatterns: []string{"pay", "bank", "finance", "wallet", "money", "transfer", "trade", "invest", "loan", "credit", "fintech"},
		PriorityAreas: []string{
			"payment flow manipulation",
			"price and quantity parameter tampering",
			"race conditions on transaction endpoints",
			"account balance manipulation",
			"double-spend attacks",
		},
		SystemInstruction: "This is a FINTECH target. Prioritize: (1) payment and transfer flow integrity " +
			"(race conditions, double-spend, negative amounts); (2) price manipulation in cart/checkout; " +
			"(3) authorization bypass on account balance and transaction history; " +
			"(4) PCI-DSS relevant findings (card data exposure, unencrypted storage, weak TLS). " +
			"Frame risk rationale using PCI-DSS impact. Elevate any finding that could cause financial loss.",
	},
	{
		Name:         "healthcare",
		HostPatterns: []string{"health", "medical", "clinic", "hospital", "patient", "ehr", "emr", "pharmacy", "prescription", "hipaa"},
		PriorityAreas: []string{
			"PHI/PII exposure",
			"IDOR on patient records",
			"authentication bypass",
			"audit log tampering",
		},
		SystemInstruction: "This is a HEALTHCARE target. Prioritize: (1) PHI exposure (HIPAA-relevant findings); " +
			"(2) IDOR on patient records and appointments; (3) authentication bypass on clinician accounts; " +
			"(4) audit log integrity (can findings be covered up?). " +
			"Frame risk rationale using HIPAA/HITECH impact. Elevation to high when PHI is in scope.",
	},
	{
		Name:         "saas",
		HostPatterns: []string{"app.", "dashboard", "portal", "platform", "cloud", "saas"},
		PriorityAreas: []string{
			"tenant isolation",
			"IDOR across accounts",
			"privilege escalation within roles",
			"API key / secret leakage",
		},
		SystemInstruction: "This is a SaaS/multi-tenant target. Prioritize: (1) cross-tenant IDOR (can a tenant A access tenant B data?); " +
			"(2) privilege escalation within a tenant (viewer → admin); (3) API key enumeration and weak token generation; " +
			"(4) secrets in JS bundles. Frame risk using SLA and data isolation impact.",
	},
	{
		Name:         "api-first",
		HostPatterns: []string{"api.", "/api/", "gateway", "graphql", "grpc", "rest"},
		PriorityAreas: []string{
			"broken object-level authorization",
			"GraphQL introspection",
			"mass assignment",
			"JWT forgery",
		},
		SystemInstruction: "This is an API-FIRST target. Prioritize: (1) BOLA/IDOR on every object ID parameter; " +
			"(2) GraphQL introspection and field-level auth; (3) mass assignment via undocumented fields; " +
			"(4) JWT algorithm confusion and weak signing keys; (5) rate limiting on authentication endpoints. " +
			"Map findings to OWASP API Security Top 10.",
	},
}

// SelectDomainProfile returns the best-matching DomainProfilePack for a target
// URL, or nil when no profile matches.
func SelectDomainProfile(targetURL string) *DomainProfilePack {
	lower := strings.ToLower(targetURL)
	for i := range domainProfilePacks {
		for _, pattern := range domainProfilePacks[i].HostPatterns {
			if strings.Contains(lower, pattern) {
				return &domainProfilePacks[i]
			}
		}
	}
	return nil
}
