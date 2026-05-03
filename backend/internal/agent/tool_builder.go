package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/toolbuilder"
)

// ToolBuilderAgent autonomously selects, generates, and executes custom Python
// tools for specialised pen testing tasks that have no pre-installed binary.
//
// It first runs applicable built-in tool templates selected from the current
// finding context (JWT tokens → jwt_probe; GraphQL hints → graphql_probe, etc.).
// When an AI coding client is configured it also prompts the LLM on the fly to
// generate bespoke Python tools for findings that have no matching built-in
// template, enabling fully autonomous tool synthesis during a live pen test.
type ToolBuilderAgent struct {
	enabled  bool
	builder  *toolbuilder.Builder
	aiClient *ai.Client
}

// NewToolBuilderAgent constructs the agent. aiClient may be nil; when nil the
// agent falls back to the static built-in tool catalog only.
func NewToolBuilderAgent(enabled bool, aiClient *ai.Client) *ToolBuilderAgent {
	return &ToolBuilderAgent{
		enabled:  enabled,
		builder:  &toolbuilder.Builder{},
		aiClient: aiClient,
	}
}

const maxAIGeneratedTools = 3

func (a *ToolBuilderAgent) Name() string  { return "tool_builder" }
func (a *ToolBuilderAgent) Enabled() bool { return a.enabled }

func (a *ToolBuilderAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   "Tool builder agent starting — selecting and generating custom tools from findings",
	})

	allFindings := input.AllFindings
	if len(allFindings) == 0 {
		allFindings = input.Previous.Findings
	}

	selected := a.selectTools(allFindings)
	if len(selected) == 0 {
		// Always run the header and CSP probes as a baseline.
		selected = []string{"header_probe", "csp_probe"}
	}

	catalog := toolbuilder.BuiltInTools()
	built := 0
	totalFindings := 0

	for _, toolName := range selected {
		select {
		case <-ctx.Done():
			output.Status = "partial"
			break
		default:
		}

		factory, ok := catalog[toolName]
		if !ok {
			continue
		}

		spec := factory(a.Name())

		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventInfo,
			AgentName: a.Name(),
			Message:   fmt.Sprintf("Building and deploying tool %q: %s", spec.Name, spec.Rationale),
		})

		findings, err := a.builder.Build(ctx, spec, input.Target, input.Emit)
		if err != nil {
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventInfo,
				AgentName: a.Name(),
				Message:   fmt.Sprintf("Tool %q execution issue: %v", spec.Name, err),
			})
			continue
		}

		built++
		totalFindings += len(findings)
		output.Findings = append(output.Findings, findings...)

		// Emit individual finding events.
		for _, f := range findings {
			Emit(input.Emit, model.ScanEvent{
				Type:         model.ScanEventFinding,
				AgentName:    a.Name(),
				FindingTitle: f.Title,
				Severity:     string(f.Severity),
				Message:      fmt.Sprintf("[%s] %s", f.Severity, f.Title),
			})
		}
	}

	// ── AI on-the-fly tool generation ────────────────────────────────────────
	// When a coding LLM is configured, inspect the current findings for
	// categories that have no matching built-in template and ask the model to
	// write a bespoke Python probe for each.  This happens after the built-in
	// tools run so the LLM has richer context from their results.
	aiBuilt := 0
	if a.aiClient != nil {
		uncovered := a.uncoveredCategories(allFindings, catalog)
		for _, task := range uncovered {
			select {
			case <-ctx.Done():
				output.Status = "partial"
				goto done
			default:
			}

			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventInfo,
				AgentName: a.Name(),
				Message:   fmt.Sprintf("Prompting coding LLM to generate Python tool for: %s", task),
			})

			contextTitles := findingTitles(allFindings, 5)
			generated := a.aiClient.GenerateTool(ctx, task, input.Target, contextTitles)
			if generated == nil {
				continue
			}

			spec := toolbuilder.ToolSpec{
				Name:        "ai_" + generated.Name,
				Language:    "python3",
				Code:        generated.Code,
				Rationale:   generated.Rationale,
				GeneratedBy: a.Name(),
			}

			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventInfo,
				AgentName: a.Name(),
				Message:   fmt.Sprintf("Running LLM-generated tool %q: %s", spec.Name, spec.Rationale),
			})

			findings, err := a.builder.Build(ctx, spec, input.Target, input.Emit)
			if err != nil {
				Emit(input.Emit, model.ScanEvent{
					Type:      model.ScanEventInfo,
					AgentName: a.Name(),
					Message:   fmt.Sprintf("LLM tool %q execution issue: %v", spec.Name, err),
				})
				continue
			}

			aiBuilt++
			built++
			totalFindings += len(findings)
			output.Findings = append(output.Findings, findings...)

			for _, f := range findings {
				Emit(input.Emit, model.ScanEvent{
					Type:         model.ScanEventFinding,
					AgentName:    a.Name(),
					FindingTitle: f.Title,
					Severity:     string(f.Severity),
					Message:      fmt.Sprintf("[%s] %s", f.Severity, f.Title),
				})
			}
		}
	}

done:
	output.Metadata["tools_built"] = fmt.Sprintf("%d", built)
	output.Metadata["tools_selected"] = fmt.Sprintf("%d", len(selected))
	output.Metadata["ai_tools_generated"] = fmt.Sprintf("%d", aiBuilt)
	output.DebugNotes = fmt.Sprintf(
		"Built and ran %d/%d built-in tools + %d AI-generated tools; produced %d findings.",
		built-aiBuilt, len(selected), aiBuilt, totalFindings,
	)
	return output, nil
}

// selectTools returns the names of tool templates relevant to the current
// findings.  It can select multiple tools; the caller runs them in sequence.
func (a *ToolBuilderAgent) selectTools(findings []model.Finding) []string {
	selected := make([]string, 0, 4)
	seen := map[string]bool{}

	add := func(name string) {
		if !seen[name] {
			selected = append(selected, name)
			seen[name] = true
		}
	}

	for _, f := range findings {
		ev := f.Evidence
		title := f.Title

		if containsAny(ev+title, "jwt", "bearer", "token") {
			add("jwt_probe")
		}
		if containsAny(ev+title, "graphql", "__schema", "introspection") {
			add("graphql_probe")
		}
		if containsAny(ev+title, "redirect", "location:", "open redirect") {
			add("redirect_probe")
		}
		if containsAny(ev+title, "header", "csp", "x-frame", "hsts") {
			add("header_probe")
			add("csp_probe")
		}
	}

	// Always run baseline header/CSP checks regardless of prior findings.
	add("header_probe")
	add("csp_probe")

	return selected
}

// containsAny reports whether s (case-insensitive) contains any of the given substrings.
func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// uncoveredCategories returns a list of task descriptions for finding
// categories that have no matching built-in tool template.  These are passed
// to the coding LLM so it can generate targeted Python probes on the fly.
func (a *ToolBuilderAgent) uncoveredCategories(findings []model.Finding, catalog map[string]func(string) toolbuilder.ToolSpec) []string {
	// Built-in catalog coverage map: category keyword → template name.
	builtinCoverage := map[string]string{
		"jwt":             "jwt_probe",
		"bearer":          "jwt_probe",
		"graphql":         "graphql_probe",
		"redirect":        "redirect_probe",
		"header":          "header_probe",
		"csp":             "csp_probe",
		"ssrf":            "ssrf_probe",
		"cors":            "cors_probe",
		"idor":            "idor_probe",
		"cookie":          "cookie_probe",
		"information":     "info_disclosure_probe",
		"ssti":            "ssti_probe",
		"xxe":             "xxe_probe",
		"rate":            "rate_limit_probe",
		"api_key":         "api_keys_probe",
		"traversal":       "path_traversal_probe",
		"log4":            "log4shell_probe",
		"nosql":           "nosql_injection_probe",
		"ldap":            "ldap_injection_probe",
		"crlf":            "crlf_injection_probe",
		"smuggling":       "http_smuggling_probe",
		"subdomain":       "subdomain_takeover_probe",
		"ssl":             "ssl_tls_probe",
		"tls":             "ssl_tls_probe",
		"host_header":     "host_header_injection_probe",
		"oauth":           "oauth_probe",
		"password_reset":  "password_reset_probe",
		"enumeration":     "account_enumeration_probe",
		"mass_assignment": "mass_assignment_probe",
		"verb":            "verb_tampering_probe",
		"deserializ":      "deserialization_probe",
		"cache":           "cache_poisoning_probe",
		"race":            "race_condition_probe",
		"dom_xss":         "dom_xss_probe",
		"http_method":     "http_methods_probe",
		"business_logic":  "business_logic_probe",
		"file_upload":     "file_upload_probe",
	}

	seen := map[string]bool{}
	var tasks []string

	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if cat == "" || seen[cat] {
			continue
		}
		covered := false
		for keyword := range builtinCoverage {
			if strings.Contains(cat, keyword) {
				covered = true
				break
			}
		}
		if !covered {
			seen[cat] = true
			tasks = append(tasks, fmt.Sprintf(
				"Probe the target for '%s' vulnerabilities based on finding: %s",
				cat, strings.TrimSpace(f.Title),
			))
			if len(tasks) >= maxAIGeneratedTools {
				break
			}
		}
	}
	return tasks
}

// findingTitles returns up to n finding titles as a string slice for LLM context.
func findingTitles(findings []model.Finding, n int) []string {
	out := make([]string, 0, n)
	for _, f := range findings {
		if len(out) >= n {
			break
		}
		if t := strings.TrimSpace(f.Title); t != "" {
			out = append(out, t)
		}
	}
	return out
}
