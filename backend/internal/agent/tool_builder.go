package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/toolbuilder"
)

// ToolBuilderAgent autonomously selects, generates, and executes custom Python
// tools for specialised pen testing tasks that have no pre-installed binary.
//
// It decides which built-in tool templates to run based on the current finding
// context (JWT tokens found → run jwt_probe; GraphQL hints → graphql_probe, etc.)
// and assembles the generated scripts' JSON-lines output into model.Finding values.
type ToolBuilderAgent struct {
	enabled bool
	builder *toolbuilder.Builder
}

func NewToolBuilderAgent(enabled bool) *ToolBuilderAgent {
	return &ToolBuilderAgent{enabled: enabled, builder: &toolbuilder.Builder{}}
}

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

	output.Metadata["tools_built"] = fmt.Sprintf("%d", built)
	output.Metadata["tools_selected"] = fmt.Sprintf("%d", len(selected))
	output.DebugNotes = fmt.Sprintf(
		"Built and ran %d/%d custom tools; produced %d findings.",
		built, len(selected), totalFindings,
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
