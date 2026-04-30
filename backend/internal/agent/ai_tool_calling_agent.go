package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/cmdbuilder"
	"auto-bughunter/backend/internal/hacktricks"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/toolbuilder"
)

const (
	maxAIToolCallRounds         = 4
	maxAIToolCallHistory        = 5
	maxAIToolCommandActions     = 2
	maxAIToolHackTricksActions  = 2
	maxAIToolGeneratedTools     = 1
	maxAIToolTechniqueTemplates = 2
)

type aiToolCaller interface {
	PlanToolCall(ctx context.Context, req ai.ToolCallRequest) *ai.ToolCallDecision
	AdaptTechniqueCommands(ctx context.Context, templates []string, findingTitle, findingEvidence, target string) []ai.AdaptedCommand
	GenerateTool(ctx context.Context, taskDescription string, target string, contextFindings []string) *ai.GeneratedToolSpec
}

// AIToolCallingAgent lets the planning model choose bounded tool actions while
// routing all execution through the existing guarded command and tool builders.
type AIToolCallingAgent struct {
	enabled  bool
	aiClient aiToolCaller
	builder  *toolbuilder.Builder
}

func NewAIToolCallingAgent(aiClient aiToolCaller, enabled bool) *AIToolCallingAgent {
	return &AIToolCallingAgent{
		enabled:  enabled,
		aiClient: aiClient,
		builder:  &toolbuilder.Builder{},
	}
}

func (a *AIToolCallingAgent) Name() string  { return "ai_tool_calling" }
func (a *AIToolCallingAgent) Enabled() bool { return a.enabled }

func (a *AIToolCallingAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if !input.Options.UseAIToolCalling {
		output.DebugNotes = "AI tool-calling disabled for this scan"
		return output, nil
	}
	if a.aiClient == nil {
		output.DebugNotes = "AI tool-calling skipped — AI client not configured"
		return output, nil
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   "AI tool-calling agent starting — impact-first bug bounty validation loop",
	})

	allFindings := append([]model.Finding(nil), input.AllFindings...)
	history := make([]ai.ToolCallHistory, 0, maxAIToolCallHistory)
	commandCalls := 0
	hacktricksCalls := 0
	generatedToolCalls := 0
	executedCalls := 0
	validationFailures := 0
	roundsCompleted := 0
	stopLoop := false

	for round := 0; round < maxAIToolCallRounds; round++ {
		if stopLoop {
			break
		}
		select {
		case <-ctx.Done():
			output.Status = "partial"
			output.DebugNotes = "AI tool-calling interrupted by context cancellation"
			setAIToolCallingMetadata(&output, roundsCompleted, executedCalls, validationFailures, commandCalls, hacktricksCalls, generatedToolCalls)
			return output, ctx.Err()
		default:
		}
		roundsCompleted++

		req := ai.ToolCallRequest{
			Target:            input.Target,
			Findings:          summarizeToolCallFindings(allFindings),
			RecentToolOutputs: append([]ai.ToolCallHistory(nil), history...),
			AllowedBinaries:   cmdbuilder.ApprovedBinaries(),
			HackTricksTopics:  hacktricksCategories(),
			BuiltInTools:      builtInToolNames(),
		}
		decision := a.aiClient.PlanToolCall(ctx, req)
		if decision == nil {
			history = appendToolHistory(history, ai.ToolCallHistory{
				Action:  "stop",
				Status:  "no_decision",
				Summary: "planner returned no actionable tool decision",
			})
			break
		}

		if decision.Action == "stop" {
			reason := strings.TrimSpace(decision.StopReason)
			if reason == "" {
				reason = "model requested stop"
			}
			history = appendToolHistory(history, ai.ToolCallHistory{
				Action:  "stop",
				Status:  "completed",
				Summary: reason,
			})
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventInfo,
				AgentName: a.Name(),
				Message:   "AI tool-calling loop stopped: " + reason,
				Metadata: map[string]string{
					"tool_action": "stop",
					"reason":      reason,
				},
			})
			break
		}

		switch decision.Action {
		case "run_command":
			if commandCalls >= maxAIToolCommandActions {
				history = appendToolHistory(history, ai.ToolCallHistory{
					Action:  decision.Action,
					Status:  "budget_exhausted",
					Summary: "command action budget exhausted",
				})
				continue
			}
			commandCalls++
			result, findings := a.executeCommand(ctx, input, *decision)
			executedCalls++
			if result.Error != nil && strings.Contains(result.Error.Error(), "safety validation failed") {
				validationFailures++
			}
			allFindings = append(allFindings, findings...)
			output.Findings = append(output.Findings, findings...)
			history = appendToolHistory(history, summarizeCommandHistory(result, findings))
		case "run_hacktricks":
			if hacktricksCalls >= maxAIToolHackTricksActions {
				history = appendToolHistory(history, ai.ToolCallHistory{
					Action:  decision.Action,
					Status:  "budget_exhausted",
					Summary: "HackTricks action budget exhausted",
				})
				continue
			}
			hacktricksCalls++
			findings, failures, summary := a.executeHackTricks(ctx, input, allFindings, *decision)
			executedCalls++
			validationFailures += failures
			allFindings = append(allFindings, findings...)
			output.Findings = append(output.Findings, findings...)
			history = appendToolHistory(history, ai.ToolCallHistory{
				Action:  decision.Action,
				Status:  summarizeStatus(findings, failures == 0),
				Summary: summary,
			})
		case "generate_tool":
			if generatedToolCalls >= maxAIToolGeneratedTools {
				history = appendToolHistory(history, ai.ToolCallHistory{
					Action:  decision.Action,
					Status:  "budget_exhausted",
					Summary: "generated-tool action budget exhausted",
				})
				continue
			}
			generatedToolCalls++
			findings, err := a.executeGeneratedTool(ctx, input, allFindings, *decision)
			executedCalls++
			if err != nil {
				history = appendToolHistory(history, ai.ToolCallHistory{
					Action:  decision.Action,
					Status:  "error",
					Summary: truncate(err.Error(), 220),
				})
				continue
			}
			allFindings = append(allFindings, findings...)
			output.Findings = append(output.Findings, findings...)
			history = appendToolHistory(history, ai.ToolCallHistory{
				Action:  decision.Action,
				Status:  summarizeStatus(findings, true),
				Summary: fmt.Sprintf("generated tool produced %d finding(s)", len(findings)),
			})
		default:
			history = appendToolHistory(history, ai.ToolCallHistory{
				Action:  decision.Action,
				Status:  "invalid_action",
				Summary: "planner returned unsupported action",
			})
			stopLoop = true
		}
	}

	setAIToolCallingMetadata(&output, roundsCompleted, executedCalls, validationFailures, commandCalls, hacktricksCalls, generatedToolCalls)
	output.DebugNotes = fmt.Sprintf(
		"AI tool-calling executed %d bounded action(s), validation failures=%d, findings=%d.",
		executedCalls, validationFailures, len(output.Findings),
	)
	return output, nil
}

func (a *AIToolCallingAgent) executeCommand(ctx context.Context, input AgentInput, decision ai.ToolCallDecision) (cmdbuilder.RunResult, []model.Finding) {
	spec := cmdbuilder.CommandSpec{
		Binary:      decision.Binary,
		Args:        append([]string(nil), decision.Args...),
		Rationale:   nonEmpty(decision.Rationale, "AI-selected impact validation command"),
		GeneratedBy: a.Name(),
		Timeout:     90 * time.Second,
	}
	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventInfo,
		AgentName: a.Name(),
		Message:   fmt.Sprintf("AI selected command %q for impact validation", spec.String()),
		Metadata: map[string]string{
			"tool_action": "run_command",
		},
	})
	result := cmdbuilder.RunWithPolicy(ctx, spec, input.Target, cmdbuilder.ValidationPolicy{
		UnsafeMode: input.Options.UnsafeDynamicCommandFlags,
	}, input.Emit)
	return result, parseCommandOutput(result.Stdout, spec, input.Target)
}

func (a *AIToolCallingAgent) executeHackTricks(ctx context.Context, input AgentInput, findings []model.Finding, decision ai.ToolCallDecision) ([]model.Finding, int, string) {
	techniques := hacktricks.ForCategories(decision.Category)
	if len(techniques) == 0 {
		return nil, 0, "no HackTricks technique matched requested category"
	}
	sourceFinding := selectHackTricksFinding(findings, decision)
	if sourceFinding.ID == "" && len(findings) > 0 {
		sourceFinding = findings[len(findings)-1]
	}
	helper := NewHackTricksAgent(true, nil)
	if a.aiClient != nil {
		helper.aiClient = anyToAIClient(a.aiClient)
	}
	tech := techniques[0]
	templates := tech.CommandTemplates
	if len(templates) > maxAIToolTechniqueTemplates {
		templates = templates[:maxAIToolTechniqueTemplates]
	}
	specs := helper.buildCommandSpecs(ctx, templates, sourceFinding, input.Target, extractHostname(input.Target), extractPath(input.Target))
	if len(specs) == 0 {
		return nil, 0, "HackTricks adaptation produced no commands"
	}
	out := make([]model.Finding, 0)
	failures := 0
	for _, spec := range specs {
		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventInfo,
			AgentName: a.Name(),
			Message:   fmt.Sprintf("AI selected HackTricks %q via %s", tech.Category, spec.String()),
			Metadata: map[string]string{
				"tool_action": "run_hacktricks",
				"category":    tech.Category,
			},
		})
		result := cmdbuilder.RunWithPolicy(ctx, spec, input.Target, cmdbuilder.ValidationPolicy{
			UnsafeMode: input.Options.UnsafeDynamicCommandFlags,
		}, input.Emit)
		if result.Error != nil && strings.Contains(result.Error.Error(), "safety validation failed") {
			failures++
		}
		if result.Error != nil {
			continue
		}
		out = append(out, parseHackTricksOutput(result, spec, sourceFinding, input.Target, tech.Category, tech.HackTricksURL)...)
	}
	return out, failures, fmt.Sprintf("HackTricks %s produced %d finding(s) across %d command(s)", tech.Category, len(out), len(specs))
}

func (a *AIToolCallingAgent) executeGeneratedTool(ctx context.Context, input AgentInput, findings []model.Finding, decision ai.ToolCallDecision) ([]model.Finding, error) {
	generated := a.aiClient.GenerateTool(ctx, decision.Task, input.Target, findingTitles(findings, 5))
	if generated == nil {
		return nil, fmt.Errorf("AI did not generate a tool for task %q", decision.Task)
	}
	spec := toolbuilder.ToolSpec{
		Name:        "ai_tool_calling_" + generated.Name,
		Language:    "python3",
		Code:        generated.Code,
		Rationale:   nonEmpty(decision.Rationale, generated.Rationale),
		GeneratedBy: a.Name(),
		Timeout:     60 * time.Second,
	}
	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventInfo,
		AgentName: a.Name(),
		Message:   fmt.Sprintf("AI generated sandboxed probe %q", spec.Name),
		Metadata: map[string]string{
			"tool_action": "generate_tool",
		},
	})
	return a.builder.Build(ctx, spec, input.Target, input.Emit)
}

func summarizeToolCallFindings(findings []model.Finding) []map[string]any {
	if len(findings) == 0 {
		return nil
	}
	capHint := len(findings)
	if capHint > 12 {
		capHint = 12
	}
	out := make([]map[string]any, 0, capHint)
	for _, f := range findings {
		if len(out) >= 12 {
			break
		}
		out = append(out, map[string]any{
			"id":          f.ID,
			"title":       f.Title,
			"category":    f.Category,
			"severity":    string(f.Severity),
			"affectedUrl": f.AffectedURL,
			"confidence":  f.Confidence,
			"evidence":    truncate(f.Evidence, 180),
		})
	}
	return out
}

func builtInToolNames() []string {
	catalog := toolbuilder.BuiltInTools()
	out := make([]string, 0, len(catalog))
	for name := range catalog {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func hacktricksCategories() []string {
	library := hacktricks.Library()
	out := make([]string, 0, len(library))
	for _, item := range library {
		if cat := strings.TrimSpace(item.Category); cat != "" {
			out = append(out, cat)
		}
	}
	sort.Strings(out)
	return out
}

func appendToolHistory(history []ai.ToolCallHistory, item ai.ToolCallHistory) []ai.ToolCallHistory {
	history = append(history, item)
	if len(history) > maxAIToolCallHistory {
		history = history[len(history)-maxAIToolCallHistory:]
	}
	return history
}

func summarizeCommandHistory(result cmdbuilder.RunResult, findings []model.Finding) ai.ToolCallHistory {
	status := summarizeStatus(findings, result.Error == nil)
	summary := fmt.Sprintf("%s -> %d finding(s)", result.Spec.String(), len(findings))
	if result.Error != nil {
		summary = truncate(result.Error.Error(), 220)
	}
	return ai.ToolCallHistory{
		Action:  "run_command",
		Status:  status,
		Summary: summary,
	}
}

func summarizeStatus(findings []model.Finding, success bool) string {
	switch {
	case !success:
		return "error"
	case len(findings) > 0:
		return "completed"
	default:
		return "no_findings"
	}
}

func selectHackTricksFinding(findings []model.Finding, decision ai.ToolCallDecision) model.Finding {
	if decision.FindingID != "" {
		for _, f := range findings {
			if f.ID == decision.FindingID {
				return f
			}
		}
	}
	category := strings.ToLower(strings.TrimSpace(decision.Category))
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Category), category) || strings.Contains(strings.ToLower(f.Title), category) {
			return f
		}
	}
	return model.Finding{}
}

func setAIToolCallingMetadata(out *AgentOutput, rounds, executed, validationFailures, commandCalls, hacktricksCalls, generatedToolCalls int) {
	out.Metadata["tool_rounds"] = itoa(rounds)
	out.Metadata["tool_actions_executed"] = itoa(executed)
	out.Metadata["validation_failures"] = itoa(validationFailures)
	out.Metadata["command_actions"] = itoa(commandCalls)
	out.Metadata["hacktricks_actions"] = itoa(hacktricksCalls)
	out.Metadata["generated_tool_actions"] = itoa(generatedToolCalls)
}

func nonEmpty(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

func anyToAIClient(v aiToolCaller) *ai.Client {
	client, _ := v.(*ai.Client)
	return client
}
