package agent

import (
	"context"
	"fmt"
	"strconv"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// advancedCoverageChecks lists the supplemental probes that extend the core
// scanning pass with stateful and role-aware coverage.
var advancedCoverageChecks = []string{
	"idor_role_diff",
	"business_logic_diff",
	"race_condition",
	"oauth",
	"oauth_session",
	"mfa",
	"login",
	"session_lifecycle",
	"session_edge_cases",
	"magic_link",
	"jwt_advanced",
	"host_header_injection",
	"deserialization",
	"dom_xss",
	"postmessage",
	"browser_storage",
	"flow_engine",
	"surface_diff",
}

type AdvancedCoverageAgent struct {
	scanService *scanner.Service
	enabled     bool
}

func NewAdvancedCoverageAgent(scanService *scanner.Service, enabled bool) *AdvancedCoverageAgent {
	return &AdvancedCoverageAgent{
		scanService: scanService,
		enabled:     enabled,
	}
}

func (a *AdvancedCoverageAgent) Name() string  { return "advanced_coverage" }
func (a *AdvancedCoverageAgent) Enabled() bool { return a.enabled }

func (a *AdvancedCoverageAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}
	if a.scanService == nil {
		output.DebugNotes = "AdvancedCoverageAgent: scanner service unavailable"
		return output, nil
	}
	if input.RoleReplay {
		output.Metadata["skipped"] = "role_replay"
		output.DebugNotes = "AdvancedCoverageAgent: skipped during role replay"
		return output, nil
	}

	output.Findings = append(output.Findings, a.scanService.RunIDORRoleDiff(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.RoleProfiles, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunBusinessLogicDiff(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.RoleProfiles, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunRaceConditionProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunOAuthProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunOAuthSessionProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunMFAProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunLoginProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunSessionLifecycleProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunSessionEdgeCaseAgents(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunMagicLinkProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunJWTAdvancedProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunHostHeaderInjectionProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.OAST, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunDeserializationProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunDOMXSSProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunPostMessageProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunBrowserStorageProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	output.Findings = append(output.Findings, a.scanService.RunFlowEngine(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit, nil)...)

	surfaceFindings, snapshot := a.scanService.RunSurfaceDiffProbe(
		ctx,
		input.Target,
		input.Options,
		input.AuthProfile,
		"",
		input.PriorSurfaceSnapshot,
		input.Emit,
	)
	output.Findings = append(output.Findings, surfaceFindings...)
	output.SurfaceSnapshot = snapshot
	output.Metadata["findings_count"] = strconv.Itoa(len(output.Findings))
	output.Metadata["role_profiles"] = strconv.Itoa(len(input.RoleProfiles))
	if snapshot != nil {
		output.Metadata["surface_snapshot"] = "updated"
	}
	output.DebugNotes = fmt.Sprintf("AdvancedCoverageAgent: executed %d supplemental probe families and produced %d findings.", len(advancedCoverageChecks), len(output.Findings))
	return output, nil
}
