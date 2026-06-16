package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// JavaScriptSASTAgent captures the JavaScript a target ships and runs a static
// analysis (SAST) pass over it during reconnaissance. It serves two purposes:
//
//   - It emits code-level weakness findings (DOM XSS sinks, eval/new Function,
//     insecure postMessage handlers, secrets in client storage, ...). The
//     finding categories let the planner tailor which active probes to run
//     next. When the static pass finds nothing the scan is unaffected and the
//     platform continues hunting for every vulnerability class as usual.
//   - It extracts web-application routes referenced from the code and records
//     them in metadata so the wordlist agent can probe real, code-confirmed
//     endpoints directly instead of brute-forcing the full wordlist.

// jsSASTChecks lists the weakness classes this agent inspects. An AI advisor
// may reorder or skip entries based on the tech stack or prior findings.
var jsSASTChecks = []string{
	"dom_xss",
	"eval_injection",
	"postmessage_security",
	"client_storage_secrets",
	"route_extraction",
}

type JavaScriptSASTAgent struct {
	scanService *scanner.Service
	enabled     bool
}

func NewJavaScriptSASTAgent(scanService *scanner.Service, enabled bool) *JavaScriptSASTAgent {
	return &JavaScriptSASTAgent{scanService: scanService, enabled: enabled}
}

func (a *JavaScriptSASTAgent) Name() string { return "js_sast" }

func (a *JavaScriptSASTAgent) Enabled() bool { return a.enabled && a.scanService != nil }

func (a *JavaScriptSASTAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if a.scanService == nil {
		output.DebugNotes = "scan service unavailable; skipping JavaScript SAST."
		output.Metadata["findings_count"] = "0"
		return output, nil
	}

	result, err := a.scanService.RunJavaScriptSAST(ctx, scanner.RunInput{
		Target:      input.Target,
		AuthProfile: input.AuthProfile,
		Options:     input.Options,
		Scope:       input.Scope,
		Emit:        input.Emit,
	}, "")
	if err != nil {
		return output, err
	}

	output.Findings = append(output.Findings, result.Findings...)
	output.Metadata["scripts_analyzed"] = fmt.Sprintf("%d", result.ScriptsAnalyzed)
	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(result.Findings))

	bugCount := 0
	for _, f := range result.Findings {
		if f.Category == "code-defect" {
			bugCount++
		}
	}
	if bugCount > 0 {
		output.Metadata["code_defects_found"] = fmt.Sprintf("%d", bugCount)
	}

	if len(result.Routes) > 0 {
		// Recorded so the wordlist agent can probe these confirmed routes
		// directly for a faster, focused enumeration pass.
		output.Metadata["discovered_routes"] = strings.Join(result.Routes, ",")
		output.Metadata["routes_found"] = fmt.Sprintf("%d", len(result.Routes))
	}
	if len(result.VulnCategories) > 0 {
		// Surfaced so the planner can prioritize the matching active probes.
		output.Metadata["sast_vuln_categories"] = strings.Join(result.VulnCategories, ",")
	}

	if input.SharedScanContext != nil {
		if routes := output.Metadata["discovered_routes"]; routes != "" {
			for _, r := range strings.Split(routes, ",") {
				r = strings.TrimSpace(r)
				if r == "" {
					continue
				}
				input.SharedScanContext.AddEndpoint(r)
				input.SharedScanContext.AddDiscovery(DiscoveryEvent{
					Kind:        DiscoveryAPIRoute,
					Value:       r,
					SourceAgent: a.Name(),
					Confidence:  0.85,
				}, input.Emit)
			}
		}
		if cats := output.Metadata["sast_vuln_categories"]; cats != "" {
			input.SharedScanContext.AddDiscovery(DiscoveryEvent{
				Kind:        DiscoveryGeneric,
				Value:       "sast_categories=" + cats,
				SourceAgent: a.Name(),
				Confidence:  0.8,
			}, input.Emit)
		}
	}

	output.DebugNotes = fmt.Sprintf(
		"JavaScript SAST analyzed %d bundle(s): %d finding(s) (%d code defect(s)), %d code-discovered route(s), categories=[%s].",
		result.ScriptsAnalyzed, len(result.Findings), bugCount, len(result.Routes), strings.Join(result.VulnCategories, ","),
	)
	return output, nil
}

// sastDiscoveredRoutes scans prior agent history for routes the JavaScript SAST
// agent extracted from the target's code. The wordlist agent uses these to run
// a focused, faster enumeration pass over confirmed-from-code endpoints.
func sastDiscoveredRoutes(history []AgentOutput) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, h := range history {
		if h.AgentName != "js_sast" || h.Metadata == nil {
			continue
		}
		raw := strings.TrimSpace(h.Metadata["discovered_routes"])
		if raw == "" {
			continue
		}
		for _, r := range strings.Split(raw, ",") {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	return out
}
