package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/cmdbuilder"
	"auto-bughunter/backend/internal/model"
)

// DynamicCommandAgent autonomously generates and executes pen testing commands
// tailored to the findings discovered so far.  It uses the cmdbuilder package
// to heuristically compose tool invocations, validates each one against the
// safety policy, runs them, and converts their output into findings.
//
// This agent runs AFTER the scanning and analysis phases so it has the richest
// possible context to work from.

// dynamicCommandChecks lists the logical phases this agent performs. An AI
// advisor provides pre-run focus and writes a post-run lesson to the blackboard.
var dynamicCommandChecks = []string{
	"command_generation",
	"command_execution",
}

type DynamicCommandAgent struct {
	enabled   bool
	generator *cmdbuilder.Generator
}

func NewDynamicCommandAgent(enabled bool) *DynamicCommandAgent {
	return &DynamicCommandAgent{enabled: enabled, generator: &cmdbuilder.Generator{}}
}

func (a *DynamicCommandAgent) Name() string    { return "dynamic_commands" }
func (a *DynamicCommandAgent) Enabled() bool   { return a.enabled }

func (a *DynamicCommandAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   "Dynamic command agent starting — generating custom tool invocations from findings",
	})

	allFindings := input.AllFindings
	if len(allFindings) == 0 {
		allFindings = input.Previous.Findings
	}

	specs := a.generator.Generate(a.Name(), input.Target, allFindings)
	if len(specs) == 0 {
		output.DebugNotes = "No commands generated for current findings context"
		return output, nil
	}

	output.Metadata["commands_generated"] = fmt.Sprintf("%d", len(specs))
	output.Metadata["unsafe_flag_mode"] = fmt.Sprintf("%t", input.Options.UnsafeDynamicCommandFlags)
	ran := 0
	failed := 0

	for _, spec := range specs {
		select {
		case <-ctx.Done():
			output.Status = "partial"
			break
		default:
		}

		result := cmdbuilder.RunWithPolicy(ctx, spec, input.Target, cmdbuilder.ValidationPolicy{
			UnsafeMode: input.Options.UnsafeDynamicCommandFlags,
		}, input.Emit)
		if result.Error != nil {
			failed++
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventInfo,
				AgentName: a.Name(),
				Message:   fmt.Sprintf("Command %q did not succeed: %v", spec.Binary, result.Error),
			})
			continue
		}
		ran++

		// Parse stdout for findings; tools that produce structured output
		// embed JSON lines.  We also do heuristic parsing for plain-text tools.
		findings := parseCommandOutput(result.Stdout, spec, input.Target)
		output.Findings = append(output.Findings, findings...)
	}

	output.Metadata["commands_run"] = fmt.Sprintf("%d", ran)
	output.Metadata["commands_failed"] = fmt.Sprintf("%d", failed)
	output.DebugNotes = fmt.Sprintf("Ran %d/%d dynamic commands; produced %d findings.", ran, len(specs), len(output.Findings))
	return output, nil
}

// parseCommandOutput extracts findings from a command's stdout.  It first
// tries to parse JSON-lines, then falls back to heuristic text parsing.
func parseCommandOutput(out string, spec cmdbuilder.CommandSpec, target string) []model.Finding {
	findings := make([]model.Finding, 0)
	if strings.TrimSpace(out) == "" {
		return findings
	}

	lines := strings.Split(out, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Generic keyword-based heuristics for common tools
		lineLower := strings.ToLower(line)

		switch {
		// sqlmap
		case spec.Binary == "sqlmap" && strings.Contains(lineLower, "parameter") && strings.Contains(lineLower, "injectable"):
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("dynamic-sqli-%d", i),
				Category:       "injection",
				Severity:       model.SeverityHigh,
				Title:          "SQL Injection — parameter confirmed injectable",
				Description:    "sqlmap confirmed a SQL injection vulnerability in a query parameter.",
				Evidence:       line,
				Recommendation: "Use parameterised queries or prepared statements. Sanitise all user input.",
				Sources:        []string{"dynamic:sqlmap"},
				Confidence:     0.92,
			})

		// dalfox XSS
		case spec.Binary == "dalfox" && (strings.Contains(lineLower, "reflected") || strings.Contains(lineLower, "[v]")):
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("dynamic-xss-%d", i),
				Category:       "input_validation",
				Severity:       model.SeverityHigh,
				Title:          "Cross-Site Scripting (XSS) — reflected",
				Description:    "dalfox confirmed a reflected XSS vulnerability.",
				Evidence:       line,
				Recommendation: "Encode all user-controlled output. Enforce a strict Content-Security-Policy.",
				Sources:        []string{"dynamic:dalfox"},
				Confidence:     0.9,
			})

		// wpscan vulnerabilities
		case spec.Binary == "wpscan" && strings.Contains(lineLower, "[!]") && strings.Contains(lineLower, "vulnerabilit"):
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("dynamic-wp-%d", i),
				Category:       "scanning",
				Severity:       model.SeverityMedium,
				Title:          "WordPress vulnerability detected",
				Description:    "WPScan identified a vulnerability in a WordPress component.",
				Evidence:       line,
				Recommendation: "Update WordPress core, plugins, and themes to the latest versions.",
				Sources:        []string{"dynamic:wpscan"},
				Confidence:     0.85,
			})

		// nmap open port
		case spec.Binary == "nmap" && strings.Contains(lineLower, "open") && strings.Contains(lineLower, "/tcp"):
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("dynamic-port-%d", i),
				Category:       "reconnaissance",
				Severity:       model.SeverityInfo,
				Title:          "Open port discovered",
				Description:    fmt.Sprintf("nmap discovered an open TCP port at %s.", target),
				Evidence:       line,
				Recommendation: "Review exposed services and restrict access with firewall rules.",
				Sources:        []string{"dynamic:nmap"},
				Confidence:     0.95,
			})

		// wafw00f WAF detection
		case spec.Binary == "wafw00f" && strings.Contains(lineLower, "is behind"):
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("dynamic-waf-%d", i),
				Category:       "reconnaissance",
				Severity:       model.SeverityInfo,
				Title:          "WAF detected — attack strategy adapted",
				Description:    "A Web Application Firewall was detected. Agent will adapt subsequent probes to evade WAF signatures.",
				Evidence:       line,
				Recommendation: "Ensure WAF rules are kept up to date and supplement with DAST tooling.",
				Sources:        []string{"dynamic:wafw00f"},
				Confidence:     0.88,
			})

		// gobuster/ffuf new paths
		case (spec.Binary == "gobuster" || spec.Binary == "ffuf") &&
			(strings.Contains(lineLower, "status: 200") || strings.Contains(lineLower, "[status]") || strings.Contains(lineLower, " 200 ")):
			if strings.Contains(lineLower, "admin") || strings.Contains(lineLower, "backup") ||
				strings.Contains(lineLower, "config") || strings.Contains(lineLower, ".git") ||
				strings.Contains(lineLower, ".env") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("dynamic-path-%d", i),
					Category:       "information_disclosure",
					Severity:       model.SeverityMedium,
					Title:          "Sensitive path discovered",
					Description:    fmt.Sprintf("%s found a sensitive path that returned HTTP 200.", spec.Binary),
					Evidence:       line,
					Recommendation: "Restrict access to sensitive paths. Remove or protect backup and config files.",
					Sources:        []string{"dynamic:" + spec.Binary},
					Confidence:     0.8,
				})
			}
		}
	}
	return findings
}
