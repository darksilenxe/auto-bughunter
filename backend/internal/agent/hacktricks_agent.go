package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/cmdbuilder"
	"auto-bughunter/backend/internal/hacktricks"
	"auto-bughunter/backend/internal/model"
)

// HackTricksAgent bridges the HackTricks technique library to live execution.
//
// For each finding discovered by earlier agents the HackTricksAgent:
//  1. Looks up matching HackTricks technique templates from the curated library.
//  2. Asks the coding LLM to adapt the templates to the specific target and
//     finding evidence — filling in {{TARGET}}, {{PARAM}}, etc. with real values.
//  3. Falls back to simple placeholder substitution when no coding LLM is
//     available.
//  4. Validates every adapted command against the cmdbuilder safety policy.
//  5. Executes approved commands and converts their output into findings.
//
// The agent never runs more than maxTechniquesPerFinding commands per finding
// to bound execution time.  It respects context cancellation at every step.
type HackTricksAgent struct {
	enabled  bool
	aiClient *ai.Client
}

const maxTechniquesPerFinding = 3

// NewHackTricksAgent constructs the agent. aiClient may be nil; when nil the
// agent falls back to simple placeholder substitution for all templates.
func NewHackTricksAgent(enabled bool, aiClient *ai.Client) *HackTricksAgent {
	return &HackTricksAgent{enabled: enabled, aiClient: aiClient}
}

func (a *HackTricksAgent) Name() string  { return "hacktricks_techniques" }
func (a *HackTricksAgent) Enabled() bool { return a.enabled }

func (a *HackTricksAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   "HackTricks technique agent starting — matching findings to curated attack templates",
	})

	allFindings := input.AllFindings
	if len(allFindings) == 0 {
		allFindings = input.Previous.Findings
	}
	if len(allFindings) == 0 {
		output.DebugNotes = "HackTricksAgent: no findings available; skipping"
		return output, nil
	}

	target := strings.TrimSpace(input.Target)
	if target == "" {
		output.DebugNotes = "HackTricksAgent: no target; skipping"
		return output, nil
	}
	host := extractHostname(target)
	path := extractPath(target)

	cmdsRun := 0
	cmdsSkipped := 0
	uniqueCategories := map[string]bool{}

	for _, finding := range allFindings {
		select {
		case <-ctx.Done():
			output.Status = "partial"
			goto done
		default:
		}

		keywords := categoryKeywords(finding)
		if len(keywords) == 0 {
			continue
		}

		techniques := hacktricks.ForCategories(keywords...)
		if len(techniques) == 0 {
			continue
		}

		for _, tech := range techniques {
			if uniqueCategories[tech.Category] {
				continue
			}
			uniqueCategories[tech.Category] = true

			// Cap templates per finding to avoid excessive runtime.
			templates := tech.CommandTemplates
			if len(templates) > maxTechniquesPerFinding {
				templates = templates[:maxTechniquesPerFinding]
			}

			specs := a.buildCommandSpecs(ctx, templates, finding, target, host, path)

			for _, spec := range specs {
				select {
				case <-ctx.Done():
					output.Status = "partial"
					goto done
				default:
				}

				Emit(input.Emit, model.ScanEvent{
					Type:      model.ScanEventInfo,
					AgentName: a.Name(),
					Message: fmt.Sprintf("HackTricks [%s] → %s (ref: %s)",
						tech.Category, spec.String(), tech.HackTricksURL),
				})

				result := cmdbuilder.Run(ctx, spec, target, input.Emit)
				if result.Error != nil {
					cmdsSkipped++
					Emit(input.Emit, model.ScanEvent{
						Type:      model.ScanEventInfo,
						AgentName: a.Name(),
						Message:   fmt.Sprintf("Command %q did not complete: %v", spec.Binary, result.Error),
					})
					continue
				}
				cmdsRun++

				findings := parseHackTricksOutput(result, spec, finding, target, tech.Category, tech.HackTricksURL)
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
	}

done:
	output.Metadata["commands_run"] = fmt.Sprintf("%d", cmdsRun)
	output.Metadata["commands_skipped"] = fmt.Sprintf("%d", cmdsSkipped)
	output.Metadata["categories_covered"] = fmt.Sprintf("%d", len(uniqueCategories))
	output.DebugNotes = fmt.Sprintf(
		"HackTricksAgent: ran %d commands across %d vuln categories; produced %d findings.",
		cmdsRun, len(uniqueCategories), len(output.Findings),
	)
	return output, nil
}

// buildCommandSpecs converts CommandTemplates to cmdbuilder.CommandSpec slices.
// When an AI client is configured it calls AdaptTechniqueCommands to let the
// coding LLM fill in the placeholders intelligently; otherwise it falls back to
// simple string substitution via hacktricks.Substitute.
func (a *HackTricksAgent) buildCommandSpecs(
	ctx context.Context,
	templates []hacktricks.CommandTemplate,
	finding model.Finding,
	target, host, path string,
) []cmdbuilder.CommandSpec {
	param := extractParam(finding.Evidence)

	// Try AI adaptation first.
	if a.aiClient != nil {
		rawTemplates := make([]string, len(templates))
		for i, t := range templates {
			rawTemplates[i] = t.Binary + " " + strings.Join(t.ArgsTemplate, " ")
		}
		adapted := a.aiClient.AdaptTechniqueCommands(
			ctx, rawTemplates, finding.Title, finding.Evidence, target,
		)
		if len(adapted) > 0 {
			specs := make([]cmdbuilder.CommandSpec, 0, len(adapted))
			for _, ac := range adapted {
				specs = append(specs, cmdbuilder.CommandSpec{
					Binary:      ac.Binary,
					Args:        ac.Args,
					Rationale:   ac.Rationale,
					GeneratedBy: a.Name(),
					Timeout:     60 * time.Second,
				})
			}
			return specs
		}
	}

	// Fallback: simple placeholder substitution.
	specs := make([]cmdbuilder.CommandSpec, 0, len(templates))
	for _, tmpl := range templates {
		adaptedArgs := hacktricks.Substitute(tmpl.ArgsTemplate, target, host, path, param)
		specs = append(specs, cmdbuilder.CommandSpec{
			Binary:      tmpl.Binary,
			Args:        adaptedArgs,
			Rationale:   tmpl.Description,
			GeneratedBy: a.Name(),
			Timeout:     60 * time.Second,
		})
	}
	return specs
}

// parseHackTricksOutput interprets the stdout of a completed command and
// returns any findings.  It applies category-specific heuristics and also
// scans for generic vulnerability signals in the output.
func parseHackTricksOutput(
	result cmdbuilder.RunResult,
	spec cmdbuilder.CommandSpec,
	sourceFinding model.Finding,
	target, category, referenceURL string,
) []model.Finding {
	out := strings.TrimSpace(result.Stdout)
	if out == "" {
		return nil
	}

	var findings []model.Finding
	lines := strings.Split(out, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)

		switch category {
		case "xss":
			if strings.Contains(low, "reflected") || strings.Contains(low, "[v]") ||
				strings.Contains(low, "parameter") && strings.Contains(low, "vulnerable") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-xss-%d", i),
					Category:       "input_validation",
					Severity:       model.SeverityHigh,
					Title:          "Cross-Site Scripting (XSS) — HackTricks technique confirmed",
					Description:    fmt.Sprintf("HackTricks XSS technique (%s) produced a confirmed reflection. Tool: %s.", referenceURL, spec.Binary),
					Evidence:       line,
					Recommendation: "Encode all user-controlled output. Enforce a strict Content-Security-Policy.",
					Sources:        []string{"hacktricks:" + spec.Binary},
					Confidence:     0.88,
				})
			}

		case "sqli":
			if (strings.Contains(low, "parameter") && strings.Contains(low, "injectable")) ||
				strings.Contains(low, "sql injection") || strings.Contains(low, "vulnerable") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-sqli-%d", i),
					Category:       "injection",
					Severity:       model.SeverityHigh,
					Title:          "SQL Injection — HackTricks sqlmap confirmed",
					Description:    fmt.Sprintf("sqlmap (HackTricks ref: %s) confirmed SQL injection.", referenceURL),
					Evidence:       line,
					Recommendation: "Use parameterised queries. Sanitise all user input.",
					Sources:        []string{"hacktricks:sqlmap"},
					Confidence:     0.92,
				})
			}

		case "ssrf":
			// Any 200 response to our internal probe URL is suspicious.
			if strings.Contains(line, "200") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-ssrf-%d", i),
					Category:       "ssrf",
					Severity:       model.SeverityHigh,
					Title:          "SSRF — Internal endpoint reachable via parameter",
					Description:    fmt.Sprintf("SSRF probe (HackTricks ref: %s) received HTTP 200 from an internal resource.", referenceURL),
					Evidence:       line,
					Recommendation: "Validate and allowlist outbound request targets. Block internal IP ranges.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.80,
				})
			}

		case "ssti":
			// Look for "49" (7*7) appearing in the response body.
			if strings.Contains(line, "49") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-ssti-%d", i),
					Category:       "injection",
					Severity:       model.SeverityHigh,
					Title:          "SSTI — Template expression evaluated (7×7=49)",
					Description:    fmt.Sprintf("SSTI probe (HackTricks ref: %s) returned 49 — arithmetic was evaluated by the template engine.", referenceURL),
					Evidence:       line,
					Recommendation: "Never pass user input directly to template renderers. Use sandboxed rendering.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.85,
				})
			}

		case "path_traversal":
			if strings.Contains(low, "root:") || strings.Contains(low, "bin/bash") || strings.Contains(low, "daemon:") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-lfi-%d", i),
					Category:       "information_disclosure",
					Severity:       model.SeverityHigh,
					Title:          "Path Traversal / LFI — /etc/passwd read",
					Description:    fmt.Sprintf("Path traversal probe (HackTricks ref: %s) returned /etc/passwd content.", referenceURL),
					Evidence:       line,
					Recommendation: "Validate all file path inputs. Canonicalise paths and restrict to a safe base directory.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.95,
				})
			}

		case "xxe":
			if strings.Contains(low, "root:") || strings.Contains(low, "bin/bash") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-xxe-%d", i),
					Category:       "injection",
					Severity:       model.SeverityHigh,
					Title:          "XXE — File read via XML External Entity",
					Description:    fmt.Sprintf("XXE probe (HackTricks ref: %s) returned /etc/passwd content.", referenceURL),
					Evidence:       line,
					Recommendation: "Disable external entity processing in the XML parser.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.95,
				})
			}

		case "open_redirect":
			if strings.Contains(low, "evil.com") && len(line) > 0 {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-redirect-%d", i),
					Category:       "cors_redirect",
					Severity:       model.SeverityMedium,
					Title:          "Open Redirect — attacker-controlled destination accepted",
					Description:    fmt.Sprintf("Open redirect probe (HackTricks ref: %s) confirmed redirect to evil.com.", referenceURL),
					Evidence:       line,
					Recommendation: "Validate redirect targets against an allowlist. Reject absolute URLs to external domains.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.88,
				})
			}

		case "cors":
			if strings.Contains(low, "access-control-allow-origin: https://evil.com") ||
				strings.Contains(low, "access-control-allow-origin: null") ||
				strings.Contains(low, "access-control-allow-origin: *") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-cors-%d", i),
					Category:       "cors_redirect",
					Severity:       model.SeverityHigh,
					Title:          "CORS Misconfiguration — arbitrary origin reflected",
					Description:    fmt.Sprintf("CORS probe (HackTricks ref: %s) found Access-Control-Allow-Origin reflecting the attacker origin.", referenceURL),
					Evidence:       line,
					Recommendation: "Restrict ACAO to a strict allowlist of trusted origins. Never echo the request Origin blindly.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.90,
				})
			}

		case "command_injection":
			// A total_time > 4.5 seconds for a sleep-5 probe is a strong signal.
			if strings.Contains(low, "4.") || strings.Contains(low, "5.") || strings.Contains(low, "6.") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-cmdi-%d", i),
					Category:       "injection",
					Severity:       model.SeverityHigh,
					Title:          "Command Injection — timing oracle (sleep 5s) triggered",
					Description:    fmt.Sprintf("Command injection probe (HackTricks ref: %s) showed a >4s delay, indicating OS command execution.", referenceURL),
					Evidence:       fmt.Sprintf("response time: %s", line),
					Recommendation: "Never pass user input to shell commands. Use safe APIs and parameterised execution.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.75,
				})
			}

		case "auth_bypass":
			if strings.Contains(line, "200") || strings.Contains(line, "302") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-auth-%d", i),
					Category:       "access_control",
					Severity:       model.SeverityHigh,
					Title:          "Auth Bypass — unexpected " + line + " response to tampered request",
					Description:    fmt.Sprintf("Auth bypass probe (HackTricks ref: %s) received an unexpected success response.", referenceURL),
					Evidence:       spec.String() + " → " + line,
					Recommendation: "Enforce authentication checks on the server side regardless of HTTP verb or headers.",
					Sources:        []string{"hacktricks:curl"},
					Confidence:     0.70,
				})
			}

		case "information_disclosure":
			if (strings.Contains(low, "db_password") || strings.Contains(low, "secret") ||
				strings.Contains(low, "api_key") || strings.Contains(low, "aws_")) &&
				!strings.Contains(line, "404") {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("ht-infodiscl-%d", i),
					Category:       "information_disclosure",
					Severity:       model.SeverityHigh,
					Title:          "Sensitive data exposed in accessible file",
					Description:    fmt.Sprintf("Information disclosure probe (HackTricks ref: %s) found credential-like content.", referenceURL),
					Evidence:       line,
					Recommendation: "Remove sensitive files from the web root. Restrict access with server configuration.",
					Sources:        []string{"hacktricks:" + spec.Binary},
					Confidence:     0.82,
				})
			}
		}
	}

	// Generic: annotate the source finding with HackTricks reference if we
	// ran successfully but found nothing decisive — the output is still
	// valuable context for the analyst.
	if len(findings) == 0 && len(out) > 0 && result.ExitCode == 0 {
		annotated := sourceFinding
		annotated.ID = fmt.Sprintf("ht-recheck-%s", sourceFinding.ID)
		annotated.Sources = appendUnique(sourceFinding.Sources, "hacktricks:"+spec.Binary)
		annotated.EvidenceFields["hacktricksRef"] = referenceURL
		annotated.EvidenceFields["hacktricksOutput"] = truncate(out, 512)
		findings = append(findings, annotated)
	}

	return findings
}

// ─── helpers ────────────────────────────────────────────────────────────────

// categoryKeywords maps a finding's category and title tokens to the
// keywords used by hacktricks.ForCategories for lookup.
func categoryKeywords(f model.Finding) []string {
	combined := strings.ToLower(f.Category + " " + f.Title)
	var kw []string
	for _, pair := range []struct{ token, keyword string }{
		{"xss", "xss"}, {"cross-site script", "xss"},
		{"sqli", "sqli"}, {"sql inject", "sqli"}, {"sql", "sqli"},
		{"ssrf", "ssrf"}, {"server-side request", "ssrf"},
		{"idor", "idor"}, {"broken object", "idor"}, {"insecure direct", "idor"},
		{"ssti", "ssti"}, {"template inject", "ssti"},
		{"path traversal", "path_traversal"}, {"lfi", "path_traversal"}, {"file inclusion", "path_traversal"},
		{"xxe", "xxe"}, {"xml external", "xxe"},
		{"open redirect", "open_redirect"}, {"redirect", "open_redirect"},
		{"cors", "cors"},
		{"command inject", "command_injection"}, {"rce", "command_injection"}, {"os inject", "command_injection"},
		{"jwt", "jwt"},
		{"auth bypass", "auth_bypass"}, {"login bypass", "auth_bypass"},
		{"mass assignment", "mass_assignment"},
		{"subdomain takeover", "subdomain_takeover"},
		{"information disclosure", "information_disclosure"}, {"info disclosure", "information_disclosure"},
		{"sensitive data", "information_disclosure"},
		{"request smuggling", "request_smuggling"}, {"http smuggling", "request_smuggling"},
	} {
		if strings.Contains(combined, pair.token) {
			kw = append(kw, pair.keyword)
		}
	}
	return kw
}

func extractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}

func extractPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

// extractParam tries to pull a query parameter name from the finding evidence.
// It returns "id" as a safe default when no parameter can be identified.
func extractParam(evidence string) string {
	// Look for a URL with a query string in the evidence text.
	for _, part := range strings.Fields(evidence) {
		if strings.HasPrefix(part, "http") {
			u, err := url.Parse(part)
			if err != nil {
				continue
			}
			for key := range u.Query() {
				return key
			}
		}
	}
	// Fall back to common parameter tokens mentioned in the evidence.
	low := strings.ToLower(evidence)
	for _, p := range []string{"param", "parameter", "field", "query"} {
		idx := strings.Index(low, p+"=")
		if idx >= 0 {
			end := strings.IndexAny(evidence[idx:], " &\"'")
			if end < 0 {
				end = len(evidence) - idx
			}
			val := strings.SplitN(evidence[idx:idx+end], "=", 2)
			if len(val) == 2 && val[1] != "" {
				return val[1]
			}
		}
	}
	return "id"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
