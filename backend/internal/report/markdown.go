package report

import (
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// RenderPentestMarkdown produces a full-pen-test Markdown report from the
// provided ScanJob and template options. It is safe to call with a nil job;
// in that case an empty report scaffold is returned.
func RenderPentestMarkdown(job *model.ScanJob, opts model.ReportTemplateOptions) string {
	data := BuildPentestReportData(job, opts)
	var b strings.Builder

	// --- Cover ---
	b.WriteString("# " + data.Title + "\n\n")
	if opts.CompanyName != "" {
		b.WriteString("**Prepared for:** " + opts.CompanyName + "\n\n")
	}
	if opts.Classification != "" {
		b.WriteString("**Classification:** " + opts.Classification + "\n\n")
	}
	if opts.Contact != "" {
		b.WriteString("**Contact:** " + opts.Contact + "\n\n")
	}
	if opts.ProgramHandle != "" {
		b.WriteString("**Program:** " + opts.ProgramHandle + "\n\n")
	}
	b.WriteString("**Generated:** " + formatTime(data.GeneratedAt) + "\n\n")
	if job != nil {
		b.WriteString("**Target:** " + job.Target + "  \n")
		b.WriteString("**Scan ID:** " + job.ID + "  \n")
		b.WriteString("**Status:** " + job.Status + "  \n")
		b.WriteString("**Started:** " + formatTime(job.StartedAt) + "  \n")
		if job.CompletedAt != nil {
			b.WriteString("**Completed:** " + formatTime(*job.CompletedAt) + "  \n")
		}
		b.WriteString("\n")
	}

	// --- Executive Summary ---
	b.WriteString("## Executive Summary\n\n")
	if job != nil && job.AISummary != "" {
		b.WriteString(job.AISummary + "\n\n")
	} else {
		b.WriteString("This report describes the security assessment performed against the target above. ")
		b.WriteString("Findings are grouped by severity and include CVSS, CWE, OWASP mapping, reproduction ")
		b.WriteString("steps, and recommended remediation.\n\n")
	}

	// Severity counts
	b.WriteString("### Findings Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|------:|\n")
	for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", sevDisplay(sev), data.SeverityCounts[sev]))
	}
	b.WriteString("\n")

	// --- Scope & Methodology ---
	b.WriteString("## Scope & Methodology\n\n")
	if job != nil {
		if len(job.Scope.IncludeHosts) > 0 {
			b.WriteString("**In-scope hosts:** " + strings.Join(job.Scope.IncludeHosts, ", ") + "\n\n")
		}
		if len(job.Scope.ExcludeHosts) > 0 {
			b.WriteString("**Out-of-scope hosts:** " + strings.Join(job.Scope.ExcludeHosts, ", ") + "\n\n")
		}
		if len(job.DisallowedTestTypes) > 0 {
			b.WriteString("**Disallowed test types:** " + strings.Join(job.DisallowedTestTypes, ", ") + "\n\n")
		}
	}
	b.WriteString(methodologyText() + "\n\n")

	// --- Risk Rating Methodology ---
	b.WriteString("## Risk Rating Methodology\n\n")
	b.WriteString(riskRatingMethodologyText() + "\n\n")

	// --- Findings (grouped by severity) ---
	b.WriteString("## Findings\n\n")
	target := ""
	if job != nil {
		target = job.Target
	}
	if len(data.Findings) == 0 {
		b.WriteString("_No findings were produced for this scan._\n\n")
	}
	for _, group := range FindingsBySeverity(data.Findings) {
		b.WriteString(fmt.Sprintf("### %s (%d)\n\n", sevDisplay(group.Severity), len(group.Items)))
		for i, f := range group.Items {
			writeFindingMarkdown(&b, i+1, f, target)
		}
	}

	// --- Appendix ---
	b.WriteString("## Appendix A — Tools Used\n\n")
	if len(data.ToolsUsed) == 0 {
		b.WriteString("- Built-in HTTP/TLS/wordlist checks (native Go modules)\n\n")
	} else {
		for _, t := range data.ToolsUsed {
			b.WriteString("- " + t + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Appendix B — Commands Executed\n\n")
	if len(data.CommandsUsed) == 0 {
		b.WriteString("- (no external commands)\n\n")
	} else {
		for _, c := range data.CommandsUsed {
			b.WriteString("- `" + c + "`\n")
		}
		b.WriteString("\n")
	}

	if job != nil && len(job.AuditTrail) > 0 {
		b.WriteString("## Appendix C — Audit Trail\n\n")
		for _, ev := range job.AuditTrail {
			b.WriteString(fmt.Sprintf("- %s — **%s**: %s\n", formatTime(ev.Timestamp), ev.Stage, ev.Message))
		}
		b.WriteString("\n")
	}

	if len(data.AssetsDiscovered) > 0 {
		b.WriteString("## Appendix D — Assets Discovered\n\n")
		for _, a := range data.AssetsDiscovered {
			val := nonEmpty(a.AssetValue, a.AssetKey)
			b.WriteString(fmt.Sprintf("- [%s] %s\n", a.AssetType, val))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func writeFindingMarkdown(b *strings.Builder, index int, f model.Finding, target string) {
	b.WriteString(fmt.Sprintf("#### %d. %s\n\n", index, f.Title))

	rows := [][2]string{
		{"Severity", sevDisplay(f.Severity)},
		{"Category", f.Category},
		{"CWE", f.CWE},
		{"OWASP", f.OWASPCategory},
		{"CVSS", fmtCVSS(f.CVSSScore, f.CVSSVector)},
		{"Affected URL", findingAsset(f, target)},
		{"Affected Parameter", f.AffectedParameter},
	}
	for _, row := range rows {
		if strings.TrimSpace(row[1]) != "" {
			b.WriteString(fmt.Sprintf("- **%s:** %s\n", row[0], row[1]))
		}
	}
	b.WriteString("\n")

	if f.Description != "" {
		b.WriteString("**Description**\n\n" + f.Description + "\n\n")
	}
	if f.Impact != "" {
		b.WriteString("**Impact**\n\n" + f.Impact + "\n\n")
	}
	if len(f.ReproductionSteps) > 0 {
		b.WriteString("**Reproduction Steps**\n\n")
		for i, s := range f.ReproductionSteps {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, s))
		}
		b.WriteString("\n")
	}
	if f.Evidence != "" {
		b.WriteString("**Evidence**\n\n```\n" + f.Evidence + "\n```\n\n")
	}
	if f.PoC != "" {
		b.WriteString("**Proof of Concept**\n\n```\n" + f.PoC + "\n```\n\n")
	}
	if f.Recommendation != "" {
		b.WriteString("**Remediation**\n\n" + f.Recommendation + "\n\n")
	}
	if len(f.References) > 0 {
		b.WriteString("**References**\n\n")
		for _, r := range f.References {
			b.WriteString("- " + r + "\n")
		}
		b.WriteString("\n")
	}
}

// RenderExecutiveMarkdown produces a short executive summary suitable for
// stakeholders. It contains the key counts and the AI summary if present.
func RenderExecutiveMarkdown(job *model.ScanJob, opts model.ReportTemplateOptions) string {
	data := BuildPentestReportData(job, opts)
	var b strings.Builder
	b.WriteString("# Executive Security Summary\n\n")
	if opts.CompanyName != "" {
		b.WriteString("**Prepared for:** " + opts.CompanyName + "\n\n")
	}
	b.WriteString("**Generated:** " + formatTime(data.GeneratedAt) + "\n\n")
	if job != nil {
		b.WriteString("**Target:** " + job.Target + "\n\n")
		b.WriteString("**Status:** " + job.Status + "\n\n")
	}

	b.WriteString("## Key Metrics\n\n")
	b.WriteString("| Severity | Count |\n|----------|------:|\n")
	for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", sevDisplay(sev), data.SeverityCounts[sev]))
	}
	b.WriteString("\n")

	if job != nil && job.AISummary != "" {
		b.WriteString("## Summary\n\n" + job.AISummary + "\n\n")
	}
	if job != nil && len(job.NextActions) > 0 {
		b.WriteString("## Recommended Next Actions\n\n")
		for _, a := range job.NextActions {
			b.WriteString("- " + a + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}
