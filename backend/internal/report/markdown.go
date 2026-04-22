package report

import (
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// RenderPentestMarkdown produces a full-pen-test Markdown report from the
// provided ScanJob and template options. It is safe to call with a nil job;
// in that case an empty report scaffold is returned.
func RenderPentestMarkdown(job *model.ScanJob, opts model.ReportTemplateOptions, ctx ...ReportContext) string {
	data := BuildPentestReportData(job, opts, ctx...)
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

	if data.SecurityKnowledge != nil && len(data.SecurityKnowledge.References) > 0 {
		b.WriteString("## Security Knowledge References\n\n")
		if data.SecurityKnowledge.LicenseNotice != "" {
			b.WriteString(data.SecurityKnowledge.LicenseNotice + "\n\n")
		}
		for _, ref := range data.SecurityKnowledge.References {
			b.WriteString(fmt.Sprintf("- **%s** (%s) — %s\n", ref.Title, ref.URL, ref.Passage))
		}
		b.WriteString("\n")
	}

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

	// --- Attack Paths ---
	if len(data.AttackPaths) > 0 {
		b.WriteString("## Attack Paths\n\n")
		b.WriteString("The following chained attack paths demonstrate proven impact by combining individual findings into an end-to-end exploitation narrative.\n\n")
		for i, ap := range data.AttackPaths {
			b.WriteString(fmt.Sprintf("### Path %d — %s\n\n", i+1, ap.Title))
			for _, st := range ap.Steps {
				detail := st.Detail
				if detail != "" {
					detail = " — " + detail
				}
				b.WriteString(fmt.Sprintf("%d. **[%s]** %s%s\n", st.Step, sevDisplay(st.Severity), st.Title, detail))
			}
			if ap.Impact != "" {
				b.WriteString("\n> " + ap.Impact + "\n")
			}
			b.WriteString("\n")
		}
	}

	// --- Remediation Priorities (Fix Actions) ---
	if len(data.RemediationPriorities) > 0 {
		b.WriteString("## Remediation Priorities\n\n")
		b.WriteString("Recommendations are ordered by severity-weighted impact reduction. Fixing the items at the top of this list resolves the most risk per unit of effort.\n\n")
		b.WriteString("| Rank | Severity | Affected Findings | Affected Assets | Recommendation |\n")
		b.WriteString("|-----:|----------|------------------:|----------------:|----------------|\n")
		for _, p := range data.RemediationPriorities {
			b.WriteString(fmt.Sprintf("| %d | %s | %d | %d | %s |\n",
				p.Rank, sevDisplay(p.HighestSeverity), p.AffectedFindings, p.AffectedAssets, mdEscapeCell(p.Recommendation)))
		}
		b.WriteString("\n")
	}

	writeRankingRationaleMarkdown(&b, data.Job)
	writeAgentScheduleRationaleMarkdown(&b, data.Job)

	// --- Per-Asset Rollup ---
	if len(data.AssetRollup) > 0 {
		b.WriteString("## Per-Asset Rollup\n\n")
		b.WriteString("Findings grouped by asset (host) so a single owner can see everything that needs attention on one system.\n\n")
		b.WriteString("| Asset | High | Medium | Low | Info | Sample Finding |\n")
		b.WriteString("|-------|-----:|-------:|----:|-----:|----------------|\n")
		for _, r := range data.AssetRollup {
			sample := ""
			if len(r.FindingTitles) > 0 {
				sample = r.FindingTitles[0]
			}
			b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %s |\n",
				mdEscapeCell(r.Asset), r.HighCount, r.MediumCount, r.LowCount, r.InfoCount, mdEscapeCell(sample)))
		}
		b.WriteString("\n")
	}

	// --- Findings Delta ---
	if data.Delta.HasPrevious {
		b.WriteString("## What Changed Since Last Engagement\n\n")
		b.WriteString(fmt.Sprintf("Comparison against previous scan `%s`.\n\n", data.Delta.PreviousScanID))
		b.WriteString(fmt.Sprintf("- **New findings:** %d\n", len(data.Delta.NewFindings)))
		b.WriteString(fmt.Sprintf("- **Resolved findings:** %d\n", len(data.Delta.ResolvedFindings)))
		b.WriteString(fmt.Sprintf("- **Carried over (unchanged):** %d\n\n", data.Delta.UnchangedCount))
		if len(data.Delta.NewFindings) > 0 {
			b.WriteString("### New Findings\n\n")
			for _, f := range data.Delta.NewFindings {
				b.WriteString(fmt.Sprintf("- **[%s]** %s\n", sevDisplay(f.Severity), f.Title))
			}
			b.WriteString("\n")
		}
		if len(data.Delta.ResolvedFindings) > 0 {
			b.WriteString("### Resolved Findings\n\n")
			for _, f := range data.Delta.ResolvedFindings {
				b.WriteString(fmt.Sprintf("- **[%s]** %s\n", sevDisplay(f.Severity), f.Title))
			}
			b.WriteString("\n")
		}
	}

	// --- Visual Evidence ---
	if len(data.Screenshots) > 0 {
		b.WriteString("## Visual Evidence\n\n")
		b.WriteString(fmt.Sprintf("%d screenshot(s) captured during the engagement (Markdown report references only; full images are embedded in the HTML/PDF deliverables).\n\n", len(data.Screenshots)))
		for i, sh := range data.Screenshots {
			label := nonEmpty(sh.Caption, sh.URL, fmt.Sprintf("screenshot-%d", i+1))
			b.WriteString(fmt.Sprintf("- %s\n", label))
		}
		b.WriteString("\n")
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

	if len(data.ComplianceMatrix) > 0 {
		b.WriteString("## Appendix E — Compliance Crosswalk\n\n")
		b.WriteString("Findings mapped to PCI DSS v4.0, HIPAA Security Rule, and SOC 2 (Common Criteria) controls. Empty cells indicate no deterministic mapping is available for the underlying CWE.\n\n")
		b.WriteString("| Severity | Finding | CWE | OWASP | PCI DSS | HIPAA | SOC 2 |\n")
		b.WriteString("|----------|---------|-----|-------|---------|-------|-------|\n")
		for _, m := range data.ComplianceMatrix {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
				sevDisplay(m.Severity),
				mdEscapeCell(m.FindingTitle),
				mdEscapeCell(m.CWE),
				mdEscapeCell(m.OWASP),
				mdEscapeCell(m.PCI),
				mdEscapeCell(m.HIPAA),
				mdEscapeCell(m.SOC2),
			))
		}
		b.WriteString("\n")
	}

	if data.ContentHash != "" {
		b.WriteString("---\n\n")
		b.WriteString("_Document content hash (SHA-256): `" + data.ContentHash + "`_\n")
	}

	return b.String()
}

// mdEscapeCell escapes characters that would break a Markdown table cell.
func mdEscapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
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
func RenderExecutiveMarkdown(job *model.ScanJob, opts model.ReportTemplateOptions, ctx ...ReportContext) string {
	data := BuildPentestReportData(job, opts, ctx...)
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
	if data.Delta.HasPrevious {
		b.WriteString(fmt.Sprintf("## Trend vs. Previous Engagement (`%s`)\n\n", data.Delta.PreviousScanID))
		b.WriteString(fmt.Sprintf("- New: %d  \n- Resolved: %d  \n- Carried over: %d\n\n",
			len(data.Delta.NewFindings), len(data.Delta.ResolvedFindings), data.Delta.UnchangedCount))
	}
	if len(data.RemediationPriorities) > 0 {
		b.WriteString("## Top Remediation Priorities\n\n")
		max := len(data.RemediationPriorities)
		if max > 5 {
			max = 5
		}
		for i := 0; i < max; i++ {
			p := data.RemediationPriorities[i]
			b.WriteString(fmt.Sprintf("%d. **[%s]** %s _(%d findings, %d assets)_\n",
				p.Rank, sevDisplay(p.HighestSeverity), p.Recommendation, p.AffectedFindings, p.AffectedAssets))
		}
		b.WriteString("\n")
	}
	if job != nil && len(job.NextActions) > 0 {
		b.WriteString("## Recommended Next Actions\n\n")
		for _, a := range job.NextActions {
			b.WriteString("- " + a + "\n")
		}
		b.WriteString("\n")
	}
	if data.ContentHash != "" {
		b.WriteString("---\n\n")
		b.WriteString("_Document content hash (SHA-256): `" + data.ContentHash + "`_\n")
	}
	return b.String()
}

// RenderComplianceMarkdown produces a focused compliance crosswalk report.
// It re-uses the same severity table from the pen-test deliverable but the
// body is a flat list of finding-to-control mappings.
func RenderComplianceMarkdown(job *model.ScanJob, opts model.ReportTemplateOptions, ctx ...ReportContext) string {
	opts.ReportType = "compliance"
	data := BuildPentestReportData(job, opts, ctx...)
	var b strings.Builder
	b.WriteString("# " + data.Title + "\n\n")
	if opts.CompanyName != "" {
		b.WriteString("**Prepared for:** " + opts.CompanyName + "\n\n")
	}
	if opts.Classification != "" {
		b.WriteString("**Classification:** " + opts.Classification + "\n\n")
	}
	b.WriteString("**Generated:** " + formatTime(data.GeneratedAt) + "\n\n")
	if job != nil {
		b.WriteString("**Target:** " + job.Target + "  \n")
		b.WriteString("**Scan ID:** " + job.ID + "\n\n")
	}

	b.WriteString("## Severity Summary\n\n")
	b.WriteString("| Severity | Count |\n|----------|------:|\n")
	for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", sevDisplay(sev), data.SeverityCounts[sev]))
	}
	b.WriteString("\n")

	b.WriteString("## Crosswalk\n\n")
	b.WriteString("Each finding is mapped to the most relevant PCI DSS v4.0 requirement, HIPAA Security Rule citation, and SOC 2 Common Criteria control. Empty cells indicate that no deterministic mapping is available for the underlying CWE; the assessor should review those findings manually.\n\n")
	if len(data.ComplianceMatrix) == 0 {
		b.WriteString("_No findings to map._\n")
	} else {
		b.WriteString("| Severity | Finding | CWE | OWASP | PCI DSS | HIPAA | SOC 2 |\n")
		b.WriteString("|----------|---------|-----|-------|---------|-------|-------|\n")
		for _, m := range data.ComplianceMatrix {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
				sevDisplay(m.Severity),
				mdEscapeCell(m.FindingTitle),
				mdEscapeCell(m.CWE),
				mdEscapeCell(m.OWASP),
				mdEscapeCell(m.PCI),
				mdEscapeCell(m.HIPAA),
				mdEscapeCell(m.SOC2),
			))
		}
	}
	b.WriteString("\n")
	if data.ContentHash != "" {
		b.WriteString("---\n\n")
		b.WriteString("_Document content hash (SHA-256): `" + data.ContentHash + "`_\n")
	}
	return b.String()
}
