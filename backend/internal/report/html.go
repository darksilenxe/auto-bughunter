package report

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// RenderPentestHTML returns a self-contained HTML document version of the
// pen-test report. The template is intentionally print-friendly so it can be
// previewed in the browser and exported with the browser's print dialog.
func RenderPentestHTML(job *model.ScanJob, opts model.ReportTemplateOptions, ctx ...ReportContext) string {
	data := BuildPentestReportData(job, opts, ctx...)
	var b bytes.Buffer

	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<title>" + html.EscapeString(data.Title) + "</title>\n")
	b.WriteString("<style>\n")
	b.WriteString("body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:2rem auto;max-width:920px;color:#222;line-height:1.5;padding:0 1rem}\n")
	b.WriteString("h1{color:#1e3a8a;border-bottom:3px solid #1e3a8a;padding-bottom:.4rem}\n")
	b.WriteString("h2{color:#1e40af;margin-top:2rem;border-bottom:1px solid #cbd5e1;padding-bottom:.2rem}\n")
	b.WriteString("h3{color:#0f172a;margin-top:1.4rem}\n")
	b.WriteString("h4{color:#0f172a;margin-top:1rem}\n")
	b.WriteString("table{border-collapse:collapse;margin:.6rem 0}\n")
	b.WriteString("th,td{border:1px solid #cbd5e1;padding:.3rem .8rem;text-align:left}\n")
	b.WriteString("th{background:#f1f5f9}\n")
	b.WriteString("pre{background:#0f172a;color:#e2e8f0;padding:.8rem;border-radius:6px;overflow-x:auto;font-size:.85rem}\n")
	b.WriteString("code{background:#f1f5f9;padding:1px 4px;border-radius:3px;font-size:.9em}\n")
	b.WriteString(".sev-high{color:#b91c1c;font-weight:bold}\n")
	b.WriteString(".sev-medium{color:#c2410c;font-weight:bold}\n")
	b.WriteString(".sev-low{color:#1d4ed8;font-weight:bold}\n")
	b.WriteString(".sev-info{color:#475569}\n")
	b.WriteString(".meta{color:#64748b;font-size:.9rem}\n")
	b.WriteString(".finding{border-left:4px solid #cbd5e1;padding:.4rem .8rem;margin:.8rem 0;background:#f8fafc}\n")
	b.WriteString(".finding.sev-high{border-color:#b91c1c}\n")
	b.WriteString(".finding.sev-medium{border-color:#c2410c}\n")
	b.WriteString(".finding.sev-low{border-color:#1d4ed8}\n")
	b.WriteString(".finding.sev-info{border-color:#94a3b8}\n")
	b.WriteString("@media print{body{margin:0;max-width:none}}\n")
	b.WriteString("</style>\n</head>\n<body>\n")

	// Cover
	b.WriteString("<h1>" + html.EscapeString(data.Title) + "</h1>\n")
	if opts.Classification != "" {
		b.WriteString("<p class=\"meta\"><strong>Classification:</strong> " + html.EscapeString(opts.Classification) + "</p>\n")
	}
	b.WriteString("<p class=\"meta\"><strong>Generated:</strong> " + html.EscapeString(formatTime(data.GeneratedAt)) + "</p>\n")
	if opts.CompanyName != "" {
		b.WriteString("<p class=\"meta\"><strong>Prepared for:</strong> " + html.EscapeString(opts.CompanyName) + "</p>\n")
	}
	if opts.Contact != "" {
		b.WriteString("<p class=\"meta\"><strong>Contact:</strong> " + html.EscapeString(opts.Contact) + "</p>\n")
	}
	if opts.ProgramHandle != "" {
		b.WriteString("<p class=\"meta\"><strong>Program:</strong> " + html.EscapeString(opts.ProgramHandle) + "</p>\n")
	}
	if job != nil {
		b.WriteString("<p class=\"meta\"><strong>Target:</strong> " + html.EscapeString(job.Target) + "<br>")
		b.WriteString("<strong>Scan ID:</strong> " + html.EscapeString(job.ID) + "<br>")
		b.WriteString("<strong>Status:</strong> " + html.EscapeString(job.Status) + "</p>\n")
	}

	// Executive summary
	b.WriteString("<h2>Executive Summary</h2>\n")
	if job != nil && job.AISummary != "" {
		b.WriteString("<p>" + html.EscapeString(job.AISummary) + "</p>\n")
	} else {
		b.WriteString("<p>This report describes the security assessment performed against the target above. ")
		b.WriteString("Findings are grouped by severity and include CVSS, CWE, OWASP mapping, reproduction steps, and recommended remediation.</p>\n")
	}

	// Severity table
	b.WriteString("<h3>Findings Summary</h3>\n<table><tr><th>Severity</th><th>Count</th></tr>")
	for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		b.WriteString(fmt.Sprintf("<tr><td class=\"sev-%s\">%s</td><td>%d</td></tr>", strings.ToLower(string(sev)), sevDisplay(sev), data.SeverityCounts[sev]))
	}
	b.WriteString("</table>\n")

	if data.SecurityKnowledge != nil && len(data.SecurityKnowledge.References) > 0 {
		b.WriteString("<h2>Security Knowledge References</h2>\n")
		if data.SecurityKnowledge.LicenseNotice != "" {
			b.WriteString("<p class=\"meta\">" + html.EscapeString(data.SecurityKnowledge.LicenseNotice) + "</p>\n")
		}
		b.WriteString("<ul>")
		for _, ref := range data.SecurityKnowledge.References {
			b.WriteString(fmt.Sprintf("<li><strong>%s</strong> (<a href=\"%s\">%s</a>) &mdash; %s</li>",
				html.EscapeString(ref.Title),
				html.EscapeString(ref.URL),
				html.EscapeString(ref.URL),
				html.EscapeString(ref.Passage),
			))
		}
		b.WriteString("</ul>\n")
	}

	// Methodology
	b.WriteString("<h2>Scope &amp; Methodology</h2>\n<p>" + html.EscapeString(methodologyText()) + "</p>\n")
	b.WriteString("<h2>Risk Rating Methodology</h2>\n<p>" + html.EscapeString(riskRatingMethodologyText()) + "</p>\n")

	// Findings
	b.WriteString("<h2>Findings</h2>\n")
	target := ""
	if job != nil {
		target = job.Target
	}
	if len(data.Findings) == 0 {
		b.WriteString("<p><em>No findings were produced for this scan.</em></p>\n")
	}
	for _, group := range FindingsBySeverity(data.Findings) {
		b.WriteString(fmt.Sprintf("<h3 class=\"sev-%s\">%s (%d)</h3>\n", strings.ToLower(string(group.Severity)), sevDisplay(group.Severity), len(group.Items)))
		for i, f := range group.Items {
			writeFindingHTML(&b, i+1, f, target)
		}
	}

	// Attack Paths
	if len(data.AttackPaths) > 0 {
		b.WriteString("<h2>Attack Paths</h2>\n")
		b.WriteString("<p>Chained narratives that demonstrate proven impact by combining individual findings into an end-to-end exploitation story.</p>\n")
		for i, ap := range data.AttackPaths {
			b.WriteString(fmt.Sprintf("<h3>Path %d &mdash; %s</h3>\n<ol>", i+1, html.EscapeString(ap.Title)))
			for _, st := range ap.Steps {
				detail := st.Detail
				if detail != "" {
					detail = " &mdash; " + html.EscapeString(detail)
				}
				b.WriteString(fmt.Sprintf("<li><span class=\"sev-%s\">[%s]</span> %s%s</li>",
					strings.ToLower(string(st.Severity)), sevDisplay(st.Severity), html.EscapeString(st.Title), detail))
			}
			b.WriteString("</ol>\n")
			if ap.Impact != "" {
				b.WriteString("<blockquote>" + html.EscapeString(ap.Impact) + "</blockquote>\n")
			}
		}
	}

	// Remediation Priorities
	if len(data.RemediationPriorities) > 0 {
		b.WriteString("<h2>Remediation Priorities</h2>\n")
		b.WriteString("<p>Recommendations are ordered by severity-weighted impact reduction. Fix the items at the top of this list first.</p>\n")
		b.WriteString("<table><tr><th>Rank</th><th>Severity</th><th>Findings</th><th>Assets</th><th>Recommendation</th></tr>")
		for _, p := range data.RemediationPriorities {
			b.WriteString(fmt.Sprintf("<tr><td>%d</td><td class=\"sev-%s\">%s</td><td>%d</td><td>%d</td><td>%s</td></tr>",
				p.Rank, strings.ToLower(string(p.HighestSeverity)), sevDisplay(p.HighestSeverity),
				p.AffectedFindings, p.AffectedAssets, html.EscapeString(p.Recommendation)))
		}
		b.WriteString("</table>\n")
	}

	// Per-Asset Rollup
	if len(data.AssetRollup) > 0 {
		b.WriteString("<h2>Per-Asset Rollup</h2>\n")
		b.WriteString("<p>Findings grouped by asset (host) so a single owner can see every issue on one system.</p>\n")
		b.WriteString("<table><tr><th>Asset</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Sample Finding</th></tr>")
		for _, r := range data.AssetRollup {
			sample := ""
			if len(r.FindingTitles) > 0 {
				sample = r.FindingTitles[0]
			}
			b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td></tr>",
				html.EscapeString(r.Asset), r.HighCount, r.MediumCount, r.LowCount, r.InfoCount, html.EscapeString(sample)))
		}
		b.WriteString("</table>\n")
	}

	// Findings Delta
	if data.Delta.HasPrevious {
		b.WriteString("<h2>What Changed Since Last Engagement</h2>\n")
		b.WriteString(fmt.Sprintf("<p class=\"meta\">Comparison against previous scan <code>%s</code>.</p>\n", html.EscapeString(data.Delta.PreviousScanID)))
		b.WriteString(fmt.Sprintf("<ul><li><strong>New findings:</strong> %d</li><li><strong>Resolved findings:</strong> %d</li><li><strong>Carried over (unchanged):</strong> %d</li></ul>",
			len(data.Delta.NewFindings), len(data.Delta.ResolvedFindings), data.Delta.UnchangedCount))
		if len(data.Delta.NewFindings) > 0 {
			b.WriteString("<h3>New Findings</h3>\n<ul>")
			for _, f := range data.Delta.NewFindings {
				b.WriteString(fmt.Sprintf("<li><span class=\"sev-%s\">[%s]</span> %s</li>",
					strings.ToLower(string(f.Severity)), sevDisplay(f.Severity), html.EscapeString(f.Title)))
			}
			b.WriteString("</ul>\n")
		}
		if len(data.Delta.ResolvedFindings) > 0 {
			b.WriteString("<h3>Resolved Findings</h3>\n<ul>")
			for _, f := range data.Delta.ResolvedFindings {
				b.WriteString(fmt.Sprintf("<li><span class=\"sev-%s\">[%s]</span> %s</li>",
					strings.ToLower(string(f.Severity)), sevDisplay(f.Severity), html.EscapeString(f.Title)))
			}
			b.WriteString("</ul>\n")
		}
	}

	// Visual Evidence (inline screenshots)
	if len(data.Screenshots) > 0 {
		b.WriteString("<h2>Visual Evidence</h2>\n")
		b.WriteString("<p>Screenshots captured during the engagement, embedded inline as base64 PNGs.</p>\n")
		for i, sh := range data.Screenshots {
			caption := html.EscapeString(nonEmpty(sh.Caption, sh.URL, fmt.Sprintf("screenshot-%d", i+1)))
			b.WriteString("<figure style=\"margin:1rem 0;border:1px solid #cbd5e1;padding:.5rem;background:#f8fafc\">")
			b.WriteString("<img alt=\"" + caption + "\" style=\"max-width:100%;height:auto\" src=\"data:image/png;base64,")
			b.WriteString(base64.StdEncoding.EncodeToString(sh.Data))
			b.WriteString("\">")
			b.WriteString("<figcaption class=\"meta\">" + caption + "</figcaption>")
			b.WriteString("</figure>\n")
		}
	}

	// Appendix
	b.WriteString("<h2>Appendix A — Tools Used</h2>\n<ul>")
	if len(data.ToolsUsed) == 0 {
		b.WriteString("<li>Built-in HTTP/TLS/wordlist checks (native Go modules)</li>")
	}
	for _, t := range data.ToolsUsed {
		b.WriteString("<li>" + html.EscapeString(t) + "</li>")
	}
	b.WriteString("</ul>\n")

	b.WriteString("<h2>Appendix B — Commands Executed</h2>\n<ul>")
	if len(data.CommandsUsed) == 0 {
		b.WriteString("<li>(no external commands)</li>")
	}
	for _, c := range data.CommandsUsed {
		b.WriteString("<li><code>" + html.EscapeString(c) + "</code></li>")
	}
	b.WriteString("</ul>\n")

	// Compliance crosswalk appendix
	if len(data.ComplianceMatrix) > 0 {
		b.WriteString("<h2>Appendix C — Compliance Crosswalk</h2>\n")
		b.WriteString("<p class=\"meta\">Findings mapped to PCI DSS v4.0, HIPAA Security Rule, and SOC 2 (Common Criteria) controls. Empty cells indicate no deterministic mapping for the underlying CWE.</p>\n")
		b.WriteString("<table><tr><th>Severity</th><th>Finding</th><th>CWE</th><th>OWASP</th><th>PCI DSS</th><th>HIPAA</th><th>SOC 2</th></tr>")
		for _, m := range data.ComplianceMatrix {
			b.WriteString(fmt.Sprintf("<tr><td class=\"sev-%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				strings.ToLower(string(m.Severity)),
				sevDisplay(m.Severity),
				html.EscapeString(m.FindingTitle),
				html.EscapeString(m.CWE),
				html.EscapeString(m.OWASP),
				html.EscapeString(m.PCI),
				html.EscapeString(m.HIPAA),
				html.EscapeString(m.SOC2),
			))
		}
		b.WriteString("</table>\n")
	}

	if data.ContentHash != "" {
		b.WriteString("<hr><p class=\"meta\"><strong>Document content hash (SHA-256):</strong> <code>" + html.EscapeString(data.ContentHash) + "</code></p>\n")
	}

	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// RenderComplianceHTML renders a focused compliance crosswalk in HTML.
func RenderComplianceHTML(job *model.ScanJob, opts model.ReportTemplateOptions, ctx ...ReportContext) string {
	opts.ReportType = "compliance"
	data := BuildPentestReportData(job, opts, ctx...)
	var b bytes.Buffer
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>")
	b.WriteString(html.EscapeString(data.Title))
	b.WriteString("</title><style>body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:2rem auto;max-width:1100px;color:#222;line-height:1.5;padding:0 1rem}h1{color:#1e3a8a;border-bottom:3px solid #1e3a8a;padding-bottom:.4rem}table{border-collapse:collapse;margin:.6rem 0;width:100%}th,td{border:1px solid #cbd5e1;padding:.3rem .6rem;text-align:left;font-size:.9rem}th{background:#f1f5f9}.meta{color:#64748b;font-size:.9rem}.sev-high{color:#b91c1c;font-weight:bold}.sev-medium{color:#c2410c;font-weight:bold}.sev-low{color:#1d4ed8;font-weight:bold}.sev-info{color:#475569}</style></head><body>")
	b.WriteString("<h1>" + html.EscapeString(data.Title) + "</h1>")
	if opts.CompanyName != "" {
		b.WriteString("<p class=\"meta\"><strong>Prepared for:</strong> " + html.EscapeString(opts.CompanyName) + "</p>")
	}
	b.WriteString("<p class=\"meta\"><strong>Generated:</strong> " + html.EscapeString(formatTime(data.GeneratedAt)) + "</p>")
	if job != nil {
		b.WriteString("<p class=\"meta\"><strong>Target:</strong> " + html.EscapeString(job.Target) + " &nbsp; <strong>Scan ID:</strong> " + html.EscapeString(job.ID) + "</p>")
	}
	b.WriteString("<h2>Crosswalk</h2><p>Each finding is mapped to the most relevant PCI DSS v4.0 requirement, HIPAA Security Rule citation, and SOC 2 Common Criteria control.</p>")
	if len(data.ComplianceMatrix) == 0 {
		b.WriteString("<p><em>No findings to map.</em></p>")
	} else {
		b.WriteString("<table><tr><th>Severity</th><th>Finding</th><th>CWE</th><th>OWASP</th><th>PCI DSS</th><th>HIPAA</th><th>SOC 2</th></tr>")
		for _, m := range data.ComplianceMatrix {
			b.WriteString(fmt.Sprintf("<tr><td class=\"sev-%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				strings.ToLower(string(m.Severity)), sevDisplay(m.Severity),
				html.EscapeString(m.FindingTitle), html.EscapeString(m.CWE), html.EscapeString(m.OWASP),
				html.EscapeString(m.PCI), html.EscapeString(m.HIPAA), html.EscapeString(m.SOC2)))
		}
		b.WriteString("</table>")
	}
	if data.ContentHash != "" {
		b.WriteString("<hr><p class=\"meta\"><strong>Document content hash (SHA-256):</strong> <code>" + html.EscapeString(data.ContentHash) + "</code></p>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

func writeFindingHTML(b *bytes.Buffer, index int, f model.Finding, target string) {
	sevClass := strings.ToLower(string(f.Severity))
	b.WriteString(fmt.Sprintf("<div class=\"finding sev-%s\">\n", sevClass))
	b.WriteString(fmt.Sprintf("<h4>%d. %s</h4>\n", index, html.EscapeString(f.Title)))

	rows := [][2]string{
		{"Severity", sevDisplay(f.Severity)},
		{"Category", f.Category},
		{"CWE", f.CWE},
		{"OWASP", f.OWASPCategory},
		{"CVSS", fmtCVSS(f.CVSSScore, f.CVSSVector)},
		{"Affected URL", findingAsset(f, target)},
		{"Affected Parameter", f.AffectedParameter},
	}
	b.WriteString("<table>")
	for _, row := range rows {
		if strings.TrimSpace(row[1]) != "" {
			b.WriteString("<tr><th>" + html.EscapeString(row[0]) + "</th><td>" + html.EscapeString(row[1]) + "</td></tr>")
		}
	}
	b.WriteString("</table>\n")

	if f.Description != "" {
		b.WriteString("<p><strong>Description:</strong> " + html.EscapeString(f.Description) + "</p>\n")
	}
	if f.Impact != "" {
		b.WriteString("<p><strong>Impact:</strong> " + html.EscapeString(f.Impact) + "</p>\n")
	}
	if len(f.ReproductionSteps) > 0 {
		b.WriteString("<p><strong>Reproduction Steps:</strong></p>\n<ol>")
		for _, s := range f.ReproductionSteps {
			b.WriteString("<li>" + html.EscapeString(s) + "</li>")
		}
		b.WriteString("</ol>\n")
	}
	if f.Evidence != "" {
		b.WriteString("<p><strong>Evidence:</strong></p>\n<pre>" + html.EscapeString(f.Evidence) + "</pre>\n")
	}
	if f.PoC != "" {
		b.WriteString("<p><strong>Proof of Concept:</strong></p>\n<pre>" + html.EscapeString(f.PoC) + "</pre>\n")
	}
	if f.Recommendation != "" {
		b.WriteString("<p><strong>Remediation:</strong> " + html.EscapeString(f.Recommendation) + "</p>\n")
	}
	if len(f.References) > 0 {
		b.WriteString("<p><strong>References:</strong></p>\n<ul>")
		for _, r := range f.References {
			b.WriteString("<li><a href=\"" + html.EscapeString(r) + "\">" + html.EscapeString(r) + "</a></li>")
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString("</div>\n")
}
