package report

import (
	"bytes"
	"fmt"
	"html"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// RenderPentestHTML returns a self-contained HTML document version of the
// pen-test report. The template is intentionally print-friendly so it can be
// previewed in the browser and exported with the browser's print dialog.
func RenderPentestHTML(job *model.ScanJob, opts model.ReportTemplateOptions) string {
	data := BuildPentestReportData(job, opts)
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

	b.WriteString("</body>\n</html>\n")
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
