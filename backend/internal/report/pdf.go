package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/go-pdf/fpdf"
)

var severityColors = map[model.Severity][3]int{
	model.SeverityHigh:   {200, 50, 50},
	model.SeverityMedium: {220, 130, 30},
	model.SeverityLow:    {50, 130, 200},
	model.SeverityInfo:   {100, 100, 100},
}

// RenderPentestPDF produces a styled, multi-section PDF pen-test report.
// It always returns a non-empty byte slice for any non-nil ScanJob (the cover
// page alone is enough to render). The renderer is tolerant of missing data.
func RenderPentestPDF(job *model.ScanJob, opts model.ReportTemplateOptions) ([]byte, error) {
	data := BuildPentestReportData(job, opts)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	pageW, _ := pdf.GetPageSize()
	contentW := pageW - 30

	// --- Title ---
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetTextColor(30, 80, 160)
	pdf.CellFormat(contentW, 10, latin1(data.Title), "", 1, "C", false, 0, "")
	pdf.Ln(2)

	// Subtitle / branding
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(80, 80, 80)
	if opts.CompanyName != "" {
		pdf.CellFormat(contentW, 6, latin1("Prepared for: "+opts.CompanyName), "", 1, "C", false, 0, "")
	}
	if opts.Classification != "" {
		pdf.CellFormat(contentW, 6, latin1("Classification: "+opts.Classification), "", 1, "C", false, 0, "")
	}
	pdf.Ln(4)

	// --- Meta ---
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	if job != nil {
		pdf.CellFormat(contentW, 6, latin1("Target: "+job.Target), "", 1, "L", false, 0, "")
		pdf.CellFormat(contentW, 6, latin1("Scan ID: "+job.ID), "", 1, "L", false, 0, "")
		pdf.CellFormat(contentW, 6, latin1("Status: "+job.Status), "", 1, "L", false, 0, "")
		pdf.CellFormat(contentW, 6, latin1("Started: "+job.StartedAt.UTC().Format(time.RFC3339)), "", 1, "L", false, 0, "")
		if job.CompletedAt != nil {
			pdf.CellFormat(contentW, 6, latin1("Completed: "+job.CompletedAt.UTC().Format(time.RFC3339)), "", 1, "L", false, 0, "")
		}
		if job.ProgramName != "" {
			pdf.CellFormat(contentW, 6, latin1("Program: "+job.ProgramName), "", 1, "L", false, 0, "")
		}
	}
	if opts.Contact != "" {
		pdf.CellFormat(contentW, 6, latin1("Contact: "+opts.Contact), "", 1, "L", false, 0, "")
	}
	pdf.Ln(4)

	// --- Findings Summary ---
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(contentW, 8, "Findings Summary", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 10)
	for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		c := severityColors[sev]
		pdf.SetTextColor(c[0], c[1], c[2])
		pdf.CellFormat(contentW, 6, latin1(fmt.Sprintf("  %-8s %d", sevDisplay(sev), data.SeverityCounts[sev])), "", 1, "L", false, 0, "")
	}
	pdf.SetTextColor(30, 30, 30)
	pdf.Ln(4)

	// --- Executive Summary ---
	if job != nil && job.AISummary != "" {
		pdf.SetFont("Helvetica", "B", 13)
		pdf.CellFormat(contentW, 8, "Executive Summary", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(50, 50, 50)
		pdf.MultiCell(contentW, 5, latin1(job.AISummary), "", "L", false)
		pdf.SetTextColor(30, 30, 30)
		pdf.Ln(2)
	}

	// --- Methodology ---
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(contentW, 8, "Scope & Methodology", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(50, 50, 50)
	pdf.MultiCell(contentW, 5, latin1(methodologyText()), "", "L", false)
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(contentW, 8, "Risk Rating Methodology", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(50, 50, 50)
	pdf.MultiCell(contentW, 5, latin1(riskRatingMethodologyText()), "", "L", false)
	pdf.Ln(4)

	// --- Findings Detail (grouped by severity) ---
	target := ""
	if job != nil {
		target = job.Target
	}
	if len(data.Findings) > 0 {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 16)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(contentW, 10, "Findings", "", 1, "L", false, 0, "")
		pdf.Ln(2)

		for _, group := range FindingsBySeverity(data.Findings) {
			c := severityColors[group.Severity]
			pdf.SetFont("Helvetica", "B", 13)
			pdf.SetTextColor(c[0], c[1], c[2])
			pdf.CellFormat(contentW, 8, latin1(fmt.Sprintf("%s (%d)", sevDisplay(group.Severity), len(group.Items))), "", 1, "L", false, 0, "")
			for i, f := range group.Items {
				writeFindingPDF(pdf, contentW, i+1, f, target)
			}
			pdf.Ln(2)
		}
	}

	// --- Appendices ---
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(contentW, 10, "Appendix", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(contentW, 7, "A. Tools Used", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(50, 50, 50)
	if len(data.ToolsUsed) == 0 {
		pdf.MultiCell(contentW, 5, latin1("- Built-in HTTP/TLS/wordlist checks (native Go modules)"), "", "L", false)
	} else {
		for _, t := range data.ToolsUsed {
			pdf.MultiCell(contentW, 5, latin1("- "+t), "", "L", false)
		}
	}
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(contentW, 7, "B. Commands Executed", "", 1, "L", false, 0, "")
	pdf.SetFont("Courier", "", 8)
	pdf.SetTextColor(40, 40, 40)
	if len(data.CommandsUsed) == 0 {
		pdf.MultiCell(contentW, 5, latin1("(no external commands)"), "", "L", false)
	} else {
		for _, c := range data.CommandsUsed {
			pdf.MultiCell(contentW, 5, latin1(c), "", "L", false)
		}
	}
	pdf.Ln(2)

	if job != nil && len(job.AuditTrail) > 0 {
		pdf.SetFont("Helvetica", "B", 12)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(contentW, 7, "C. Audit Trail", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(60, 60, 60)
		for _, ev := range job.AuditTrail {
			line := fmt.Sprintf("%s [%s] %s", ev.Timestamp.UTC().Format(time.RFC3339), ev.Stage, ev.Message)
			pdf.MultiCell(contentW, 4, latin1(line), "", "L", false)
		}
		pdf.Ln(2)
	}

	if len(data.AssetsDiscovered) > 0 {
		pdf.SetFont("Helvetica", "B", 12)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(contentW, 7, "D. Assets Discovered", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(60, 60, 60)
		for _, a := range data.AssetsDiscovered {
			line := fmt.Sprintf("[%s] %s", a.AssetType, nonEmpty(a.AssetValue, a.AssetKey))
			pdf.MultiCell(contentW, 4, latin1(line), "", "L", false)
		}
	}

	// Footer
	reportDate := data.GeneratedAt
	if job != nil {
		reportDate = job.StartedAt.UTC()
		if job.CompletedAt != nil {
			reportDate = job.CompletedAt.UTC()
		}
	}
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(150, 150, 150)
		pdf.CellFormat(0, 5, latin1(fmt.Sprintf("Page %d - Auto Bughunter Report - %s", pdf.PageNo(), reportDate.Format("2006-01-02"))), "", 0, "C", false, 0, "")
	})

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeFindingPDF(pdf *fpdf.Fpdf, contentW float64, index int, f model.Finding, target string) {
	c := severityColors[f.Severity]
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(c[0], c[1], c[2])
	pdf.MultiCell(contentW, 6, latin1(fmt.Sprintf("%d. [%s] %s", index, sevDisplay(f.Severity), f.Title)), "", "L", false)

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(50, 50, 50)
	rows := [][2]string{
		{"Category", f.Category},
		{"CWE", f.CWE},
		{"OWASP", f.OWASPCategory},
		{"CVSS", fmtCVSS(f.CVSSScore, f.CVSSVector)},
		{"Affected URL", findingAsset(f, target)},
		{"Affected Parameter", f.AffectedParameter},
	}
	for _, row := range rows {
		if strings.TrimSpace(row[1]) != "" {
			pdf.MultiCell(contentW, 5, latin1(row[0]+": "+row[1]), "", "L", false)
		}
	}
	if f.Description != "" {
		pdf.MultiCell(contentW, 5, latin1("Description: "+f.Description), "", "L", false)
	}
	if f.Impact != "" {
		pdf.MultiCell(contentW, 5, latin1("Impact: "+f.Impact), "", "L", false)
	}
	if len(f.ReproductionSteps) > 0 {
		pdf.MultiCell(contentW, 5, latin1("Reproduction Steps:"), "", "L", false)
		for i, s := range f.ReproductionSteps {
			pdf.MultiCell(contentW, 5, latin1(fmt.Sprintf("  %d. %s", i+1, s)), "", "L", false)
		}
	}
	if f.Evidence != "" {
		pdf.MultiCell(contentW, 5, latin1("Evidence: "+f.Evidence), "", "L", false)
	}
	if f.PoC != "" {
		pdf.MultiCell(contentW, 5, latin1("PoC: "+f.PoC), "", "L", false)
	}
	if f.Recommendation != "" {
		pdf.MultiCell(contentW, 5, latin1("Remediation: "+f.Recommendation), "", "L", false)
	}
	if len(f.References) > 0 {
		pdf.MultiCell(contentW, 5, latin1("References: "+strings.Join(f.References, ", ")), "", "L", false)
	}
	pdf.Ln(3)
}

// latin1 replaces the small set of non-Latin-1 characters that gofpdf cannot
// render in its built-in fonts with safe ASCII equivalents.
func latin1(s string) string {
	replacer := strings.NewReplacer(
		"—", "-",
		"–", "-",
		"\u2018", "'",
		"\u2019", "'",
		"\u201C", "\"",
		"\u201D", "\"",
		"\u2026", "...",
		"\u00A0", " ",
	)
	return replacer.Replace(s)
}
