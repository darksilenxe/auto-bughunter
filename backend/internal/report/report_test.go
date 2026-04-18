package report

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func sampleJob() *model.ScanJob {
	completed := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	return &model.ScanJob{
		ID:          "scan-1",
		Target:      "https://example.com",
		Status:      "completed",
		StartedAt:   time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC),
		CompletedAt: &completed,
		AISummary:   "Two issues identified during the assessment.",
		Findings: []model.Finding{
			{
				ID:                "sqlmap-error-based",
				Category:          "injection",
				Severity:          model.SeverityHigh,
				Title:             "SQL injection in id parameter",
				Description:       "Error-based SQL injection detected.",
				Evidence:          "param=id payload='",
				Recommendation:    "Use parameterized queries.",
				AffectedURL:       "https://example.com/users",
				AffectedParameter: "id",
			},
			{
				ID:       "headers-missing-csp",
				Category: "misconfiguration",
				Severity: model.SeverityLow,
				Title:    "Missing Content-Security-Policy header",
				Evidence: "no CSP header in response",
			},
		},
	}
}

func TestEnrichFindingFillsCWEAndOWASP(t *testing.T) {
	f := EnrichFinding(model.Finding{Category: "injection"})
	if f.CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", f.CWE)
	}
	if !strings.Contains(f.OWASPCategory, "Injection") {
		t.Errorf("expected OWASP injection mapping, got %q", f.OWASPCategory)
	}
	if f.CVSSScore == 0 {
		t.Errorf("expected CVSS score to be set")
	}
	if len(f.ReproductionSteps) == 0 {
		t.Errorf("expected reproduction steps to be populated")
	}
}

func TestEnrichFindingDoesNotOverwrite(t *testing.T) {
	in := model.Finding{
		Category:  "injection",
		CWE:       "CWE-CUSTOM",
		CVSSScore: 1.5,
	}
	out := EnrichFinding(in)
	if out.CWE != "CWE-CUSTOM" {
		t.Errorf("EnrichFinding overwrote existing CWE: %q", out.CWE)
	}
	if out.CVSSScore != 1.5 {
		t.Errorf("EnrichFinding overwrote existing CVSSScore: %v", out.CVSSScore)
	}
}

func TestRenderPentestMarkdownIncludesAllSections(t *testing.T) {
	md := RenderPentestMarkdown(sampleJob(), model.ReportTemplateOptions{
		CompanyName:    "Acme Corp",
		Classification: "Confidential",
	})
	wantSubstrings := []string{
		"# Penetration Testing Report",
		"Acme Corp",
		"Classification:** Confidential",
		"## Executive Summary",
		"## Scope & Methodology",
		"## Risk Rating Methodology",
		"## Findings",
		"### HIGH (1)",
		"### LOW (1)",
		"SQL injection in id parameter",
		"CWE-89",
		"Reproduction Steps",
		"Appendix A — Tools Used",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(md, s) {
			t.Errorf("markdown missing %q", s)
		}
	}
}

func TestRenderPentestMarkdownEmptyFindings(t *testing.T) {
	job := &model.ScanJob{ID: "x", Target: "https://nothing.test", Status: "completed", StartedAt: time.Now()}
	md := RenderPentestMarkdown(job, model.ReportTemplateOptions{})
	if !strings.Contains(md, "_No findings were produced for this scan._") {
		t.Errorf("expected empty-findings notice, got: %s", md)
	}
}

func TestRenderPentestPDFNonEmpty(t *testing.T) {
	pdf, err := RenderPentestPDF(sampleJob(), model.ReportTemplateOptions{CompanyName: "Acme"})
	if err != nil {
		t.Fatalf("RenderPentestPDF returned error: %v", err)
	}
	if len(pdf) == 0 {
		t.Fatalf("expected non-empty PDF bytes")
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Errorf("expected PDF magic header, got prefix %q", pdf[:8])
	}
}

func TestRenderBugBountyMarkdownContainsRequiredSections(t *testing.T) {
	f := sampleJob().Findings[0]
	md := RenderBugBountyMarkdown(f, "https://example.com")
	for _, want := range []string{
		"## Summary",
		"## Steps to Reproduce",
		"## Impact",
		"## Suggested Remediation",
		"CWE-89",
		"id",                    // affected parameter
		"https://example.com/u", // affected URL
	} {
		if !strings.Contains(md, want) {
			t.Errorf("bug-bounty markdown missing %q", want)
		}
	}
}

func TestRenderBugBountyZipContainsOneFilePerFinding(t *testing.T) {
	job := sampleJob()
	zipBytes, err := RenderBugBountyZip(job)
	if err != nil {
		t.Fatalf("RenderBugBountyZip returned error: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("invalid zip output: %v", err)
	}
	gotIndex := false
	mdFiles := 0
	for _, f := range zr.File {
		if f.Name == "INDEX.md" {
			gotIndex = true
			continue
		}
		if strings.HasSuffix(f.Name, ".md") {
			mdFiles++
		}
	}
	if !gotIndex {
		t.Errorf("INDEX.md not found in zip")
	}
	if mdFiles != len(job.Findings) {
		t.Errorf("expected %d finding files, got %d", len(job.Findings), mdFiles)
	}
}

func TestRenderPentestHTMLContainsExpectedTags(t *testing.T) {
	html := RenderPentestHTML(sampleJob(), model.ReportTemplateOptions{Classification: "Internal"})
	for _, want := range []string{
		"<title>Penetration Testing Report</title>",
		"Findings Summary",
		"sev-high",
		"SQL injection",
		"<h2>Findings</h2>",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestRenderExecutiveMarkdownIncludesCounts(t *testing.T) {
	md := RenderExecutiveMarkdown(sampleJob(), model.ReportTemplateOptions{CompanyName: "Acme"})
	if !strings.Contains(md, "Executive Security Summary") {
		t.Errorf("missing executive title")
	}
	if !strings.Contains(md, "Acme") {
		t.Errorf("expected company name in executive summary")
	}
	if !strings.Contains(md, "| HIGH | 1 |") {
		t.Errorf("expected HIGH count in executive summary, got: %s", md)
	}
}

func TestReportTemplateOptionsApplied(t *testing.T) {
	job := sampleJob()
	md := RenderPentestMarkdown(job, model.ReportTemplateOptions{
		CompanyName:    "Custom Company",
		Classification: "TLP:RED",
		Contact:        "ciso@custom.test",
		ProgramHandle:  "h1-acme",
	})
	for _, want := range []string{"Custom Company", "TLP:RED", "ciso@custom.test", "h1-acme"} {
		if !strings.Contains(md, want) {
			t.Errorf("template option %q not in markdown", want)
		}
	}
}

func TestSafeFilenameStripsUnsafeCharacters(t *testing.T) {
	got := safeFilename("../etc/passwd?abc=1")
	if strings.ContainsAny(got, "/?") {
		t.Errorf("unsafe characters remain in %q", got)
	}
}
