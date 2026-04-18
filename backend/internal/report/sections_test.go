package report

import (
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

// jobWithAttackPaths returns a sample job with dashboard top attack paths and
// per-finding hints that the narrative builder can chain together.
func jobWithAttackPaths() *model.ScanJob {
	return &model.ScanJob{
		ID:     "scan-ap-1",
		Target: "https://example.com",
		Status: "completed",
		Dashboard: &model.DecisionDashboard{
			TopAttackPaths: []string{
				"unauth-foothold → cred-dump → lateral-move",
			},
		},
		Findings: []model.Finding{
			{
				ID:       "f-1",
				Title:    "Unauthenticated admin panel",
				Category: "auth",
				Severity: model.SeverityHigh,
				Exploitability: &model.Exploitability{
					AttackPathHints: []string{"unauth-foothold"},
				},
			},
			{
				ID:       "f-2",
				Title:    "Plaintext credentials in config",
				Category: "secrets",
				Severity: model.SeverityHigh,
				Exploitability: &model.Exploitability{
					AttackPathHints: []string{"cred-dump"},
				},
			},
		},
	}
}

func TestBuildAttackPathNarratives(t *testing.T) {
	narratives := BuildAttackPathNarratives(jobWithAttackPaths(), jobWithAttackPaths().Findings)
	if len(narratives) != 1 {
		t.Fatalf("expected 1 narrative, got %d", len(narratives))
	}
	n := narratives[0]
	if len(n.Steps) != 3 {
		t.Fatalf("expected 3 steps in chained path, got %d", len(n.Steps))
	}
	if n.Steps[0].Severity != model.SeverityHigh {
		t.Errorf("step 1 expected HIGH severity (matched unauth foothold finding), got %s", n.Steps[0].Severity)
	}
	if !strings.Contains(n.Impact, "HIGH") {
		t.Errorf("expected proven-impact line to surface HIGH severity, got %q", n.Impact)
	}
}

func TestBuildAttackPathNarratives_NoData(t *testing.T) {
	if got := BuildAttackPathNarratives(nil, nil); got != nil {
		t.Errorf("expected nil for nil job, got %v", got)
	}
	job := &model.ScanJob{Dashboard: &model.DecisionDashboard{}}
	if got := BuildAttackPathNarratives(job, nil); got != nil {
		t.Errorf("expected nil when no top attack paths, got %v", got)
	}
}

func TestBuildRemediationPriorities_OrderingAndCounts(t *testing.T) {
	findings := []model.Finding{
		{Title: "A", Severity: model.SeverityLow, Recommendation: "Patch", AffectedURL: "https://a/x"},
		{Title: "B", Severity: model.SeverityHigh, Recommendation: "Patch", AffectedURL: "https://a/y"},
		{Title: "C", Severity: model.SeverityMedium, Recommendation: "Rotate keys", AffectedURL: "https://b/z"},
		{Title: "D", Severity: model.SeverityLow, Recommendation: "Rotate keys", AffectedURL: "https://b/z"},
	}
	priorities := BuildRemediationPriorities(findings)
	if len(priorities) != 2 {
		t.Fatalf("expected 2 deduplicated buckets, got %d", len(priorities))
	}
	if priorities[0].Recommendation != "Patch" {
		t.Errorf("expected HIGH recommendation first, got %q", priorities[0].Recommendation)
	}
	if priorities[0].Rank != 1 || priorities[1].Rank != 2 {
		t.Errorf("expected rank 1,2; got %d,%d", priorities[0].Rank, priorities[1].Rank)
	}
	if priorities[0].AffectedFindings != 2 {
		t.Errorf("expected 2 findings in Patch bucket, got %d", priorities[0].AffectedFindings)
	}
	if priorities[0].AffectedAssets != 2 {
		t.Errorf("expected 2 distinct assets in Patch bucket, got %d", priorities[0].AffectedAssets)
	}
}

func TestBuildAssetRollup_GroupsByHost(t *testing.T) {
	findings := []model.Finding{
		{Title: "X", Severity: model.SeverityHigh, AffectedURL: "https://example.com/a"},
		{Title: "Y", Severity: model.SeverityLow, AffectedURL: "https://example.com/b"},
		{Title: "Z", Severity: model.SeverityMedium, AffectedURL: "https://other.com/q"},
	}
	rollups := BuildAssetRollup(findings, "")
	if len(rollups) != 2 {
		t.Fatalf("expected 2 host rollups, got %d", len(rollups))
	}
	if rollups[0].Asset != "example.com" {
		t.Errorf("expected example.com first (HIGH severity), got %s", rollups[0].Asset)
	}
	if rollups[0].HighCount != 1 || rollups[0].LowCount != 1 {
		t.Errorf("expected 1 high + 1 low for example.com, got high=%d low=%d", rollups[0].HighCount, rollups[0].LowCount)
	}
}

func TestBuildComplianceMatrix_KnownAndUnknownCWE(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQLi", CWE: "CWE-89", Severity: model.SeverityHigh, OWASPCategory: "A03"},
		{Title: "Unknown", CWE: "CWE-99999", Severity: model.SeverityLow},
	}
	mappings := BuildComplianceMatrix(findings)
	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
	if mappings[0].PCI == "" || mappings[0].HIPAA == "" || mappings[0].SOC2 == "" {
		t.Errorf("expected non-empty controls for CWE-89, got PCI=%q HIPAA=%q SOC2=%q", mappings[0].PCI, mappings[0].HIPAA, mappings[0].SOC2)
	}
	if mappings[1].PCI != "" || mappings[1].HIPAA != "" || mappings[1].SOC2 != "" {
		t.Errorf("expected empty controls for unknown CWE, got PCI=%q HIPAA=%q SOC2=%q", mappings[1].PCI, mappings[1].HIPAA, mappings[1].SOC2)
	}
}

func TestBuildFindingsDelta(t *testing.T) {
	prev := &model.ScanJob{
		ID: "prev-1",
		Findings: []model.Finding{
			{ID: "a", Title: "Carry over", Severity: model.SeverityMedium},
			{ID: "b", Title: "Resolved bug", Severity: model.SeverityHigh},
		},
	}
	curr := []model.Finding{
		{ID: "a", Title: "Carry over", Severity: model.SeverityMedium},
		{ID: "c", Title: "Brand new bug", Severity: model.SeverityHigh},
	}
	delta := BuildFindingsDelta(curr, prev)
	if !delta.HasPrevious {
		t.Fatal("expected HasPrevious=true")
	}
	if delta.PreviousScanID != "prev-1" {
		t.Errorf("expected previous scan id 'prev-1', got %q", delta.PreviousScanID)
	}
	if len(delta.NewFindings) != 1 || delta.NewFindings[0].ID != "c" {
		t.Errorf("expected 1 new finding (c), got %v", delta.NewFindings)
	}
	if len(delta.ResolvedFindings) != 1 || delta.ResolvedFindings[0].ID != "b" {
		t.Errorf("expected 1 resolved finding (b), got %v", delta.ResolvedFindings)
	}
	if delta.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", delta.UnchangedCount)
	}
}

func TestBuildFindingsDelta_NoPrevious(t *testing.T) {
	if got := BuildFindingsDelta(nil, nil); got.HasPrevious {
		t.Errorf("expected HasPrevious=false for nil previous, got %+v", got)
	}
}

func TestComputeContentHash_Stable(t *testing.T) {
	job := sampleJob()
	d1 := BuildPentestReportData(job, model.ReportTemplateOptions{})
	// Force a different GeneratedAt; the hash must NOT change because the
	// timestamp is excluded from the canonical form.
	d2 := BuildPentestReportData(job, model.ReportTemplateOptions{})
	d2.GeneratedAt = d1.GeneratedAt.Add(time.Hour)
	if d1.ContentHash == "" {
		t.Fatal("expected non-empty hash")
	}
	if ComputeContentHash(d1) != ComputeContentHash(d2) {
		t.Error("hash should not depend on GeneratedAt")
	}
}

func TestComputeContentHash_ChangesWithFindings(t *testing.T) {
	job := sampleJob()
	d1 := BuildPentestReportData(job, model.ReportTemplateOptions{})
	job2 := sampleJob()
	job2.Findings[0].Title = "Different"
	d2 := BuildPentestReportData(job2, model.ReportTemplateOptions{})
	if ComputeContentHash(d1) == ComputeContentHash(d2) {
		t.Error("hash should change when findings change")
	}
}

func TestRenderPentestMarkdown_IncludesNewSections(t *testing.T) {
	job := jobWithAttackPaths()
	prev := &model.ScanJob{
		ID: "prev-1",
		Findings: []model.Finding{
			{ID: "old", Title: "Stale issue", Severity: model.SeverityLow},
		},
	}
	md := RenderPentestMarkdown(job, model.ReportTemplateOptions{}, ReportContext{PreviousJob: prev})
	wants := []string{
		"## Attack Paths",
		"## Remediation Priorities",
		"## Per-Asset Rollup",
		"## What Changed Since Last Engagement",
		"Document content hash (SHA-256)",
	}
	for _, want := range wants {
		if !strings.Contains(md, want) {
			t.Errorf("expected markdown to contain %q", want)
		}
	}
}

func TestRenderPentestHTML_EmbedsScreenshot(t *testing.T) {
	// 1x1 transparent PNG.
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
		0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41,
		0x54, 0x78, 0x9C, 0x62, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
		0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
		0x42, 0x60, 0x82,
	}
	ctx := ReportContext{Screenshots: []Screenshot{{Caption: "login page", Data: pngData}}}
	html := RenderPentestHTML(sampleJob(), model.ReportTemplateOptions{}, ctx)
	if !strings.Contains(html, "Visual Evidence") {
		t.Error("expected Visual Evidence section")
	}
	if !strings.Contains(html, "data:image/png;base64,") {
		t.Error("expected inline base64 image data URL")
	}
	if !strings.Contains(html, "login page") {
		t.Error("expected screenshot caption")
	}
}

func TestRenderComplianceMarkdown(t *testing.T) {
	md := RenderComplianceMarkdown(sampleJob(), model.ReportTemplateOptions{})
	if !strings.Contains(md, "Compliance Crosswalk") {
		t.Error("expected compliance crosswalk title")
	}
	if !strings.Contains(md, "PCI DSS") || !strings.Contains(md, "HIPAA") || !strings.Contains(md, "SOC 2") {
		t.Error("expected PCI/HIPAA/SOC2 column headers")
	}
}

func TestRenderComplianceHTML_EmptyFindings(t *testing.T) {
	html := RenderComplianceHTML(&model.ScanJob{ID: "x", Target: "t"}, model.ReportTemplateOptions{})
	if !strings.Contains(html, "No findings to map") {
		t.Error("expected empty-state message")
	}
}

func TestCapScreenshots(t *testing.T) {
	in := make([]Screenshot, MaxInlineScreenshots+5)
	out := capScreenshots(in, MaxInlineScreenshots)
	if len(out) != MaxInlineScreenshots {
		t.Errorf("expected %d, got %d", MaxInlineScreenshots, len(out))
	}
}

func TestSplitChain(t *testing.T) {
	cases := map[string]int{
		"a -> b -> c": 3,
		"a → b":       2,
		"single":      1,
	}
	for in, n := range cases {
		got := splitChain(in)
		if len(got) != n {
			t.Errorf("splitChain(%q) = %v, want %d segments", in, got, n)
		}
	}
}

func TestRenderPentestPDF_NonEmptyAndHasHash(t *testing.T) {
	pdf, err := RenderPentestPDF(sampleJob(), model.ReportTemplateOptions{})
	if err != nil {
		t.Fatalf("RenderPentestPDF: %v", err)
	}
	if len(pdf) == 0 {
		t.Fatal("expected non-empty PDF")
	}
	// Sanity: the report data hash is computed during BuildPentestReportData,
	// which is invoked by the PDF renderer; verify the same hash is non-empty.
	data := BuildPentestReportData(sampleJob(), model.ReportTemplateOptions{})
	if data.ContentHash == "" {
		t.Error("expected non-empty content hash to be embedded in footer")
	}
}
