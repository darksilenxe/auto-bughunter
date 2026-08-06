package report

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestSeverityRationaleMentionsSeverityAndCWE(t *testing.T) {
	f := model.Finding{
		Severity:   model.SeverityHigh,
		CVSSScore:  8.1,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CWE:        "CWE-89",
		Confidence: 0.92,
		Exploitability: &model.Exploitability{
			Reachable:    true,
			RequiredRole: "anonymous",
		},
		BusinessTags: []string{"payments"},
	}
	lines := SeverityRationale(f)
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 rationale lines, got %d", len(lines))
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"HIGH", "CVSS", "CWE-89", "0.92", "anonymous", "payments"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rationale missing %q\n%s", want, joined)
		}
	}
}

func TestRenderBugBountyMarkdownContainsRationaleAndChecklist(t *testing.T) {
	f := model.Finding{
		ID:                "f1",
		Title:             "SQL injection in /api/login",
		Severity:          model.SeverityHigh,
		Category:          "injection",
		AffectedURL:       "https://example.com/api/login",
		AffectedParameter: "username",
		Evidence:          "1=1 returned 200",
		ReproductionSteps: []string{"send '"},
		Confidence:        0.95,
		EvidenceFields:    map[string]string{"curlReproducer": "curl https://example.com/api/login"},
	}
	md := RenderBugBountyMarkdownForPlatform(f, "https://example.com", "hackerone")
	for _, want := range []string{
		"HackerOne",
		"## Severity Rationale",
		"## Reproducibility Evidence",
		"Curl reproducer",
		"Step-by-step reproduction",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in markdown:\n%s", want, md)
		}
	}
}

func TestRenderBugBountyMarkdownUnknownPlatformIsAgnostic(t *testing.T) {
	f := model.Finding{ID: "f1", Title: "Test", Severity: model.SeverityLow}
	md := RenderBugBountyMarkdownForPlatform(f, "https://example.com", "unknown-platform")
	if strings.Contains(md, "Submission target") {
		t.Errorf("unknown platform should not include a banner; got:\n%s", md)
	}
}

func TestFindDuplicatesScoresAboveThreshold(t *testing.T) {
	current := []model.Finding{{
		ID:                "f-cur",
		Title:             "Reflected XSS in search parameter",
		Category:          "xss",
		CWE:               "CWE-79",
		AffectedURL:       "https://example.com/search?q=1",
		AffectedParameter: "q",
	}}
	prior := []PriorFinding{
		{
			ScanID: "scan-old",
			Target: "https://example.com",
			Finding: model.Finding{
				ID:                "f-prior-1",
				Title:             "Reflected XSS in search parameter",
				Category:          "xss",
				CWE:               "CWE-79",
				AffectedURL:       "https://example.com/search?q=2",
				AffectedParameter: "q",
			},
		},
		{
			ScanID: "scan-other",
			Target: "https://example.com",
			Finding: model.Finding{
				ID:       "f-prior-2",
				Title:    "Missing security headers",
				Category: "headers",
			},
		},
	}
	matches := FindDuplicates(current, prior, 0.6)
	if len(matches) != 1 {
		t.Fatalf("expected 1 duplicate group, got %d", len(matches))
	}
	if got := matches[0].FindingID; got != "f-cur" {
		t.Errorf("unexpected finding id: %s", got)
	}
	if len(matches[0].Candidates) != 1 || matches[0].Candidates[0].FindingID != "f-prior-1" {
		t.Fatalf("expected single candidate f-prior-1, got %+v", matches[0].Candidates)
	}
	if matches[0].Candidates[0].Score < 0.6 {
		t.Errorf("expected score >= 0.6, got %v", matches[0].Candidates[0].Score)
	}
	matched := strings.Join(matches[0].Candidates[0].MatchedOn, ",")
	for _, want := range []string{"category", "cwe", "url", "parameter"} {
		if !strings.Contains(matched, want) {
			t.Errorf("expected matchedOn to include %q, got %s", want, matched)
		}
	}
}

func TestFindDuplicatesIgnoresLowSimilarity(t *testing.T) {
	current := []model.Finding{{ID: "f1", Title: "SSRF in webhook URL", Category: "ssrf", CWE: "CWE-918"}}
	prior := []PriorFinding{{ScanID: "old", Finding: model.Finding{ID: "p1", Title: "Open redirect", Category: "redirect"}}}
	matches := FindDuplicates(current, prior, 0)
	if len(matches) != 0 {
		t.Fatalf("expected no matches for unrelated findings, got %d", len(matches))
	}
}

func TestSubmissionReadinessScore_FullFinding(t *testing.T) {
	f := model.Finding{
		ID:                "f1",
		Title:             "SQL Injection in /api/login",
		Description:       "Classic SQL injection via username parameter.",
		Severity:          model.SeverityHigh,
		AffectedURL:       "https://example.com/api/login",
		AffectedParameter: "username",
		ReproductionSteps: []string{"Send ' OR 1=1--"},
		Evidence:          "Response returned all user rows",
		CWE:               "CWE-89",
		CVSSScore:         9.1,
		Impact:            "Full database read access",
		Recommendation:    "Use parameterized queries",
		ProofArtifacts:    []model.ProofArtifact{{Type: "curl", Label: "Reproducer", Value: "curl ..."}},
		Confidence:        0.95,
	}
	res := SubmissionReadinessScore(f)
	if res.Score < 90 {
		t.Errorf("expected score >= 90 for complete finding, got %d (missing: %v)", res.Score, res.MissingFields)
	}
	if !res.ReadyToSubmit {
		t.Error("expected ReadyToSubmit=true")
	}
}

func TestSubmissionReadinessScore_MinimalFinding(t *testing.T) {
	f := model.Finding{
		Title:    "Missing Content-Security-Policy",
		Severity: model.SeverityLow,
	}
	res := SubmissionReadinessScore(f)
	if res.Score >= 90 {
		t.Errorf("expected score < 90 for minimal finding, got %d", res.Score)
	}
	if res.ReadyToSubmit {
		t.Error("expected ReadyToSubmit=false for minimal finding")
	}
	if len(res.MissingFields) == 0 {
		t.Error("expected missing fields for minimal finding")
	}
}

func TestSubmissionReadinessScore_InfoSeverityPenalized(t *testing.T) {
	f := model.Finding{
		Title:             "Info-level finding",
		Description:       "Some informational note.",
		Severity:          model.SeverityInfo, // penalized: non-informational required
		AffectedURL:       "https://example.com",
		AffectedParameter: "x",
		ReproductionSteps: []string{"step 1"},
		Evidence:          "evidence",
		CWE:               "CWE-200",
		CVSSScore:         1.0,
		Impact:            "low",
		Recommendation:    "fix it",
		ProofArtifacts:    []model.ProofArtifact{{Type: "note"}},
		Confidence:        0.8,
	}
	res := SubmissionReadinessScore(f)
	// SeverityInfo should be penalized (-10 points).
	if res.Score > 90 {
		t.Errorf("info-severity should reduce score below 90, got %d", res.Score)
	}
}

func TestPlatformFieldMappingKnownPlatforms(t *testing.T) {
	for _, platform := range []string{"hackerone", "bugcrowd", "intigriti"} {
		m := PlatformFieldMapping(platform)
		if len(m) == 0 {
			t.Fatalf("expected mapping for %s", platform)
		}
		if m["Title"] == "" {
			t.Fatalf("expected title mapping for %s", platform)
		}
	}
	if got := PlatformFieldMapping("unknown"); got != nil {
		t.Fatalf("expected nil mapping for unknown platform, got %#v", got)
	}
}

func TestRenderBugBountyZipForPlatform_EmitsCoverageArtifacts(t *testing.T) {
	job := &model.ScanJob{
		ID:     "scan-1",
		Target: "https://example.com",
		Findings: []model.Finding{
			{ID: "f1", Title: "test", Severity: model.SeverityLow},
		},
		CoverageMap: &model.CoverageMap{
			GeneratedAt:   time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC),
			Target:        "https://example.com",
			CoverageRatio: 0.5,
			Areas: []model.CoverageMapArea{
				{Type: model.CoverageAreaEndpoint, Key: "GET example.com/api", Source: "runtime_xhr", ROIScore: 0.9, Probed: false},
			},
		},
	}
	zipBytes, err := RenderBugBountyZipForPlatform(job, "hackerone")
	if err != nil {
		t.Fatalf("render zip: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	var hasMap, hasHeatmap bool
	for _, f := range zr.File {
		if f.Name == "COVERAGE_MAP.json" {
			hasMap = true
		}
		if f.Name == "COVERAGE_HEATMAP.md" {
			hasHeatmap = true
		}
	}
	if !hasMap || !hasHeatmap {
		t.Fatalf("expected coverage artifacts, hasMap=%v hasHeatmap=%v", hasMap, hasHeatmap)
	}
}
