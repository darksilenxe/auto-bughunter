package report

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func sampleReportJob() *model.ScanJob {
	return &model.ScanJob{
		Target: "https://example.com",
		Findings: []model.Finding{
			{
				ID:            "f-1",
				Title:         "Reflected XSS",
				Severity:      model.SeverityHigh,
				Confidence:    0.9,
				Category:      "xss",
				CWE:           "CWE-79",
				OWASPCategory: "A03:2021",
				AffectedURL:   "https://example.com/search?q=1",
				Evidence:      "payload reflected\nin response",
			},
			{
				ID:       "f-2",
				Title:    "Info disclosure",
				Severity: model.SeverityInfo,
				Category: "info",
			},
		},
	}
}

func TestRenderSARIFStructure(t *testing.T) {
	out, err := RenderSARIF(sampleReportJob(), model.ReportTemplateOptions{})
	if err != nil {
		t.Fatalf("RenderSARIF error: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != sarifVersion {
		t.Errorf("version = %q, want %q", log.Version, sarifVersion)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if len(run.Results) != 2 {
		t.Errorf("results = %d, want 2", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("high severity level = %q, want error", run.Results[0].Level)
	}
	if len(run.Results[0].Locations) == 0 {
		t.Errorf("expected location for finding with AffectedURL")
	}
}

func TestRenderSARIFNilJob(t *testing.T) {
	out, err := RenderSARIF(nil, model.ReportTemplateOptions{})
	if err != nil {
		t.Fatalf("RenderSARIF(nil) error: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected non-empty SARIF for nil job")
	}
}

func TestRenderFindingsCSV(t *testing.T) {
	out := RenderFindingsCSV(sampleReportJob(), model.ReportTemplateOptions{})
	r := csv.NewReader(strings.NewReader(string(out)))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (header + 2 findings)", len(rows))
	}
	if len(rows[0]) != len(csvHeader) {
		t.Errorf("header columns = %d, want %d", len(rows[0]), len(csvHeader))
	}
	// Evidence newlines must be collapsed within the single cell.
	if strings.Contains(rows[1][11], "\n") {
		t.Errorf("evidence cell still contains newline: %q", rows[1][11])
	}
}
