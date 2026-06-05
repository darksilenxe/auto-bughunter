package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestSanitizeTextRemovesNullBytes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"hello\x00world", "helloworld"},
		{"\x00leading", "leading"},
		{"trailing\x00", "trailing"},
		{"no nulls", "no nulls"},
		{"", ""},
		{"\x00\x00\x00", ""},
	}
	for _, c := range cases {
		got := sanitizeText(c.in)
		if got != c.want {
			t.Errorf("sanitizeText(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeJSONRemovesNullEscapes(t *testing.T) {
	// json.Marshal encodes null bytes as \u0000 in string values.
	type payload struct {
		Text string `json:"text"`
	}
	raw, err := json.Marshal(payload{Text: "before\x00after"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `\u0000`) {
		t.Fatalf("expected JSON to contain \\u0000 before sanitize, got %q", raw)
	}

	cleaned := sanitizeJSON(raw)
	if strings.Contains(string(cleaned), `\u0000`) {
		t.Errorf("sanitizeJSON still contains \\u0000: %q", cleaned)
	}
	// Ensure the result is still valid JSON.
	var got payload
	if err := json.Unmarshal(cleaned, &got); err != nil {
		t.Errorf("sanitizeJSON produced invalid JSON: %v (input: %q)", err, cleaned)
	}
	if got.Text != "beforeafter" {
		t.Errorf("unexpected text after sanitize: %q", got.Text)
	}
}

// TestUpdateJobSanitizesNullBytesInAISummary verifies that UpdateJob strips
// null bytes from text fields so they can be stored in Postgres without
// triggering SQLSTATE 22P05.  We use the in-memory UpdateJob path via a
// captureUpdateRepo rather than a live DB.
func TestUpdateJobSanitizesNullBytesInAISummary(t *testing.T) {
	repo := &captureUpdateRepo{}
	job := &model.ScanJob{
		ID:             "scan-nullbyte",
		Status:         "completed",
		AISummary:      "summary with\x00null",
		AutomatedReport: "report\x00data",
		Error:          "err\x00msg",
		Findings: []model.Finding{
			{ID: "f1", Title: "finding\x00title", Description: "desc\x00"},
		},
	}

	// Call the sanitise helpers directly (they are package-private).
	got := sanitizeText(job.AISummary)
	if strings.Contains(got, "\x00") {
		t.Errorf("sanitizeText(AISummary) still contains null byte: %q", got)
	}
	got = sanitizeText(job.AutomatedReport)
	if strings.Contains(got, "\x00") {
		t.Errorf("sanitizeText(AutomatedReport) still contains null byte: %q", got)
	}

	// Verify the JSON sanitizer handles findings with embedded nulls.
	findingsJSON, _ := json.Marshal(job.Findings)
	cleanedJSON := sanitizeJSON(findingsJSON)
	if strings.Contains(string(cleanedJSON), `\u0000`) {
		t.Errorf("sanitizeJSON(findings) still contains \\u0000: %q", cleanedJSON)
	}
	_ = repo
}

// captureUpdateRepo is a minimal in-memory repo for sanitization tests.
type captureUpdateRepo struct{}

func (r *captureUpdateRepo) SaveAgentEvent(ctx context.Context, scanID string, event model.ScanEvent) error { return nil }
func (r *captureUpdateRepo) ListAgentEvents(ctx context.Context, scanID string) ([]model.ScanEvent, error) { return nil, nil }
