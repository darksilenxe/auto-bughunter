package report

import (
	"bytes"
	"encoding/csv"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// csvHeader is the ordered column set emitted by RenderFindingsCSV. The schema
// is intentionally flat and ticketing-friendly (one row per finding).
var csvHeader = []string{
	"id", "title", "severity", "confidence", "category",
	"cwe", "owasp", "affected_url", "affected_parameter",
	"cvss_score", "cvss_vector", "evidence", "recommendation",
}

// RenderFindingsCSV produces a flat, one-row-per-finding CSV export suitable
// for import into spreadsheets and issue trackers. It is safe to call with a
// nil job (an empty body with only the header row is returned).
func RenderFindingsCSV(job *model.ScanJob, opts model.ReportTemplateOptions, ctx ...ReportContext) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write(csvHeader)

	for _, f := range reportFindings(job) {
		row := []string{
			f.ID,
			f.Title,
			string(f.Severity),
			strconv.FormatFloat(f.Confidence, 'f', 2, 64),
			f.Category,
			f.CWE,
			f.OWASPCategory,
			f.AffectedURL,
			f.AffectedParameter,
			csvFloat(f.CVSSScore),
			f.CVSSVector,
			csvClean(f.Evidence),
			csvClean(f.Recommendation),
		}
		_ = w.Write(row)
	}

	w.Flush()
	return buf.Bytes()
}

// csvFloat renders a CVSS score, leaving it blank when unset (zero).
func csvFloat(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// csvClean collapses newlines/tabs so multi-line evidence stays within a single
// CSV cell that spreadsheet tools render cleanly.
func csvClean(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}
