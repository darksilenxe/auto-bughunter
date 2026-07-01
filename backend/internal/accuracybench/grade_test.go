package accuracybench

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func approxEqual(a, b float64) bool {
	if math.IsNaN(a) || math.IsNaN(b) {
		return false
	}
	return math.Abs(a-b) < 1e-9
}

func TestNormalizeCategory(t *testing.T) {
	cases := map[string]string{
		"SQL Injection":  "sqlinjection",
		"sql_injection":  "sqlinjection",
		"  sql-injection": "sqlinjection",
		"SQLI":           "sqli",
		"":               "",
	}
	for in, want := range cases {
		if got := normalizeCategory(in); got != want {
			t.Errorf("normalizeCategory(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/API/Users/":   "/api/users",
		"https://example.com/api/users?a=1": "/api/users",
		"/api/Users":                        "/api/users",
		"/":                                 "/",
		"":                                  "",
	}
	for in, want := range cases {
		if got := normalizeEndpoint(in); got != want {
			t.Errorf("normalizeEndpoint(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(model.SeverityCritical) <= severityRank(model.SeverityHigh) {
		t.Fatal("critical should outrank high")
	}
	if severityRank("") != 0 {
		t.Fatal("empty severity should rank 0")
	}
}

func TestGradePerfectScan(t *testing.T) {
	m := Manifest{
		Target: "juice-shop",
		ExpectedFindings: []ExpectedFinding{
			{Category: "sqli", Endpoint: "/rest/user/login", Parameter: "email", MinSeverity: model.SeverityHigh},
			{Category: "xss", Endpoint: "/#/search", Parameter: "q"},
		},
	}
	actual := ActualScan{
		Target: "juice-shop",
		Findings: []model.Finding{
			{Category: "SQLI", AffectedURL: "https://juice.com/rest/user/login", AffectedParameter: "email", Severity: model.SeverityCritical},
			{Category: "XSS", AffectedURL: "https://juice.com/#/search", AffectedParameter: "q", Severity: model.SeverityMedium},
		},
		PreReportVerificationPassRate: 1.0,
	}
	r := Grade([]Manifest{m}, map[string]ActualScan{"juice-shop": actual})
	if r.TruePositives != 2 || r.FalsePositives != 0 || r.FalseNegatives != 0 {
		t.Fatalf("expected 2/0/0, got %d/%d/%d", r.TruePositives, r.FalsePositives, r.FalseNegatives)
	}
	if !approxEqual(r.Precision, 1.0) || !approxEqual(r.Recall, 1.0) || !approxEqual(r.F1, 1.0) {
		t.Fatalf("expected 1.0/1.0/1.0, got %v/%v/%v", r.Precision, r.Recall, r.F1)
	}
	if !approxEqual(r.MeanPreReportVerificationPassRate, 1.0) {
		t.Fatalf("expected pass-rate 1.0, got %v", r.MeanPreReportVerificationPassRate)
	}
}

func TestGradeMissesLowSeverity(t *testing.T) {
	m := Manifest{
		Target: "t",
		ExpectedFindings: []ExpectedFinding{
			{Category: "sqli", Endpoint: "/a", MinSeverity: model.SeverityHigh},
		},
	}
	actual := ActualScan{
		Target: "t",
		Findings: []model.Finding{
			{Category: "sqli", AffectedURL: "/a", Severity: model.SeverityLow},
		},
	}
	r := Grade([]Manifest{m}, map[string]ActualScan{"t": actual})
	if r.TruePositives != 0 || r.FalseNegatives != 1 {
		t.Fatalf("low-severity actual should not satisfy high-severity expected; got tp=%d fn=%d", r.TruePositives, r.FalseNegatives)
	}
	// The low-severity finding is not a FP either: sqli is a graded category
	// but on the same endpoint, so it counts as a graded-category unexpected
	// finding (i.e. FP by the "unexpected finding in graded category" rule).
	if r.FalsePositives != 1 {
		t.Fatalf("expected leftover to be an FP (graded category), got fp=%d", r.FalsePositives)
	}
}

func TestGradeSafeEndpointCountsAsFP(t *testing.T) {
	m := Manifest{
		Target:        "clean-api",
		SafeEndpoints: []SafeEndpoint{{Category: "xss", Endpoint: "/api/users"}},
	}
	actual := ActualScan{
		Target: "clean-api",
		Findings: []model.Finding{
			{Category: "xss", AffectedURL: "/api/users", Severity: model.SeverityLow},
			// A finding in a category with no expected entries and no safe
			// endpoint is out-of-scope and MUST NOT count as an FP,
			// otherwise a new probe retroactively regresses every target.
			{Category: "csp", AffectedURL: "/api/users"},
		},
	}
	r := Grade([]Manifest{m}, map[string]ActualScan{"clean-api": actual})
	if r.FalsePositives != 1 {
		t.Fatalf("expected exactly one FP, got %d", r.FalsePositives)
	}
	if r.TruePositives != 0 || r.FalseNegatives != 0 {
		t.Fatalf("clean target should have tp=fn=0, got tp=%d fn=%d", r.TruePositives, r.FalseNegatives)
	}
}

func TestGradeAllowedExtraCategories(t *testing.T) {
	m := Manifest{
		Target:                 "t",
		ExpectedFindings:       []ExpectedFinding{{Category: "sqli", Endpoint: "/a"}},
		AllowedExtraCategories: []string{"info-disclosure"},
	}
	actual := ActualScan{
		Target: "t",
		Findings: []model.Finding{
			{Category: "sqli", AffectedURL: "/a"},
			// Would otherwise be counted because sqli is graded; but it's in
			// a different graded category, so it depends on the category set
			// — csp isn't graded so it's ignored regardless.
			{Category: "info-disclosure", AffectedURL: "/a"},
		},
	}
	r := Grade([]Manifest{m}, map[string]ActualScan{"t": actual})
	if r.FalsePositives != 0 {
		t.Fatalf("allowed extra category must not count as FP, got %d", r.FalsePositives)
	}
	if r.TruePositives != 1 {
		t.Fatalf("expected 1 TP, got %d", r.TruePositives)
	}
}

func TestGradeMissingActuals(t *testing.T) {
	corpus := []Manifest{
		{Target: "have", ExpectedFindings: []ExpectedFinding{{Category: "sqli", Endpoint: "/a"}}},
		{Target: "missing", ExpectedFindings: []ExpectedFinding{{Category: "sqli", Endpoint: "/b"}}},
	}
	actuals := map[string]ActualScan{
		"have": {Target: "have", Findings: []model.Finding{{Category: "sqli", AffectedURL: "/a"}}, PreReportVerificationPassRate: 0.75},
	}
	r := Grade(corpus, actuals)
	if len(r.TargetsWithoutActuals) != 1 || r.TargetsWithoutActuals[0] != "missing" {
		t.Fatalf("expected 'missing' to be recorded, got %v", r.TargetsWithoutActuals)
	}
	if !approxEqual(r.MeanPreReportVerificationPassRate, 0.75) {
		t.Fatalf("mean pass rate should ignore missing targets, got %v", r.MeanPreReportVerificationPassRate)
	}
	if r.FalseNegatives != 0 {
		t.Fatalf("missing target should NOT count as an FN; got fn=%d", r.FalseNegatives)
	}
}

func TestPassRateSentinelIgnored(t *testing.T) {
	corpus := []Manifest{{Target: "t"}}
	actuals := map[string]ActualScan{"t": {Target: "t", PreReportVerificationPassRate: -1}}
	r := Grade(corpus, actuals)
	if r.MeanPreReportVerificationPassRate != 0 {
		t.Fatalf("sentinel -1 must be excluded from the mean, got %v", r.MeanPreReportVerificationPassRate)
	}
}

func TestDiffReportsAndRegressions(t *testing.T) {
	base := Report{
		Precision: 0.90, Recall: 0.80, F1: 0.85,
		MeanPreReportVerificationPassRate: 0.95,
		CategoryTotals: []CategoryScore{
			{Category: "sqli", Precision: 1.0, Recall: 1.0, F1: 1.0},
		},
	}
	cand := Report{
		Precision: 0.85, Recall: 0.82, F1: 0.83,
		MeanPreReportVerificationPassRate: 0.90,
		CategoryTotals: []CategoryScore{
			{Category: "sqli", Precision: 0.90, Recall: 1.0, F1: 0.95},
			{Category: "xss", Precision: 0.50, Recall: 0.50, F1: 0.50},
		},
	}
	dr := DiffReports(base, cand)
	if len(dr.Metrics) == 0 {
		t.Fatal("expected metrics")
	}
	regs := dr.CheckRegressions(0.02)
	// aggregate precision dropped 0.05 (>tolerance), aggregate F1 dropped
	// 0.02 (== tolerance, not a regression), verify rate dropped 0.05,
	// per-category sqli precision dropped 0.10, sqli F1 dropped 0.05.
	// xss appears only in candidate so baseline is 0, candidate is 0.50 —
	// that's an improvement, not a regression.
	if regs == 0 {
		t.Fatal("expected at least one regression")
	}
	// Sanity: no regression should have positive delta.
	for _, r := range dr.Regressions {
		if r.Delta >= 0 {
			t.Fatalf("regression %+v has non-negative delta", r)
		}
	}
	// Tolerance edge case: equal-to-tolerance is not a regression.
	if r := dr.CheckRegressions(0.05); r > 0 {
		for _, x := range dr.Regressions {
			// F1 dropped by exactly 0.02 in aggregate; with tolerance 0.05
			// nothing should regress there.
			if approxEqual(x.Delta, -0.02) {
				t.Fatalf("delta -0.02 should not regress at tolerance 0.05")
			}
		}
	}
}

func TestRenderMarkdownIncludesKeySections(t *testing.T) {
	r := Report{
		Targets: []TargetReport{{
			Target: "juice-shop", TruePositives: 3, Precision: 0.75,
			PreReportVerificationPassRate: 0.9,
			Categories: []CategoryScore{{Category: "sqli", TruePositives: 3, Precision: 0.75}},
		}},
		CategoryTotals:        []CategoryScore{{Category: "sqli", TruePositives: 3, Precision: 0.75}},
		TruePositives:         3,
		Precision:             0.75,
		TargetsWithoutActuals: []string{"crapi"},
	}
	md := RenderMarkdown(r)
	for _, want := range []string{"# Accuracy benchmark report", "Aggregate", "Per-category totals", "Per-target", "Targets without actual scans", "juice-shop", "crapi"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestLoadCorpusAndActuals(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	actualsDir := filepath.Join(dir, "actuals")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(actualsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := Manifest{Target: "t", ExpectedFindings: []ExpectedFinding{{Category: "sqli", Endpoint: "/a"}}}
	writeJSON(t, filepath.Join(corpusDir, "t.json"), m)
	writeJSON(t, filepath.Join(corpusDir, "readme.md"), "not-json") // ignored
	writeJSON(t, filepath.Join(actualsDir, "t.json"), ActualScan{Target: "t", Findings: []model.Finding{{Category: "sqli", AffectedURL: "/a"}}, PreReportVerificationPassRate: 1})

	corpus, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(corpus))
	}
	actuals, err := LoadActuals(actualsDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := actuals["t"]; !ok {
		t.Fatal("expected key 't'")
	}
	r := Grade(corpus, actuals)
	if r.TruePositives != 1 {
		t.Fatalf("expected 1 TP, got %d", r.TruePositives)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	var data []byte
	switch x := v.(type) {
	case string:
		data = []byte(x)
	default:
		var err error
		data, err = json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
