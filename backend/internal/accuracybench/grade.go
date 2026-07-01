package accuracybench

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// severityRank returns a total ordering for severities so we can compare
// "at least this severe" cheaply. Unknown severities rank as Info.
func severityRank(s model.Severity) int {
	switch strings.ToLower(strings.TrimSpace(string(s))) {
	case string(model.SeverityCritical):
		return 4
	case string(model.SeverityHigh):
		return 3
	case string(model.SeverityMedium):
		return 2
	case string(model.SeverityLow):
		return 1
	default:
		return 0
	}
}

// CategoryScore is the graded result for a single category on a single
// target.
type CategoryScore struct {
	Category       string  `json:"category"`
	TruePositives  int     `json:"truePositives"`
	FalsePositives int     `json:"falsePositives"`
	FalseNegatives int     `json:"falseNegatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	F1             float64 `json:"f1"`
}

// TargetReport is the graded result for a single target.
type TargetReport struct {
	Target                        string          `json:"target"`
	Categories                    []CategoryScore `json:"categories"`
	TruePositives                 int             `json:"truePositives"`
	FalsePositives                int             `json:"falsePositives"`
	FalseNegatives                int             `json:"falseNegatives"`
	Precision                     float64         `json:"precision"`
	Recall                        float64         `json:"recall"`
	F1                            float64         `json:"f1"`
	PreReportVerificationPassRate float64         `json:"preReportVerificationPassRate"`
	// UnmatchedExpected lists the ExpectedFinding entries that were not
	// satisfied by any actual finding (i.e. the false negatives, in
	// human-readable form). Useful for triage.
	UnmatchedExpected []ExpectedFinding `json:"unmatchedExpected,omitempty"`
	// UnexpectedFindings lists actual findings that counted as false
	// positives, in human-readable form.
	UnexpectedFindings []UnexpectedFinding `json:"unexpectedFindings,omitempty"`
}

// UnexpectedFinding is a compact summary of a false-positive finding for
// inclusion in the report.
type UnexpectedFinding struct {
	Category  string         `json:"category"`
	Endpoint  string         `json:"endpoint"`
	Parameter string         `json:"parameter,omitempty"`
	Severity  model.Severity `json:"severity,omitempty"`
	Title     string         `json:"title,omitempty"`
	Reason    string         `json:"reason,omitempty"`
}

// Report is the top-level output of the harness for one bench run.
type Report struct {
	GeneratedAt                       time.Time       `json:"generatedAt"`
	Targets                           []TargetReport  `json:"targets"`
	CategoryTotals                    []CategoryScore `json:"categoryTotals"`
	TruePositives                     int             `json:"truePositives"`
	FalsePositives                    int             `json:"falsePositives"`
	FalseNegatives                    int             `json:"falseNegatives"`
	Precision                         float64         `json:"precision"`
	Recall                            float64         `json:"recall"`
	F1                                float64         `json:"f1"`
	MeanPreReportVerificationPassRate float64         `json:"meanPreReportVerificationPassRate"`
	// TargetsWithoutActuals lists manifest targets for which no actual scan
	// was supplied. They are reported but excluded from aggregate math so a
	// missing scan can't silently zero out a precision score.
	TargetsWithoutActuals []string `json:"targetsWithoutActuals,omitempty"`
}

func computeRates(tp, fp, fn int) (precision, recall, f1 float64) {
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return
}

// Grade evaluates a corpus of manifests against a keyed set of actual scans
// and returns a Report. Manifests without a matching ActualScan are recorded
// in TargetsWithoutActuals and excluded from aggregate math.
func Grade(corpus []Manifest, actuals map[string]ActualScan) Report {
	report := Report{GeneratedAt: time.Now().UTC()}
	catAgg := make(map[string]*CategoryScore)
	var passRateSum float64
	var passRateCount int

	for _, m := range corpus {
		actual, ok := actuals[m.Target]
		if !ok {
			report.TargetsWithoutActuals = append(report.TargetsWithoutActuals, m.Target)
			continue
		}
		tr := gradeTarget(m, actual)
		report.Targets = append(report.Targets, tr)
		report.TruePositives += tr.TruePositives
		report.FalsePositives += tr.FalsePositives
		report.FalseNegatives += tr.FalseNegatives
		for _, cs := range tr.Categories {
			agg, ok := catAgg[cs.Category]
			if !ok {
				agg = &CategoryScore{Category: cs.Category}
				catAgg[cs.Category] = agg
			}
			agg.TruePositives += cs.TruePositives
			agg.FalsePositives += cs.FalsePositives
			agg.FalseNegatives += cs.FalseNegatives
		}
		if actual.PreReportVerificationPassRate >= 0 {
			passRateSum += actual.PreReportVerificationPassRate
			passRateCount++
		}
	}

	report.Precision, report.Recall, report.F1 = computeRates(
		report.TruePositives, report.FalsePositives, report.FalseNegatives,
	)
	if passRateCount > 0 {
		report.MeanPreReportVerificationPassRate = passRateSum / float64(passRateCount)
	}

	keys := make([]string, 0, len(catAgg))
	for k := range catAgg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		agg := catAgg[k]
		agg.Precision, agg.Recall, agg.F1 = computeRates(agg.TruePositives, agg.FalsePositives, agg.FalseNegatives)
		report.CategoryTotals = append(report.CategoryTotals, *agg)
	}
	return report
}

// gradeTarget applies the matching rules described on Manifest to compute a
// TargetReport. The matching rules are:
//
//  1. Each ExpectedFinding consumes at most one actual finding of the same
//     normalized category whose normalized endpoint matches and whose
//     parameter matches (if the expected entry specifies one). A consumed
//     actual finding becomes a true positive.
//  2. An expected finding that consumes nothing becomes a false negative.
//  3. Any leftover actual finding is a candidate false positive. It is
//     counted as such iff:
//        - its category is not in AllowedExtraCategories, AND
//        - its (category, endpoint[, parameter]) matches a SafeEndpoint
//          entry, OR the category has any expected finding at all (i.e.
//          the scanner reported something in a graded category on an
//          endpoint we didn't expect).
//     Unexpected findings in categories with zero expected entries and no
//     matching SafeEndpoint are treated as "out of scope for this target"
//     and skipped so that adding a new probe doesn't retroactively regress
//     every historical target.
func gradeTarget(m Manifest, actual ActualScan) TargetReport {
	allowed := make(map[string]struct{}, len(m.AllowedExtraCategories))
	for _, c := range m.AllowedExtraCategories {
		allowed[normalizeCategory(c)] = struct{}{}
	}

	type actualIdx struct {
		f       model.Finding
		catN    string
		urlN    string
		paramN  string
		claimed bool
	}
	actuals := make([]actualIdx, len(actual.Findings))
	for i, f := range actual.Findings {
		actuals[i] = actualIdx{
			f:      f,
			catN:   normalizeCategory(f.Category),
			urlN:   normalizeEndpoint(f.AffectedURL),
			paramN: normalizeParameter(f.AffectedParameter),
		}
	}

	// Categories that appear in expected findings — used to decide whether
	// a leftover actual finding is a false positive vs out-of-scope.
	expectedCats := make(map[string]struct{})
	for _, exp := range m.ExpectedFindings {
		expectedCats[normalizeCategory(exp.Category)] = struct{}{}
	}

	catScores := make(map[string]*CategoryScore)
	getScore := func(cat string) *CategoryScore {
		cs, ok := catScores[cat]
		if !ok {
			cs = &CategoryScore{Category: cat}
			catScores[cat] = cs
		}
		return cs
	}

	var unmatched []ExpectedFinding
	for _, exp := range m.ExpectedFindings {
		catN := normalizeCategory(exp.Category)
		urlN := normalizeEndpoint(exp.Endpoint)
		paramN := normalizeParameter(exp.Parameter)
		minRank := severityRank(exp.MinSeverity)

		matchedIdx := -1
		for i := range actuals {
			a := &actuals[i]
			if a.claimed || a.catN != catN {
				continue
			}
			if urlN != "" && a.urlN != urlN {
				continue
			}
			if paramN != "" && a.paramN != paramN {
				continue
			}
			if minRank > 0 && severityRank(a.f.Severity) < minRank {
				continue
			}
			matchedIdx = i
			break
		}
		if matchedIdx >= 0 {
			actuals[matchedIdx].claimed = true
			getScore(catN).TruePositives++
		} else {
			getScore(catN).FalseNegatives++
			unmatched = append(unmatched, exp)
		}
	}

	// Compute FPs from leftover actuals.
	safeIndex := make(map[string][]SafeEndpoint)
	for _, se := range m.SafeEndpoints {
		key := normalizeCategory(se.Category)
		safeIndex[key] = append(safeIndex[key], se)
	}

	var unexpected []UnexpectedFinding
	for _, a := range actuals {
		if a.claimed {
			continue
		}
		if _, ok := allowed[a.catN]; ok {
			continue
		}
		isFP := false
		reason := ""
		// SafeEndpoint match beats everything else.
		for _, se := range safeIndex[a.catN] {
			seURL := normalizeEndpoint(se.Endpoint)
			seParam := normalizeParameter(se.Parameter)
			if seURL != "" && seURL != a.urlN {
				continue
			}
			if seParam != "" && seParam != a.paramN {
				continue
			}
			isFP = true
			reason = "matched SafeEndpoint"
			if se.Note != "" {
				reason = "matched SafeEndpoint: " + se.Note
			}
			break
		}
		if !isFP {
			if _, graded := expectedCats[a.catN]; graded {
				isFP = true
				reason = "unexpected finding in graded category"
			}
		}
		if isFP {
			getScore(a.catN).FalsePositives++
			unexpected = append(unexpected, UnexpectedFinding{
				Category:  a.catN,
				Endpoint:  a.urlN,
				Parameter: a.paramN,
				Severity:  a.f.Severity,
				Title:     a.f.Title,
				Reason:    reason,
			})
		}
	}

	tr := TargetReport{
		Target:                        m.Target,
		PreReportVerificationPassRate: actual.PreReportVerificationPassRate,
		UnmatchedExpected:             unmatched,
		UnexpectedFindings:            unexpected,
	}
	keys := make([]string, 0, len(catScores))
	for k := range catScores {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cs := catScores[k]
		cs.Precision, cs.Recall, cs.F1 = computeRates(cs.TruePositives, cs.FalsePositives, cs.FalseNegatives)
		tr.Categories = append(tr.Categories, *cs)
		tr.TruePositives += cs.TruePositives
		tr.FalsePositives += cs.FalsePositives
		tr.FalseNegatives += cs.FalseNegatives
	}
	tr.Precision, tr.Recall, tr.F1 = computeRates(tr.TruePositives, tr.FalsePositives, tr.FalseNegatives)
	return tr
}

// Delta expresses a per-metric change between a baseline report and a
// candidate report. Positive Delta values mean the candidate is *better*
// than the baseline for that metric (higher precision/recall/F1, higher
// verification pass rate). Negative Delta values are regressions.
type Delta struct {
	Metric   string  `json:"metric"`
	Baseline float64 `json:"baseline"`
	Candidate float64 `json:"candidate"`
	Delta    float64 `json:"delta"`
	// Category is empty for aggregate metrics and set to the normalized
	// category for per-category rows.
	Category string `json:"category,omitempty"`
}

// DeltaReport is a diff of two Reports.
type DeltaReport struct {
	Baseline  Report  `json:"-"`
	Candidate Report  `json:"-"`
	Metrics   []Delta `json:"metrics"`
	// Regressions is the subset of Metrics whose Delta is strictly less
	// than -Tolerance (for precision/recall/F1) or which drops the value
	// below 0 in absolute terms. Populated by CheckRegressions.
	Regressions []Delta `json:"regressions,omitempty"`
	Tolerance   float64 `json:"tolerance"`
}

// DiffReports computes a DeltaReport comparing baseline and candidate. The
// harness runs even when the two reports don't cover the same category set
// — a category present only in one is treated as if the other reported
// zero.
func DiffReports(baseline, candidate Report) DeltaReport {
	dr := DeltaReport{Baseline: baseline, Candidate: candidate}
	add := func(metric, category string, b, c float64) {
		dr.Metrics = append(dr.Metrics, Delta{
			Metric:    metric,
			Category:  category,
			Baseline:  b,
			Candidate: c,
			Delta:     c - b,
		})
	}
	add("precision", "", baseline.Precision, candidate.Precision)
	add("recall", "", baseline.Recall, candidate.Recall)
	add("f1", "", baseline.F1, candidate.F1)
	add("preReportVerificationPassRate", "",
		baseline.MeanPreReportVerificationPassRate,
		candidate.MeanPreReportVerificationPassRate)

	byCatBase := indexCategoryTotals(baseline.CategoryTotals)
	byCatCand := indexCategoryTotals(candidate.CategoryTotals)
	cats := mergedCategoryKeys(byCatBase, byCatCand)
	for _, cat := range cats {
		b := byCatBase[cat]
		c := byCatCand[cat]
		add("precision", cat, b.Precision, c.Precision)
		add("recall", cat, b.Recall, c.Recall)
		add("f1", cat, b.F1, c.F1)
	}
	return dr
}

func indexCategoryTotals(rows []CategoryScore) map[string]CategoryScore {
	out := make(map[string]CategoryScore, len(rows))
	for _, r := range rows {
		out[r.Category] = r
	}
	return out
}

func mergedCategoryKeys(a, b map[string]CategoryScore) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CheckRegressions flags every metric whose Delta is below -tolerance as a
// regression and populates DeltaReport.Regressions. It returns the number of
// regressions found so callers can gate CI on len == 0.
func (dr *DeltaReport) CheckRegressions(tolerance float64) int {
	if tolerance < 0 || math.IsNaN(tolerance) {
		tolerance = 0
	}
	dr.Tolerance = tolerance
	dr.Regressions = dr.Regressions[:0]
	for _, m := range dr.Metrics {
		if m.Delta < -tolerance {
			dr.Regressions = append(dr.Regressions, m)
		}
	}
	return len(dr.Regressions)
}

// RenderMarkdown returns a compact markdown summary suitable for GitHub
// workflow artifacts.
func RenderMarkdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Accuracy benchmark report\n\n")
	fmt.Fprintf(&b, "_Generated %s_\n\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "## Aggregate\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| True positives | %d |\n", r.TruePositives)
	fmt.Fprintf(&b, "| False positives | %d |\n", r.FalsePositives)
	fmt.Fprintf(&b, "| False negatives | %d |\n", r.FalseNegatives)
	fmt.Fprintf(&b, "| Precision | %s |\n", pct(r.Precision))
	fmt.Fprintf(&b, "| Recall | %s |\n", pct(r.Recall))
	fmt.Fprintf(&b, "| F1 | %s |\n", pct(r.F1))
	fmt.Fprintf(&b, "| Mean pre-report verification pass rate | %s |\n\n", pct(r.MeanPreReportVerificationPassRate))

	if len(r.CategoryTotals) > 0 {
		fmt.Fprintf(&b, "## Per-category totals\n\n")
		fmt.Fprintf(&b, "| Category | TP | FP | FN | Precision | Recall | F1 |\n")
		fmt.Fprintf(&b, "|---|---:|---:|---:|---:|---:|---:|\n")
		for _, c := range r.CategoryTotals {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %s | %s | %s |\n",
				c.Category, c.TruePositives, c.FalsePositives, c.FalseNegatives,
				pct(c.Precision), pct(c.Recall), pct(c.F1))
		}
		fmt.Fprintln(&b)
	}

	if len(r.Targets) > 0 {
		fmt.Fprintf(&b, "## Per-target\n\n")
		fmt.Fprintf(&b, "| Target | TP | FP | FN | Precision | Recall | F1 | Verify pass |\n")
		fmt.Fprintf(&b, "|---|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, t := range r.Targets {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %s | %s | %s | %s |\n",
				t.Target, t.TruePositives, t.FalsePositives, t.FalseNegatives,
				pct(t.Precision), pct(t.Recall), pct(t.F1),
				pct(t.PreReportVerificationPassRate))
		}
		fmt.Fprintln(&b)
	}

	if len(r.TargetsWithoutActuals) > 0 {
		fmt.Fprintf(&b, "## Targets without actual scans\n\n")
		for _, t := range r.TargetsWithoutActuals {
			fmt.Fprintf(&b, "- %s\n", t)
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

// RenderDeltaMarkdown returns a compact markdown diff between two reports.
func RenderDeltaMarkdown(dr DeltaReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Accuracy benchmark delta\n\n")
	fmt.Fprintf(&b, "Tolerance: %s\n\n", pct(dr.Tolerance))
	fmt.Fprintf(&b, "| Metric | Category | Baseline | Candidate | Delta |\n")
	fmt.Fprintf(&b, "|---|---|---:|---:|---:|\n")
	for _, m := range dr.Metrics {
		cat := m.Category
		if cat == "" {
			cat = "_aggregate_"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %+s |\n",
			m.Metric, cat, pct(m.Baseline), pct(m.Candidate), pct(m.Delta))
	}
	if len(dr.Regressions) > 0 {
		fmt.Fprintf(&b, "\n## Regressions\n\n")
		for _, m := range dr.Regressions {
			cat := m.Category
			if cat == "" {
				cat = "_aggregate_"
			}
			fmt.Fprintf(&b, "- **%s** [%s]: %s -> %s (delta %+s)\n",
				m.Metric, cat, pct(m.Baseline), pct(m.Candidate), pct(m.Delta))
		}
	}
	return b.String()
}

func pct(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", v*100)
}
