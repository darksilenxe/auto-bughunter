package agent

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

type AnalysisAgent struct {
	enabled bool
}

func NewAnalysisAgent(enabled bool) *AnalysisAgent {
	return &AnalysisAgent{enabled: enabled}
}

func (a *AnalysisAgent) Name() string {
	return "analysis"
}

func (a *AnalysisAgent) Enabled() bool {
	return a.enabled
}

func (a *AnalysisAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	allFindings := input.AllFindings
	if len(allFindings) == 0 {
		allFindings = input.Previous.Findings
	}
	if len(allFindings) == 0 {
		output.DebugNotes = "No findings to analyze"
		return output, nil
	}

	deduped := deduplicateFindings(allFindings)
	scored := scoreAndRankFindings(deduped)

	output.Findings = scored
	output.Metadata["original_count"] = fmt.Sprintf("%d", len(allFindings))
	output.Metadata["deduped_count"] = fmt.Sprintf("%d", len(deduped))
	output.Metadata["high_severity"] = fmt.Sprintf("%d", countBySeverity(scored, model.SeverityHigh))
	output.Metadata["medium_severity"] = fmt.Sprintf("%d", countBySeverity(scored, model.SeverityMedium))

	output.DebugNotes = fmt.Sprintf("Deduplicated %d findings to %d unique issues; scored and ranked by severity and category.", len(allFindings), len(deduped))

	return output, nil
}

// deduplicateFindings collapses near-duplicate findings into a single
// representative. Two findings are considered duplicates when they share
// the same category and a normalised "signature" derived from
// (CWE, ID, affected parameter, host of affected URL). When duplicates
// cluster:
//
//   - The representative is the highest-severity (and, on ties, the
//     highest-confidence) finding in the cluster.
//   - The number of additional members and a sample of their affected
//     URLs is appended to the representative's evidence so a triager can
//     see at a glance "this issue affects N endpoints" rather than
//     scrolling past N nearly-identical entries.
//
// Findings without enough metadata to compute a signature fall back to
// the legacy `category:title` key.
func deduplicateFindings(findings []model.Finding) []model.Finding {
	groups := make(map[string][]model.Finding)
	keys := make([]string, 0)
	for _, f := range findings {
		key := findingClusterKey(f)
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], f)
	}

	deduped := make([]model.Finding, 0, len(groups))
	for _, key := range keys {
		members := groups[key]
		rep := pickClusterRepresentative(members)
		if len(members) > 1 {
			rep = annotateWithCluster(rep, members)
		}
		deduped = append(deduped, rep)
	}
	return deduped
}

// findingClusterKey builds the normalised signature used to bucket
// near-duplicate findings. We deliberately key on the *host* (not the
// full URL) of AffectedURL so a single class of bug repeated across many
// endpoints on the same target collapses into one entry.
func findingClusterKey(f model.Finding) string {
	cat := strings.ToLower(strings.TrimSpace(f.Category))
	id := strings.ToLower(strings.TrimSpace(f.ID))
	cwe := strings.ToLower(strings.TrimSpace(f.CWE))
	param := strings.ToLower(strings.TrimSpace(f.AffectedParameter))
	host := ""
	if u, err := url.Parse(f.AffectedURL); err == nil && u.Host != "" {
		host = strings.ToLower(u.Host)
	}
	if id == "" && cwe == "" && param == "" && host == "" {
		// Fall back to the legacy key so findings without structured
		// metadata still get a chance to dedupe.
		return cat + ":" + strings.ToLower(strings.TrimSpace(f.Title))
	}
	return strings.Join([]string{cat, id, cwe, param, host}, "|")
}

// pickClusterRepresentative returns the highest-severity (then highest-
// confidence) member of the cluster. The first member is returned when
// the cluster has only one entry.
func pickClusterRepresentative(members []model.Finding) model.Finding {
	if len(members) == 0 {
		return model.Finding{}
	}
	best := members[0]
	for _, m := range members[1:] {
		if severityScore(m.Severity) > severityScore(best.Severity) {
			best = m
			continue
		}
		if severityScore(m.Severity) == severityScore(best.Severity) && m.Confidence > best.Confidence {
			best = m
		}
	}
	return best
}

// annotateWithCluster appends an "+N more" notice and a small sample of
// affected URLs to the representative finding. This preserves the dedupe
// signal without losing visibility into the breadth of the issue.
func annotateWithCluster(rep model.Finding, members []model.Finding) model.Finding {
	others := 0
	urls := make([]string, 0, len(members))
	seenURL := map[string]struct{}{}
	if rep.AffectedURL != "" {
		seenURL[rep.AffectedURL] = struct{}{}
		urls = append(urls, rep.AffectedURL)
	}
	for _, m := range members {
		if m.AffectedURL == "" || m.AffectedURL == rep.AffectedURL {
			continue
		}
		if _, ok := seenURL[m.AffectedURL]; ok {
			continue
		}
		seenURL[m.AffectedURL] = struct{}{}
		urls = append(urls, m.AffectedURL)
		others++
	}
	if others == 0 {
		return rep
	}
	if rep.EvidenceFields == nil {
		rep.EvidenceFields = map[string]string{}
	}
	rep.EvidenceFields["affectedCount"] = fmt.Sprintf("%d", len(urls))
	sample := urls
	if len(sample) > 6 {
		sample = sample[:6]
	}
	rep.EvidenceFields["clusteredUrls"] = strings.Join(sample, ", ")
	rep.Evidence = strings.TrimSpace(rep.Evidence)
	if rep.Evidence != "" {
		rep.Evidence += "\n\n"
	}
	rep.Evidence += fmt.Sprintf("Cluster: %d affected endpoints (sample: %s)", len(urls), strings.Join(sample, ", "))
	return rep
}

func scoreAndRankFindings(findings []model.Finding) []model.Finding {
	type scored struct {
		finding model.Finding
		score   int
	}

	scoredList := make([]scored, 0, len(findings))
	for _, f := range findings {
		score := severityScore(f.Severity) * 1000
		score += categoryScore(f.Category) * 100
		score += int(maxFloat(0, minFloat(0.99, f.Confidence)) * 100)
		score += evidenceTierScore(f.EvidenceQualityTier) * 15
		scoredList = append(scoredList, scored{finding: f, score: score})
	}

	sort.SliceStable(scoredList, func(i, j int) bool {
		return scoredList[i].score > scoredList[j].score
	})

	ranked := make([]model.Finding, 0, len(scoredList))
	for _, s := range scoredList {
		ranked = append(ranked, s.finding)
	}

	return ranked
}

func severityScore(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

func categoryScore(cat string) int {
	cat = strings.ToLower(strings.TrimSpace(cat))
	scores := map[string]int{
		"security":       10,
		"authentication": 9,
		"authorization":  9,
		"injection":      8,
		"xss":            7,
		"csrf":           7,
		"encryption":     8,
		"tls":            6,
		"headers":        5,
		"cookies":        5,
		"discovery":      2,
		"reconnaissance": 1,
	}
	if score, ok := scores[cat]; ok {
		return score
	}
	return 3
}

func countBySeverity(findings []model.Finding, severity model.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}

func evidenceTierScore(tier string) int {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "strong":
		return 3
	case "moderate":
		return 2
	case "weak":
		return 1
	default:
		return 0
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
