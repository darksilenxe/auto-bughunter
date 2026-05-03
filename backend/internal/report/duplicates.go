package report

import (
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// DuplicateCandidate represents a prior finding that is similar enough to a
// query finding to be considered a likely duplicate. Score is in [0, 1] with
// 1.0 indicating an exact fingerprint match.
type DuplicateCandidate struct {
	ScanID      string         `json:"scanId,omitempty"`
	Target      string         `json:"target,omitempty"`
	FindingID   string         `json:"findingId"`
	Title       string         `json:"title,omitempty"`
	Severity    model.Severity `json:"severity,omitempty"`
	Score       float64        `json:"score"`
	MatchedOn   []string       `json:"matchedOn,omitempty"`
	ProgramName string         `json:"programName,omitempty"`
}

// DuplicateMatch groups all candidate prior findings that resemble a single
// query finding.
type DuplicateMatch struct {
	FindingID  string               `json:"findingId"`
	Title      string               `json:"title,omitempty"`
	Candidates []DuplicateCandidate `json:"candidates,omitempty"`
}

// PriorFinding is the minimal projection of a historical finding the
// duplicate detector needs. Callers translate database rows into this shape.
type PriorFinding struct {
	ScanID      string
	Target      string
	ProgramName string
	Finding     model.Finding
}

// DefaultDuplicateThreshold is the minimum similarity score reported by
// FindDuplicates when the caller does not override the threshold. Tuned to
// surface obvious recurrences (same category + same affected URL/parameter
// or same title) without flooding triagers with weak matches.
const DefaultDuplicateThreshold = 0.6

// FindDuplicates compares each finding in `current` against each prior
// finding and returns the per-finding list of candidates that scored at or
// above `threshold` (capped at 5 candidates per finding, highest score
// first). Threshold values <= 0 fall back to DefaultDuplicateThreshold and
// values > 1 are clamped to 1.
//
// Similarity is computed deterministically from category, normalized title
// (token Jaccard), CWE, affected URL host+path, and affected parameter so
// that the same inputs always produce the same scores. This avoids any
// dependency on an external embedding service while still catching the most
// common duplicate-bug-bounty-submission patterns: same vulnerability class
// recurring on the same endpoint after a partial fix.
func FindDuplicates(current []model.Finding, prior []PriorFinding, threshold float64) []DuplicateMatch {
	if threshold <= 0 {
		threshold = DefaultDuplicateThreshold
	}
	if threshold > 1 {
		threshold = 1
	}
	out := make([]DuplicateMatch, 0, len(current))
	for _, f := range current {
		matches := DuplicateMatch{FindingID: f.ID, Title: f.Title}
		for _, p := range prior {
			if p.Finding.ID == f.ID && p.ScanID == "" {
				continue
			}
			score, matched := similarityScore(f, p.Finding)
			if score < threshold {
				continue
			}
			matches.Candidates = append(matches.Candidates, DuplicateCandidate{
				ScanID:      p.ScanID,
				Target:      p.Target,
				FindingID:   p.Finding.ID,
				Title:       p.Finding.Title,
				Severity:    p.Finding.Severity,
				Score:       round2DupScore(score),
				MatchedOn:   matched,
				ProgramName: p.ProgramName,
			})
		}
		sort.SliceStable(matches.Candidates, func(i, j int) bool {
			if matches.Candidates[i].Score != matches.Candidates[j].Score {
				return matches.Candidates[i].Score > matches.Candidates[j].Score
			}
			return matches.Candidates[i].FindingID < matches.Candidates[j].FindingID
		})
		if len(matches.Candidates) > 5 {
			matches.Candidates = matches.Candidates[:5]
		}
		if len(matches.Candidates) > 0 {
			out = append(out, matches)
		}
	}
	return out
}

func similarityScore(a, b model.Finding) (float64, []string) {
	matched := []string{}
	score := 0.0
	if normCat(a.Category) != "" && normCat(a.Category) == normCat(b.Category) {
		score += 0.35
		matched = append(matched, "category")
	}
	if normCWE(a.CWE) != "" && normCWE(a.CWE) == normCWE(b.CWE) {
		score += 0.20
		matched = append(matched, "cwe")
	}
	titleSim := jaccard(tokenize(a.Title), tokenize(b.Title))
	if titleSim > 0.5 {
		score += 0.20 * titleSim
		matched = append(matched, "title")
	}
	if hostPath(a.AffectedURL) != "" && hostPath(a.AffectedURL) == hostPath(b.AffectedURL) {
		score += 0.20
		matched = append(matched, "url")
	}
	if normParam(a.AffectedParameter) != "" && normParam(a.AffectedParameter) == normParam(b.AffectedParameter) {
		score += 0.10
		matched = append(matched, "parameter")
	}
	if score > 1 {
		score = 1
	}
	return score, matched
}

func normCat(s string) string  { return strings.ToLower(strings.TrimSpace(s)) }
func normCWE(s string) string  { return strings.ToUpper(strings.TrimSpace(s)) }
func normParam(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func hostPath(rawURL string) string {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return ""
	}
	// Strip scheme.
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	// Strip query/fragment.
	for _, sep := range []string{"?", "#"} {
		if idx := strings.Index(u, sep); idx >= 0 {
			u = u[:idx]
		}
	}
	return strings.ToLower(strings.TrimRight(u, "/"))
}

func tokenize(s string) map[string]struct{} {
	out := map[string]struct{}{}
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		t := strings.ToLower(cur.String())
		cur.Reset()
		if len(t) <= 2 {
			return
		}
		if _, skip := stopWords[t]; skip {
			return
		}
		out[t] = struct{}{}
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	intersect := 0
	for t := range a {
		if _, ok := b[t]; ok {
			intersect++
		}
	}
	union := len(a) + len(b) - intersect
	if union == 0 {
		return 0
	}
	return float64(intersect) / float64(union)
}

func round2DupScore(v float64) float64 {
	return float64(int(v*100+0.5)) / 100.0
}

var stopWords = map[string]struct{}{
	"the": {}, "and": {}, "for": {}, "with": {}, "from": {}, "via": {},
	"into": {}, "found": {}, "detected": {}, "vulnerability": {},
}
