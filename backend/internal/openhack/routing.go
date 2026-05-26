package openhack

import (
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// FindingHints is the lightweight input ExpertForFinding uses to pick the
// best-matching OpenHack expert prompt. It is decoupled from the full
// model.Finding so callers (and tests) can probe the matcher with arbitrary
// strings.
type FindingHints struct {
	Category  string
	Title     string
	Evidence  string
	CWE       string
	Severity  string
	Signals   []string // additional pre-extracted routing keywords
}

// HintsFromFinding maps a model.Finding into a FindingHints.
func HintsFromFinding(f model.Finding) FindingHints {
	return FindingHints{
		Category: f.Category,
		Title:    f.Title,
		Evidence: f.Evidence,
		CWE:      f.CWE,
		Severity: string(f.Severity),
	}
}

// ExpertForFinding picks the OpenHack expert with the strongest routing-signal
// overlap for the given finding hints. Returns nil only when the pack itself
// has no experts (which would indicate a packaging bug).
//
// Matching rules:
//
//  1. Exact CWE in the expert's standard refs scores 5.
//  2. Each routing-signal that appears as a whole word in
//     category+title+evidence+signals scores 2.
//  3. Each tag (e.g. owasp-a01-2025) hit scores 3.
//  4. A direct hit on the expert's `category` frontmatter scores 4.
//  5. Ties break by stable expert id order so the result is deterministic.
//
// The fallback when no expert scores above zero is the "insecure-design"
// expert because its scope explicitly covers root-cause families that don't
// fit any other bucket.
func (p *Pack) ExpertForFinding(h FindingHints) *Expert {
	if p == nil || len(p.experts) == 0 {
		return nil
	}
	corpus := strings.ToLower(strings.Join([]string{
		h.Category, h.Title, h.Evidence, h.CWE, strings.Join(h.Signals, " "),
	}, " "))
	cweToken := strings.ToUpper(strings.TrimSpace(h.CWE))
	categoryToken := normaliseCategoryToken(h.Category)

	type scored struct {
		expert *Expert
		score  int
	}
	scoredList := make([]scored, 0, len(p.experts))
	for _, exp := range p.experts {
		score := 0
		if cweToken != "" {
			for _, ref := range exp.StandardRefs {
				if strings.EqualFold(strings.TrimSpace(ref), cweToken) {
					score += 5
					break
				}
			}
		}
		if categoryToken != "" && normaliseCategoryToken(exp.Category) == categoryToken {
			score += 4
		}
		for _, tag := range exp.Tags {
			if tag == "" {
				continue
			}
			if strings.Contains(corpus, tag) {
				score += 3
			}
		}
		for _, sig := range exp.RoutingSignals {
			if sig == "" {
				continue
			}
			if containsWord(corpus, sig) {
				score += 2
			}
		}
		scoredList = append(scoredList, scored{expert: exp, score: score})
	}
	sort.SliceStable(scoredList, func(i, j int) bool {
		if scoredList[i].score != scoredList[j].score {
			return scoredList[i].score > scoredList[j].score
		}
		return scoredList[i].expert.ID < scoredList[j].expert.ID
	})
	best := scoredList[0]
	if best.score > 0 {
		return best.expert
	}
	if fallback := p.ExpertByID("insecure-design"); fallback != nil {
		return fallback
	}
	return p.experts[0]
}

func normaliseCategoryToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

// containsWord checks if needle appears as a whole token in haystack. This
// prevents the substring "sql" from matching "mysqli" in noisy evidence text.
// Routing signals containing non-word characters (e.g. "knex.raw") fall back
// to a plain substring match.
func containsWord(haystack, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}
	if !isSimpleWord(needle) {
		return strings.Contains(haystack, needle)
	}
	// Walk the haystack, considering word boundaries.
	idx := 0
	for {
		i := strings.Index(haystack[idx:], needle)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(needle)
		leftOK := start == 0 || !isWordByte(haystack[start-1])
		rightOK := end == len(haystack) || !isWordByte(haystack[end])
		if leftOK && rightOK {
			return true
		}
		idx = start + 1
		if idx >= len(haystack) {
			return false
		}
	}
}

func isSimpleWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isWordByte(s[i]) {
			return false
		}
	}
	return true
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}
