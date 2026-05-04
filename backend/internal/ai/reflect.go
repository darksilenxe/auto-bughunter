package ai

import (
	"context"
	"encoding/json"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// ReflectionResult is the structured output of a single pentest-loop reflection
// step. The AI (or local reasoner) analyses what has been tried so far and
// proposes concrete adjustments for the next iteration.
type ReflectionResult struct {
	// GapAnalysis is a human-readable sentence describing what vulnerability
	// classes, endpoints, or parameter patterns have NOT been adequately tested.
	GapAnalysis string `json:"gapAnalysis"`

	// FocusAreas lists the top-priority vulnerability categories to target in
	// the next round (e.g. "idor", "ssti", "business_logic").
	FocusAreas []string `json:"focusAreas"`

	// RefinedHints are ready-to-use hypothesis refinements derived from
	// partially-confirmed signals or known evasion patterns.
	RefinedHints []RefinedHint `json:"refinedHints"`

	// ShouldEscalate is true when the reflection recommends escalating to
	// more aggressive or authenticated probing (e.g. WAF bypass, session-aware).
	ShouldEscalate bool `json:"shouldEscalate"`

	// EscalationReason explains why escalation is recommended.
	EscalationReason string `json:"escalationReason,omitempty"`

	// SkipCategories lists vulnerability categories that are fully confirmed or
	// have been exhausted; the next round should avoid spending budget on them.
	SkipCategories []string `json:"skipCategories"`
}

// RefinedHint is a concrete, scanner-executable probe suggestion derived from
// the reflection step. It mirrors VulnerabilityHypothesis but emphasises the
// corrective/refined nature of the payload (e.g. WAF-evading variant).
type RefinedHint struct {
	// Category is the vulnerability class (matches RunHypothesisVerification).
	Category string `json:"category"`
	// Endpoint is the target URL for this refined probe.
	Endpoint string `json:"endpoint"`
	// ParamName is the HTTP parameter to inject into.
	ParamName string `json:"paramName,omitempty"`
	// PayloadHint is the corrected or evasion-variant payload.
	PayloadHint string `json:"payloadHint"`
	// Rationale explains why this payload variant is expected to succeed where
	// the previous attempt failed.
	Rationale string `json:"rationale"`
}

// Reflect asks the configured AI provider to analyse one completed pentest
// iteration and produce actionable guidance for the next round. It receives:
//   - target: the base URL being tested
//   - round: the 1-based round number just completed
//   - findings: all findings confirmed so far across all rounds
//   - triedHypotheses: the hypotheses that were executed in the round just finished
//   - coverageMap: per-category list of endpoints already tested (from CoverageTracker)
//
// Falls back to a rule-based local reasoner when no AI provider is configured.
func (c *Client) Reflect(
	ctx context.Context,
	target string,
	round int,
	findings []model.Finding,
	triedHypotheses []VulnerabilityHypothesis,
	coverageMap map[string][]string,
) ReflectionResult {
	if c == nil || !c.shouldCallProvider() {
		return localReasonerReflect(target, round, findings, triedHypotheses, coverageMap)
	}

	// Build a compact view of tried hypotheses for the prompt.
	tried := make([]map[string]string, 0, len(triedHypotheses))
	for _, h := range triedHypotheses {
		tried = append(tried, map[string]string{
			"category":    h.Category,
			"endpoint":    h.Endpoint,
			"paramName":   h.ParamName,
			"payloadHint": h.PayloadHint,
		})
	}

	// Build a compact finding summary.
	confirmedCats := map[string]struct{}{}
	findingSummary := make([]map[string]string, 0, len(findings))
	for _, f := range findings {
		confirmedCats[strings.ToLower(f.Category)] = struct{}{}
		findingSummary = append(findingSummary, map[string]string{
			"category": f.Category,
			"severity": string(f.Severity),
			"title":    f.Title,
			"url":      f.AffectedURL,
		})
	}

	payload := map[string]any{
		"target":          target,
		"round":           round,
		"findings":        findingSummary,
		"triedHypotheses": tried,
		"coverageMap":     coverageMap,
		"instructions": "You are an expert penetration tester reflecting on a completed scan iteration. " +
			"Analyse what vulnerability classes, endpoints, and parameters have been tested and which have NOT. " +
			"Identify gaps in coverage, note any partially-confirmed signals that warrant refinement, and " +
			"recommend up to 3 corrective or evasion-variant payloads as refinedHints. " +
			"List focusAreas (up to 4 category names) that the next round should target. " +
			"Set shouldEscalate to true if the findings suggest deeper (authenticated, WAF-bypass) probing is needed. " +
			"List skipCategories that are fully confirmed or exhausted. " +
			"Reply with strict JSON only: " +
			`{"gapAnalysis":string,"focusAreas":[string],"refinedHints":[{"category":string,"endpoint":string,"paramName":string,"payloadHint":string,"rationale":string}],"shouldEscalate":bool,"escalationReason":string,"skipCategories":[string]}`,
	}

	userJSON, err := json.Marshal(payload)
	if err != nil {
		return localReasonerReflect(target, round, findings, triedHypotheses, coverageMap)
	}

	messages := []Message{
		{Role: "system", Content: "You are an expert penetration tester. Reflect on the completed scan iteration and provide actionable guidance. Reply with strict JSON."},
		{Role: "user", Content: string(userJSON)},
	}

	content, err := c.planningComplete(ctx, messages, 0.3, true)
	if err != nil || content == "" {
		return localReasonerReflect(target, round, findings, triedHypotheses, coverageMap)
	}

	var result ReflectionResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return localReasonerReflect(target, round, findings, triedHypotheses, coverageMap)
	}
	return result
}

// allCategories is the canonical set of vulnerability categories the system
// can probe, used by the local reasoner to compute coverage gaps.
var allCategories = []string{
	"xss", "sqli", "open_redirect", "cors", "ssrf",
	"auth_bypass", "idor", "ssti", "business_logic",
}

// localReasonerReflect is the rule-based fallback reflection used when no AI
// provider is configured. It computes coverage gaps deterministically.
func localReasonerReflect(
	_ string,
	round int,
	findings []model.Finding,
	triedHypotheses []VulnerabilityHypothesis,
	coverageMap map[string][]string,
) ReflectionResult {
	// Determine which categories have been confirmed in findings.
	confirmed := map[string]bool{}
	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if cat != "" {
			confirmed[cat] = true
		}
	}

	// Determine which categories have been tried.
	tried := map[string]bool{}
	triedEndpoints := map[string][]string{}
	for _, h := range triedHypotheses {
		cat := strings.ToLower(strings.TrimSpace(h.Category))
		tried[cat] = true
		ep := strings.TrimSpace(h.Endpoint)
		if ep != "" {
			triedEndpoints[cat] = append(triedEndpoints[cat], ep)
		}
	}
	// Also mark categories appearing in the coverage map as tried.
	for cat, eps := range coverageMap {
		if len(eps) > 0 {
			tried[strings.ToLower(cat)] = true
		}
	}

	// Gap analysis: find categories that haven't been tried yet.
	gaps := make([]string, 0, len(allCategories))
	for _, cat := range allCategories {
		if !tried[cat] {
			gaps = append(gaps, cat)
		}
	}

	gapAnalysis := "No coverage gaps detected."
	if len(gaps) > 0 {
		gapAnalysis = "Untested vulnerability categories after round " + itoa(round) + ": " + strings.Join(gaps, ", ") + "."
	}

	// Focus areas: prioritise gaps, then unconfirmed tried categories.
	focusAreas := make([]string, 0, 4)
	for _, cat := range gaps {
		focusAreas = append(focusAreas, cat)
		if len(focusAreas) >= 4 {
			break
		}
	}
	if len(focusAreas) < 4 {
		for _, cat := range allCategories {
			if tried[cat] && !confirmed[cat] {
				focusAreas = appendUniqueString(focusAreas, cat)
			}
			if len(focusAreas) >= 4 {
				break
			}
		}
	}

	// Refined hints: propose evasion/alternative payloads for tried-but-unconfirmed.
	var refinedHints []RefinedHint
	for _, h := range triedHypotheses {
		cat := strings.ToLower(strings.TrimSpace(h.Category))
		if confirmed[cat] {
			continue // already confirmed; no need to refine
		}
		ep := strings.TrimSpace(h.Endpoint)
		if ep == "" {
			continue
		}
		// Propose one alternative payload per unconfirmed tried category (up to 3).
		if len(refinedHints) >= 3 {
			break
		}
		alt := alternativePayload(cat, h.PayloadHint)
		if alt == "" || alt == h.PayloadHint {
			continue
		}
		refinedHints = append(refinedHints, RefinedHint{
			Category:    h.Category,
			Endpoint:    ep,
			ParamName:   h.ParamName,
			PayloadHint: alt,
			Rationale:   "Previous payload may have been filtered; trying an evasion-variant for " + h.Category + ".",
		})
	}

	// Skip categories: those already confirmed at high confidence.
	skipCats := make([]string, 0)
	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if f.Confidence >= 0.88 && cat != "" {
			skipCats = appendUniqueString(skipCats, cat)
		}
	}

	// Escalation: suggest if round >= 2 and no new findings in this round.
	shouldEscalate := round >= 2 && len(findings) == 0
	escalationReason := ""
	if shouldEscalate {
		escalationReason = "No findings after " + itoa(round) + " rounds; escalate to authenticated or WAF-bypass probing."
	}

	return ReflectionResult{
		GapAnalysis:      gapAnalysis,
		FocusAreas:       focusAreas,
		RefinedHints:     refinedHints,
		ShouldEscalate:   shouldEscalate,
		EscalationReason: escalationReason,
		SkipCategories:   skipCats,
	}
}

// alternativePayload returns a WAF-evasion or structural variant of payload for
// the given category. Returns empty string when no alternative is known.
func alternativePayload(category, previous string) string {
	_ = previous
	switch category {
	case "xss":
		return `"><img src=x onerror=alert(1)>`
	case "sqli":
		return `1 AND SLEEP(5)--`
	case "ssti":
		return `{{7*'7'}}`
	case "open_redirect":
		return `//evil.example.com/%0d%0a`
	case "cors":
		return `Origin: https://evil.example.com`
	case "ssrf":
		return `http://169.254.169.254/latest/meta-data/`
	case "idor":
		return `0`
	case "auth_bypass":
		return `' OR 1=1--`
	default:
		return ""
	}
}

// appendUniqueString appends s to ss only if not already present.
func appendUniqueString(ss []string, s string) []string {
	for _, existing := range ss {
		if existing == s {
			return ss
		}
	}
	return append(ss, s)
}

// itoa converts an int to its decimal string representation without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
