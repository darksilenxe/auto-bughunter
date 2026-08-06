package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/url"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// AgentSpec describes a single agent the planner has decided to run next.
// Reason is informational and is recorded into the agent's metadata so that
// downstream telemetry can explain why an agent was scheduled.
type AgentSpec struct {
	Name   string
	Reason string
}

// PlannerDecision is what a Planner returns at each orchestration round.
// When IsDone is true the orchestrator stops scheduling further agents.
type PlannerDecision struct {
	Agents []AgentSpec
	IsDone bool
	Notes  string
}

// Planner decides which agents should run next given the current findings
// and execution history.
type Planner interface {
	Plan(ctx context.Context, input AgentInput, history []AgentOutput) (PlannerDecision, error)
}

// StaticPlanner reproduces the historical "run every registered agent in order
// once" behavior. It is used when no AI provider is configured or when
// autonomous orchestration is disabled.
type StaticPlanner struct {
	Order []string
}

// NewStaticPlanner returns a StaticPlanner that walks the supplied agent names
// in order. Empty names are filtered out so callers can pass registry order
// directly.
func NewStaticPlanner(order []string) *StaticPlanner {
	cleaned := make([]string, 0, len(order))
	for _, name := range order {
		name = strings.TrimSpace(name)
		if name != "" {
			cleaned = append(cleaned, name)
		}
	}
	return &StaticPlanner{Order: cleaned}
}

// Plan returns the next not-yet-run agent and signals done when the static
// pipeline has been fully executed.
func (p *StaticPlanner) Plan(_ context.Context, _ AgentInput, history []AgentOutput) (PlannerDecision, error) {
	completed := map[string]struct{}{}
	for _, h := range history {
		if h.AgentName != "" {
			completed[h.AgentName] = struct{}{}
		}
	}
	for _, name := range p.Order {
		if _, done := completed[name]; done {
			continue
		}
		return PlannerDecision{
			Agents: []AgentSpec{{Name: name, Reason: "static-pipeline"}},
		}, nil
	}
	return PlannerDecision{IsDone: true, Notes: "static pipeline exhausted"}, nil
}

// AIPlanCaller is the minimal contract the AIPlanner needs from the AI client.
// It is satisfied by *ai.Client.Plan and is declared here to avoid an import
// cycle between the agent and ai packages.
type AIPlanCaller interface {
	Plan(ctx context.Context, target string, findings []any, history []map[string]string, availableAgents []string, goals []model.ImpactGoal, policyPack string) ([]map[string]string, bool, error)
}

// AIPlanner asks the configured AI provider what to run next, falling back to
// the supplied StaticPlanner when the provider is unavailable, returns an
// error, or yields no actionable agents.
type AIPlanner struct {
	Caller            AIPlanCaller
	AvailableAgents   []string
	Fallback          *StaticPlanner
	MaxAgentsPerRound int
	ExplorationBudget int
	// Spawner is an optional Q-learning spawn recommender (e.g. agentlearner.Client).
	// When set, Plan merges its recommendations into each round's scheduling
	// decision so that historically high-signal agent sequences learned from past
	// scans influence the AI planner's choices.
	Spawner Spawner
}

const (
	minRunsBeforeAdaptiveBlock  = 2
	minRunsForHighErrorBlock    = 3
	highErrorRateBlockThreshold = 0.66
)

// NewAIPlanner constructs an AIPlanner. availableAgents should list every
// agent name the factory can build; fallback is required.
func NewAIPlanner(caller AIPlanCaller, availableAgents []string, fallback *StaticPlanner) *AIPlanner {
	cleaned := make([]string, 0, len(availableAgents))
	for _, name := range availableAgents {
		name = strings.TrimSpace(name)
		if name != "" {
			cleaned = append(cleaned, name)
		}
	}
	if fallback == nil {
		fallback = NewStaticPlanner(cleaned)
	}
	return &AIPlanner{
		Caller:            caller,
		AvailableAgents:   cleaned,
		Fallback:          fallback,
		MaxAgentsPerRound: 3,
		ExplorationBudget: 15,
	}
}

// Plan asks the AI provider for the next batch of agents to run; on any error
// or empty response it delegates to the static fallback so the scan still
// completes deterministically.
func (p *AIPlanner) Plan(ctx context.Context, input AgentInput, history []AgentOutput) (PlannerDecision, error) {
	if p == nil || p.Caller == nil {
		if p != nil && p.Fallback != nil {
			return p.Fallback.Plan(ctx, input, history)
		}
		return PlannerDecision{IsDone: true}, nil
	}

	if shouldStopForLowMarginalValue(history, input.Options.AutonomyMinMarginalScore) {
		return PlannerDecision{
			IsDone: true,
			Notes:  "stopped: low marginal decision quality",
		}, nil
	}

	findings := make([]any, 0, len(input.AllFindings))
	for _, f := range input.AllFindings {
		entry := map[string]string{
			"id":          f.ID,
			"category":    f.Category,
			"severity":    string(f.Severity),
			"title":       f.Title,
			"bountyScore": formatBountyScore(f.BountyScore),
		}
		findings = append(findings, entry)
	}

	historySummary := make([]map[string]string, 0, len(history)+1)
	stats := computeAgentRunStats(history)
	for _, h := range history {
		historySummary = append(historySummary, map[string]string{
			"agent":      h.AgentName,
			"status":     h.Status,
			"findings":   itoa(len(h.Findings)),
			"errors":     itoa(stats[h.AgentName].Errors),
			"runs":       itoa(stats[h.AgentName].Runs),
			"novelty":    itoa(stats[h.AgentName].NovelFindings),
			"durationMs": itoa(int(h.DurationMs)),
		})
	}
	if input.SharedScanContext != nil {
		if summary := strings.TrimSpace(input.SharedScanContext.DiscoverySummary()); summary != "" {
			historySummary = append(historySummary, map[string]string{
				"agent":      "shared_scan_context",
				"status":     "context",
				"findings":   "0",
				"blackboard": summary,
			})
		}
	}
	if len(input.Options.OperatorHints) > 0 {
		historySummary = append(historySummary, map[string]string{
			"agent":          "operator",
			"status":         "instructions",
			"findings":       "0",
			"operatorHints":  strings.Join(input.Options.OperatorHints, "; "),
		})
	}

	// Apply policy tuning profile: inject the operator augmentation into the
	// policyPack string so buildPlannerSystemPrompt uses it as a raw fragment.
	activePolicyPack := input.Options.PolicyPack
	if tp := input.PolicyTuningProfile; tp != nil && strings.TrimSpace(tp.SystemPromptAugmentation) != "" {
		aug := strings.TrimSpace(tp.SystemPromptAugmentation)
		if activePolicyPack != "" {
			// Keep the existing pack fragment and append the operator augmentation.
			activePolicyPack = activePolicyPack + "\n\nOPERATOR TUNING (" + tp.PolicyPack + "): " + aug
		} else {
			activePolicyPack = "OPERATOR TUNING (" + tp.PolicyPack + "): " + aug
		}
	}

	specs, done, err := p.Caller.Plan(ctx, input.Target, findings, historySummary, p.AvailableAgents, input.Options.ImpactGoals, activePolicyPack)
	if err != nil {
		if p.Fallback != nil {
			return p.Fallback.Plan(ctx, input, history)
		}
		return PlannerDecision{IsDone: true, Notes: "ai planner error: " + err.Error()}, nil
	}

	available := map[string]struct{}{}
	for _, name := range p.AvailableAgents {
		available[name] = struct{}{}
	}
	blocked := buildBlockedAgents(stats, input.AutonomyMemory, input.AllFindings)
	preferredSet := toNameSet(input.AutonomyMemory.PreferredAgents)
	contextPreferredSet := contextPreferredAgents(input.Target, input.AllFindings, p.AvailableAgents, input.AutonomyMemory)

	agents := make([]AgentSpec, 0, len(specs))
	for _, s := range specs {
		name := strings.TrimSpace(s["name"])
		if name == "" {
			continue
		}
		if _, ok := available[name]; !ok {
			continue
		}
		if blocked[name] && !isUrgentReason(s["reason"]) {
			continue
		}
		reason := strings.TrimSpace(s["reason"])
		if reason == "" {
			switch {
			case preferredSet[name]:
				reason = "memory-preferred"
			case contextPreferredSet[name]:
				reason = "target-context"
			default:
				reason = "ai-planned"
			}
		}
		agents = append(agents, AgentSpec{Name: name, Reason: reason})
		if p.MaxAgentsPerRound > 0 && len(agents) >= p.MaxAgentsPerRound {
			break
		}
	}
	agents = prioritizeAgentSpecs(agents, preferredSet, contextPreferredSet)
	if p.MaxAgentsPerRound > 0 && len(agents) > p.MaxAgentsPerRound {
		agents = agents[:p.MaxAgentsPerRound]
	}

	// Augment with Q-learner spawn recommendations. When a Spawner is wired
	// (typically agentlearner.Client), ask it which agents it recommends
	// following the most recently completed agent. Its Q-table reflects what
	// sequences have historically produced high-signal findings, so merging
	// its suggestions here keeps the AI plan aligned with learned patterns.
	if p.Spawner != nil && len(history) > 0 {
		lastAgent := strings.TrimSpace(history[len(history)-1].AgentName)
		if lastAgent != "" {
			scheduledNames := make(map[string]bool, len(agents))
			for _, a := range agents {
				scheduledNames[a.Name] = true
			}
			recs := p.Spawner.Recommend(ctx, lastAgent, input.AllFindings, 3, 0.65)
			for _, rec := range recs {
				rec = strings.TrimSpace(rec)
				if rec == "" {
					continue
				}
				if _, ok := available[rec]; !ok {
					continue
				}
				if blocked[rec] {
					continue
				}
				if scheduledNames[rec] {
					continue
				}
				agents = append(agents, AgentSpec{Name: rec, Reason: "q-learning"})
				scheduledNames[rec] = true
			}
		}
	}

	if shouldInjectExploration(history, p.ExplorationBudget) {
		exploration := pickExplorationAgent(p.AvailableAgents, history, agents, blocked, preferredSet)
		if exploration != "" {
			agents = append(agents, AgentSpec{Name: exploration, Reason: "exploration-budget"})
		}
	}
	if p.MaxAgentsPerRound > 0 && len(agents) > p.MaxAgentsPerRound {
		agents = agents[:p.MaxAgentsPerRound]
	}

	if len(agents) == 0 && !done {
		if p.Fallback != nil {
			return p.Fallback.Plan(ctx, input, history)
		}
		return PlannerDecision{IsDone: true, Notes: "ai planner returned no actionable agents"}, nil
	}

	return PlannerDecision{Agents: agents, IsDone: done, Notes: "ai-planned"}, nil
}

type agentRunStats struct {
	Runs          int
	Errors        int
	Timeouts      int
	Findings      int
	NovelFindings int
}

func computeAgentRunStats(history []AgentOutput) map[string]agentRunStats {
	stats := map[string]agentRunStats{}
	type findingKey struct {
		Category string
		Title    string
		Evidence string
	}
	seen := map[findingKey]struct{}{}
	for _, h := range history {
		name := strings.TrimSpace(h.AgentName)
		if name == "" {
			continue
		}
		cur := stats[name]
		cur.Runs++
		if h.Status == "error" || strings.TrimSpace(h.Error) != "" {
			cur.Errors++
		}
		if h.TimedOut {
			cur.Timeouts++
		}
		cur.Findings += len(h.Findings)
		for _, f := range h.Findings {
			key := findingKey{Category: f.Category, Title: f.Title, Evidence: f.Evidence}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			cur.NovelFindings++
		}
		stats[name] = cur
	}
	return stats
}

func buildBlockedAgents(stats map[string]agentRunStats, memory model.AutonomyMemory, allFindings []model.Finding) map[string]bool {
	blocked := map[string]bool{}
	for _, name := range memory.SuppressedAgents {
		name = strings.TrimSpace(name)
		if name != "" {
			blocked[name] = true
		}
	}
	for name, st := range stats {
		if st.Runs < minRunsBeforeAdaptiveBlock {
			continue
		}
		errorRate := float64(st.Errors) / float64(st.Runs)
		if st.Findings == 0 && (st.Errors > 0 || st.Timeouts > 0) {
			blocked[name] = true
			continue
		}
		if shouldBlockForHighErrorRate(st, errorRate) {
			blocked[name] = true
		}
	}

	// Relax blocking when high-payout-potential findings are present and the
	// blocked agent is contextually relevant to exploiting them. This prevents
	// error-history suppression from hiding a critical follow-up path.
	if len(allFindings) > 0 {
		unblockForHighPayoutFindings(blocked, allFindings)
	}

	return blocked
}

// unblockForHighPayoutFindings removes agents from the blocked set when the
// current finding set contains at least one high-payout-potential finding
// (BountyScore >= 0.75 or Critical severity) and the agent is in the primary
// attack surface for that finding's goal.
func unblockForHighPayoutFindings(blocked map[string]bool, findings []model.Finding) {
	// Maps goal → agents that should be unblocked to pursue it.
	goalAgents := map[string][]string{
		"account_takeover":        {"auth_bypass", "pentest_loop", "adaptive_probe"},
		"auth_bypass":             {"auth_bypass", "pentest_loop"},
		"ssrf_internal_access":    {"ssrf", "pentest_loop"},
		"cross_tenant_access":     {"access_control", "pentest_loop"},
		"payment_abuse":           {"input_validation", "pentest_loop"},
		"sensitive_data_exposure": {"information_disclosure", "scanning"},
	}
	for _, f := range findings {
		isHighPayout := f.BountyScore >= 0.75 || f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh
		if !isHighPayout {
			continue
		}
		for _, goal := range f.ImpactGoals {
			for _, agentName := range goalAgents[string(goal)] {
				delete(blocked, agentName)
			}
		}
		// Also unblock by category signals even when goals are not yet populated.
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		switch {
		case strings.Contains(cat, "auth") || strings.Contains(cat, "access"):
			delete(blocked, "auth_bypass")
		case strings.Contains(cat, "ssrf"):
			delete(blocked, "ssrf")
		case strings.Contains(cat, "injection"):
			delete(blocked, "input_validation")
		}
	}
}

// shouldBlockForHighErrorRate suppresses an agent only when repeated runs show
// mostly failures and no novelty, which indicates the agent is currently
// expensive noise rather than a useful follow-up.
func shouldBlockForHighErrorRate(st agentRunStats, errorRate float64) bool {
	return st.Runs >= minRunsForHighErrorBlock &&
		errorRate >= highErrorRateBlockThreshold &&
		st.NovelFindings == 0
}

func isUrgentReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	return strings.Contains(reason, "critical") ||
		strings.Contains(reason, "high") ||
		strings.Contains(reason, "rce") ||
		strings.Contains(reason, "exploit") ||
		strings.Contains(reason, "auth")
}

// humanPacedSleep introduces a randomised 1–2 minute delay between agent
// tool/action calls when opts.HumanPaced is enabled, mimicking the natural
// pause a human pentester takes before issuing the next command. It returns
// early if the context is cancelled.
func humanPacedSleep(ctx context.Context, opts model.ScanOptions) {
	if !opts.HumanPaced {
		return
	}
	// 60 s base + up to 60 s of uniform jitter → 1–2 minute range.
	// crypto/rand is used so the timing pattern is not predictable.
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fall back to a fixed 90-second delay if entropy is unavailable.
		select {
		case <-ctx.Done():
		case <-time.After(90 * time.Second):
		}
		return
	}
	jitter := time.Duration(binary.LittleEndian.Uint32(buf[:])%60001) * time.Millisecond
	delay := 60*time.Second + jitter
	select {
	case <-ctx.Done():
	case <-time.After(delay):
	}
}

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

func toNameSet(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n != "" {
			out[n] = true
		}
	}
	return out
}

func contextPreferredAgents(target string, findings []model.Finding, available []string, memory model.AutonomyMemory) map[string]bool {
	preferred := map[string]bool{}
	host := strings.ToLower(strings.TrimSpace(target))
	if u, err := url.Parse(target); err == nil {
		host = strings.ToLower(strings.TrimSpace(u.Hostname()))
	}
	hasAPI := false
	hasAccessControlSignal := false
	hasInputValidationSignal := false
	hasInfoDisclosureSignal := false
	hasRedirectSignal := false
	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		switch cat {
		case "api-security", "api":
			hasAPI = true
		case "access-control", "idor", "authorization":
			hasAccessControlSignal = true
		case "injection", "input-validation", "xss", "sql-injection", "code-injection":
			hasInputValidationSignal = true
		case "information-disclosure", "misconfiguration", "secrets":
			hasInfoDisclosureSignal = true
		case "open-redirect", "cors":
			hasRedirectSignal = true
		}
	}
	for _, name := range available {
		lc := strings.ToLower(strings.TrimSpace(name))
		switch {
		case hasAPI && (strings.Contains(lc, "api") || strings.Contains(host, "api")):
			preferred[name] = true
		case hasAccessControlSignal && (strings.Contains(lc, "access") || strings.Contains(lc, "idor")):
			preferred[name] = true
		case hasInputValidationSignal && (strings.Contains(lc, "input") || strings.Contains(lc, "scan")):
			preferred[name] = true
		case hasInfoDisclosureSignal && (strings.Contains(lc, "information") || strings.Contains(lc, "analysis")):
			preferred[name] = true
		case hasRedirectSignal && (strings.Contains(lc, "cors") || strings.Contains(lc, "redirect")):
			preferred[name] = true
		}
	}

	// Promote agents with a strong payout track record for this target/program.
	// payoutWeightThreshold is the minimum accumulated payout-weighted score an
	// agent must have (across all historical findings attributed to it via
	// ReportFeedback.PayoutUSD) before it is promoted to the preferred set.
	// A value of 0.5 corresponds to roughly one medium-bounty payout attribution.
	const payoutWeightThreshold = 0.5
	if len(memory.AgentPayoutWeights) > 0 {
		for agentName, weight := range memory.AgentPayoutWeights {
			if weight >= payoutWeightThreshold {
				preferred[agentName] = true
			}
		}
	}

	// When a TargetROIProfile exists for this target, promote deep agents for
	// high-drift targets and high-payout categories; suppress deep agents for
	// stale low-ROI targets.
	// staleTargetThresholdDays is the number of days without a novel finding
	// after which a target is considered stale and assigned a lighter scan profile.
	const staleTargetThresholdDays = 30
	if roiProfile, ok := memory.TargetROISignals[host]; ok {
		isHighDrift := roiProfile.DriftScore >= 1.0
		isStale := !roiProfile.LastNovelFindingAt.IsZero() && roiProfile.LastNovelFindingAt.Before(time.Now().UTC().Add(-time.Duration(staleTargetThresholdDays)*24*time.Hour))

		if isHighDrift {
			for _, name := range available {
				lc := strings.ToLower(strings.TrimSpace(name))
				if strings.Contains(lc, "pentest") || strings.Contains(lc, "adaptive") || strings.Contains(lc, "reasoning") {
					preferred[name] = true
				}
			}
		}

		if isStale {
			// For stale targets, demote deep agents (remove from preferred)
			// so lighter surface agents run first.
			for _, name := range available {
				lc := strings.ToLower(strings.TrimSpace(name))
				if strings.Contains(lc, "pentest") || strings.Contains(lc, "adaptive") {
					delete(preferred, name)
				}
			}
		}

		// Promote agents covering high-payout categories seen on this target.
		catToAgent := map[string][]string{
			"access_control":         {"access_control", "auth_bypass"},
			"injection":              {"input_validation", "scanning"},
			"ssrf":                   {"ssrf"},
			"information_disclosure": {"information_disclosure", "analysis"},
		}
		for _, cat := range roiProfile.HighPayoutCategories {
			lcat := strings.ToLower(strings.TrimSpace(cat))
			if agents, ok := catToAgent[lcat]; ok {
				for _, a := range agents {
					preferred[a] = true
				}
			}
		}
	}

	return preferred
}

func prioritizeAgentSpecs(specs []AgentSpec, preferred map[string]bool, contextPreferred map[string]bool) []AgentSpec {
	if len(specs) <= 1 {
		return specs
	}
	out := make([]AgentSpec, 0, len(specs))
	bucket := make([][]AgentSpec, 4)
	for _, s := range specs {
		switch {
		case preferred[s.Name] && contextPreferred[s.Name]:
			bucket[0] = append(bucket[0], s)
		case preferred[s.Name]:
			bucket[1] = append(bucket[1], s)
		case contextPreferred[s.Name]:
			bucket[2] = append(bucket[2], s)
		default:
			bucket[3] = append(bucket[3], s)
		}
	}
	for _, b := range bucket {
		out = append(out, b...)
	}
	return out
}

func shouldInjectExploration(history []AgentOutput, budgetPercent int) bool {
	if budgetPercent <= 0 {
		return false
	}
	if budgetPercent > 100 {
		budgetPercent = 100
	}
	round := len(history) + 1
	interval := 100 / budgetPercent
	if interval <= 0 {
		interval = 1
	}
	return round%interval == 0
}

func pickExplorationAgent(available []string, history []AgentOutput, current []AgentSpec, blocked map[string]bool, preferred map[string]bool) string {
	seen := map[string]bool{}
	for _, h := range history {
		name := strings.TrimSpace(h.AgentName)
		if name != "" {
			seen[name] = true
		}
	}
	for _, s := range current {
		seen[strings.TrimSpace(s.Name)] = true
	}
	for _, name := range available {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || blocked[name] || preferred[name] {
			continue
		}
		return name
	}
	for _, name := range available {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || blocked[name] {
			continue
		}
		return name
	}
	return ""
}

func shouldStopForLowMarginalValue(history []AgentOutput, minMarginalScore float64) bool {
	if minMarginalScore <= 0 || len(history) < 2 {
		return false
	}
	checked := 0
	for i := len(history) - 1; i >= 0 && checked < 2; i-- {
		score := 0.0
		if history[i].Metadata != nil {
			if raw := strings.TrimSpace(history[i].Metadata["decision_quality_score"]); raw != "" {
				if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
					score = parsed
				}
			}
		}
		if score >= minMarginalScore {
			return false
		}
		checked++
	}
	return checked == 2
}

// formatBountyScore formats a BountyScore for inclusion in the AI planner
// finding context. Returns an empty string for zero scores to reduce token
// usage on findings that have not been bounty-enriched yet.
func formatBountyScore(score float64) string {
	if score <= 0 {
		return ""
	}
	return strconv.FormatFloat(score, 'f', 2, 64)
}
