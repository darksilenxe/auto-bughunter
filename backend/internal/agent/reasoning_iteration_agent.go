package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

const (
	defaultReasoningRounds      = 4
	maxRefinedHintsPerRound     = 3
	coverageExhaustedThreshold  = 6 // stop when this many categories confirmed
)

// allProbeCategories is the full set of vulnerability categories the
// ReasoningIterationAgent cycles through. It is the union of everything
// RunHypothesisVerification can verify plus categories the AI can propose.
var allProbeCategories = []string{
	"xss", "sqli", "open_redirect", "cors", "ssrf",
	"auth_bypass", "idor", "ssti", "business_logic",
}

// ReasoningIterationAgent drives an adaptive, self-correcting pentest loop:
//
//  1. Generate hypotheses (AI or local) seeded by focus areas from the last
//     reflection and uncovered categories from the coverage tracker.
//  2. Verify each hypothesis with the deterministic scanner oracle.
//  3. Reflect: call ai.Client.Reflect to analyse what was tried vs confirmed,
//     identify gaps, and produce refined payload hints and focus areas.
//  4. Emit a ScanEventReasoningLoop event so the frontend can show the
//     live reasoning process round-by-round.
//  5. Seed the next round with the reflection output, then go to 1.
//
// Unlike PentestLoopAgent, this agent does NOT exit early when a round
// produces no findings — instead it uses the reflection output to pivot to
// different categories, payloads, or endpoints. It only stops when:
//   - All configured rounds are complete, or
//   - The coverage tracker shows all categories confirmed, or
//   - The context is cancelled.
type ReasoningIterationAgent struct {
	aiClient    *ai.Client
	scanService *scanner.Service
	MaxRounds   int
	enabled     bool
}

// NewReasoningIterationAgent constructs a ReasoningIterationAgent.
// maxRounds ≤ 0 defaults to defaultReasoningRounds.
func NewReasoningIterationAgent(aiClient *ai.Client, scanService *scanner.Service, maxRounds int, enabled bool) *ReasoningIterationAgent {
	if maxRounds <= 0 {
		maxRounds = defaultReasoningRounds
	}
	return &ReasoningIterationAgent{
		aiClient:    aiClient,
		scanService: scanService,
		MaxRounds:   maxRounds,
		enabled:     enabled,
	}
}

func (a *ReasoningIterationAgent) Name() string  { return "reasoning_iteration" }
func (a *ReasoningIterationAgent) Enabled() bool { return a.enabled }

// Run executes the full adaptive reasoning loop and returns all verified
// findings plus any chain findings identified across all rounds.
func (a *ReasoningIterationAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if a.aiClient == nil || a.scanService == nil {
		output.DebugNotes = "ReasoningIterationAgent: skipped — aiClient or scanService not configured"
		return output, nil
	}

	coverage := NewCoverageTracker()
	accumulated := append([]model.Finding(nil), input.AllFindings...)
	endpoints := append([]string{input.Target}, input.Options.SeedRuntimeEndpoints...)

	// Tracking totals for metadata.
	totalHypotheses := 0
	totalVerified := 0
	totalChains := 0
	novelRounds := 0

	// Reflection state carried between rounds.
	var lastReflection *ai.ReflectionResult
	var lastTriedHypotheses []ai.VulnerabilityHypothesis

	for round := 1; round <= a.MaxRounds; round++ {
		select {
		case <-ctx.Done():
			a.setMetadata(&output, round-1, novelRounds, totalHypotheses, totalVerified, totalChains)
			return output, ctx.Err()
		default:
		}

		// ── Step 1: build a focused hypothesis request ───────────────────
		// Derive focus areas and extra endpoints from the previous reflection.
		focusCategories := uncoveredFirst(allProbeCategories, lastReflection, coverage)
		skipCategories := map[string]bool{}
		if lastReflection != nil {
			for _, cat := range lastReflection.SkipCategories {
				skipCategories[strings.ToLower(strings.TrimSpace(cat))] = true
			}
		}

		// Promote reflection-suggested endpoints into the endpoint list.
		if lastReflection != nil {
			for _, hint := range lastReflection.RefinedHints {
				ep := strings.TrimSpace(hint.Endpoint)
				if ep != "" {
					endpoints = appendUnique(endpoints, ep)
				}
			}
		}

		// ── Step 2: generate hypotheses ──────────────────────────────────
		// Convert refined hints from the previous reflection into hypotheses
		// so they take precedence over generic AI-generated ones.
		hypotheses := hintsToHypotheses(lastReflection, maxRefinedHintsPerRound)
		if len(hypotheses) < 5 {
			// Pad with AI (or local) hypotheses directed at uncovered categories.
			aiHyps := a.aiClient.Hypothesize(ctx, input.Target, accumulated, endpoints)
			for _, h := range aiHyps {
				cat := strings.ToLower(strings.TrimSpace(h.Category))
				if skipCategories[cat] {
					continue
				}
				hypotheses = append(hypotheses, h)
				if len(hypotheses) >= 5 {
					break
				}
			}
		}

		// If there's nothing left to test, emit a reflection and break.
		if len(hypotheses) == 0 {
			Emit(input.Emit, model.ScanEvent{
				Type:      model.ScanEventReasoningLoop,
				AgentName: a.Name(),
				Message:   fmt.Sprintf("[reasoning r%d] No further testable hypotheses — surface exhausted.", round),
				Metadata: map[string]string{
					"round":  itoa(round),
					"status": "exhausted",
				},
			})
			break
		}
		totalHypotheses += len(hypotheses)
		lastTriedHypotheses = hypotheses

		// Emit round-start event so the frontend shows which categories are
		// being targeted this round.
		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventReasoningLoop,
			AgentName: a.Name(),
			Message:   fmt.Sprintf("[reasoning r%d] Testing %d hypotheses — focus: %s", round, len(hypotheses), strings.Join(focusCategories, ", ")),
			Metadata: map[string]string{
				"round":        itoa(round),
				"status":       "probing",
				"hypotheses":   itoa(len(hypotheses)),
				"focusAreas":   strings.Join(focusCategories, ","),
				"totalTried":   itoa(coverage.TotalTried()),
				"totalConfirmed": itoa(coverage.TotalConfirmed()),
			},
		})

		// ── Step 3: verify hypotheses ─────────────────────────────────────
		roundFindings := make([]model.Finding, 0, len(hypotheses))
		for i, h := range hypotheses {
			endpoint := strings.TrimSpace(h.Endpoint)
			if endpoint == "" {
				continue
			}

			coverage.RecordTried(h.Category, endpoint, h.ParamName, h.PayloadHint)

			f := a.scanService.RunHypothesisVerification(
				ctx,
				endpoint,
				h.ParamName,
				h.PayloadHint,
				h.Category,
				input.AuthProfile,
				input.Options,
			)
			if f == nil {
				continue
			}

			coverage.RecordConfirmed(h.Category, endpoint, h.ParamName)

			f.ID = fmt.Sprintf("reasoning-r%d-h%d-%s", round, i+1, strings.ToLower(strings.TrimSpace(h.Category)))
			f.Sources = appendUnique(f.Sources, "reasoning-iteration-agent")
			if f.EvidenceFields == nil {
				f.EvidenceFields = map[string]string{}
			}
			f.EvidenceFields["reasoningRound"] = itoa(round)
			f.EvidenceFields["hypothesisRationale"] = h.Rationale
			roundFindings = append(roundFindings, *f)

			Emit(input.Emit, model.ScanEvent{
				Type:         model.ScanEventFinding,
				AgentName:    a.Name(),
				FindingTitle: f.Title,
				Severity:     string(f.Severity),
				Message:      fmt.Sprintf("[reasoning r%d] [%s] %s", round, f.Severity, f.Title),
			})
		}
		totalVerified += len(roundFindings)
		if len(roundFindings) > 0 {
			novelRounds++
		}

		// ── Step 4: exploit chain analysis ───────────────────────────────
		chainInput := append(accumulated, roundFindings...)
		chainFindings := scanner.RunExploitChain(chainInput, nil)
		for i := range chainFindings {
			chainFindings[i].ID = fmt.Sprintf("reasoning-chain-r%d-%d", round, i+1)
			chainFindings[i].Sources = appendUnique(chainFindings[i].Sources, "reasoning-iteration-agent")
		}
		totalChains += len(chainFindings)

		// Accumulate for the next round.
		accumulated = append(accumulated, roundFindings...)
		accumulated = append(accumulated, chainFindings...)
		output.Findings = append(output.Findings, roundFindings...)
		output.Findings = append(output.Findings, chainFindings...)

		// Register confirmed finding URLs as additional endpoint candidates.
		for _, f := range roundFindings {
			if u := strings.TrimSpace(f.AffectedURL); u != "" {
				endpoints = appendUnique(endpoints, u)
			}
		}

		// ── Step 5: reflect ───────────────────────────────────────────────
		coverageMap := coverage.CoverageSummary()
		reflection := a.aiClient.Reflect(
			ctx,
			input.Target,
			round,
			accumulated,
			lastTriedHypotheses,
			coverageMap,
		)
		lastReflection = &reflection

		// Emit reflection event — this is the core of the "reiterate" UX.
		// The IterationRationale is the AI's own explanation of why another
		// round is warranted, written in plain English using the app's AI model.
		refinedCount := len(reflection.RefinedHints)
		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventReasoningLoop,
			AgentName: a.Name(),
			Message: fmt.Sprintf(
				"[reasoning r%d reflection] %s",
				round,
				reflection.IterationRationale,
			),
			Metadata: map[string]string{
				"round":              itoa(round),
				"status":             "reflection",
				"iterationRationale": reflection.IterationRationale,
				"gapAnalysis":        reflection.GapAnalysis,
				"focusAreas":         strings.Join(reflection.FocusAreas, ","),
				"skipCategories":     strings.Join(reflection.SkipCategories, ","),
				"shouldEscalate":     boolStr(reflection.ShouldEscalate),
				"escalationReason":   reflection.EscalationReason,
				"refinedHints":       itoa(refinedCount),
				"totalTried":         itoa(coverage.TotalTried()),
				"totalConfirmed":     itoa(coverage.TotalConfirmed()),
				"roundFindings":      itoa(len(roundFindings)),
				"roundChains":        itoa(len(chainFindings)),
			},
		})

		// Early exit: all categories confirmed — no point continuing.
		if coverage.TotalConfirmed() >= coverageExhaustedThreshold {
			break
		}

		humanPacedSleep(ctx, input.Options)
	}

	a.setMetadata(&output, a.MaxRounds, novelRounds, totalHypotheses, totalVerified, totalChains)
	output.DebugNotes = fmt.Sprintf(
		"ReasoningIterationAgent: %d/%d novel rounds, %d hypotheses generated, %d scanner-verified, %d chains, %d/%d coverage confirmed.",
		novelRounds, a.MaxRounds, totalHypotheses, totalVerified, totalChains,
		coverage.TotalConfirmed(), coverage.TotalTried(),
	)
	return output, nil
}

// setMetadata writes summary counters into the agent output metadata map.
func (a *ReasoningIterationAgent) setMetadata(out *AgentOutput, rounds, novelRounds, hypotheses, verified, chains int) {
	out.Metadata["max_rounds"] = itoa(rounds)
	out.Metadata["novel_rounds"] = itoa(novelRounds)
	out.Metadata["hypotheses_total"] = itoa(hypotheses)
	out.Metadata["verified_total"] = itoa(verified)
	out.Metadata["chains_total"] = itoa(chains)
}

// uncoveredFirst returns a prioritised list of focus areas: uncovered categories
// first, then the focus areas from the last reflection, capped at 4 entries.
func uncoveredFirst(all []string, reflection *ai.ReflectionResult, coverage *CoverageTracker) []string {
	uncovered := coverage.UncoveredCategories(all)
	result := make([]string, 0, 4)
	result = append(result, uncovered...)
	if reflection != nil {
		for _, cat := range reflection.FocusAreas {
			cat = strings.ToLower(strings.TrimSpace(cat))
			if cat != "" {
				result = appendUniqueStr(result, cat)
			}
		}
	}
	if len(result) > 4 {
		result = result[:4]
	}
	if len(result) == 0 {
		// Default to the full category list when nothing specific is known.
		return append([]string(nil), all[:min4(len(all), 4)]...)
	}
	return result
}

func min4(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// hintsToHypotheses converts refined hints from a ReflectionResult into
// VulnerabilityHypothesis entries so they are tested in the next round.
func hintsToHypotheses(r *ai.ReflectionResult, maxHints int) []ai.VulnerabilityHypothesis {
	if r == nil || len(r.RefinedHints) == 0 {
		return nil
	}
	out := make([]ai.VulnerabilityHypothesis, 0, maxHints)
	for _, hint := range r.RefinedHints {
		ep := strings.TrimSpace(hint.Endpoint)
		if ep == "" {
			continue
		}
		out = append(out, ai.VulnerabilityHypothesis{
			ID:          "reflection-hint-" + strings.ToLower(strings.TrimSpace(hint.Category)),
			Endpoint:    ep,
			Method:      "GET",
			ParamName:   hint.ParamName,
			PayloadHint: hint.PayloadHint,
			Category:    hint.Category,
			Rationale:   hint.Rationale,
		})
		if len(out) >= maxHints {
			break
		}
	}
	return out
}

// appendUniqueStr appends s to ss only if it is not already present.
func appendUniqueStr(ss []string, s string) []string {
	for _, existing := range ss {
		if existing == s {
			return ss
		}
	}
	return append(ss, s)
}

// escalationSuffix returns a short suffix string when escalation is recommended.
func escalationSuffix(r ai.ReflectionResult) string {
	if !r.ShouldEscalate {
		return ""
	}
	if r.EscalationReason != "" {
		return " | ESCALATE: " + r.EscalationReason
	}
	return " | ESCALATE recommended"
}

// boolStr converts a bool to "true"/"false".
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
