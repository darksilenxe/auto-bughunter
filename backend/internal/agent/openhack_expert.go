package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/openhack"
)

// OpenHackExpertAgent wires the OpenHack expert prompt pack into the AI
// client. For each existing finding the agent picks the best-matching
// OpenHack expert (injection, broken-access-control, …), invokes the LLM
// with the expert's system prompt, and enriches the finding with the parsed
// assessment (rationale, recommended severity, proof obligations, follow-up
// probes).
//
// When no AI client is configured, the agent performs a deterministic local
// fallback that still attaches the expert id and the OpenHack quality-gate
// reminder so downstream agents and the operator get a consistent baseline.
// This keeps the agent useful when running against a local model with no
// outbound network access — the OpenHack prompts ship inside the binary.
//
// The agent does not create new findings; it annotates existing ones in
// place by adding entries to the finding's EvidenceFields map. Downstream
// agents (notably openhack_triage and the ML triage) can read these fields
// to decide promotion, suppression, or follow-up probing.
type OpenHackExpertAgent struct {
	aiClient *ai.Client
	pack     *openhack.Pack
	enabled  bool
}

// NewOpenHackExpertAgent constructs the agent. Both aiClient and pack may be
// nil; nil pack causes the agent to load the embedded default pack lazily.
func NewOpenHackExpertAgent(aiClient *ai.Client, pack *openhack.Pack, enabled bool) *OpenHackExpertAgent {
	if pack == nil {
		pack, _ = openhack.LoadDefault()
	}
	return &OpenHackExpertAgent{aiClient: aiClient, pack: pack, enabled: enabled}
}

func (a *OpenHackExpertAgent) Name() string  { return "openhack_expert" }
func (a *OpenHackExpertAgent) Enabled() bool { return a.enabled }

// maxOpenHackExpertCalls caps how many findings the agent will send to the
// LLM in a single run. This protects scans against runaway token spend on
// large finding sets; the agent skips remaining findings with an explicit
// debug note rather than silently truncating.
const maxOpenHackExpertCalls = 20

func (a *OpenHackExpertAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
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
		output.DebugNotes = "OpenHackExpertAgent: no findings to review"
		output.Metadata["findings_count"] = "0"
		return output, nil
	}
	if a.pack == nil {
		output.Status = "skipped"
		output.DebugNotes = "OpenHackExpertAgent: prompt pack failed to load"
		output.Metadata["findings_count"] = "0"
		return output, nil
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   fmt.Sprintf("OpenHack expert review starting on %d finding(s)", len(allFindings)),
	})

	expertHits := map[string]int{}
	llmCalls, fallbackCalls := 0, 0

	for i, f := range allFindings {
		select {
		case <-ctx.Done():
			output.Status = "partial"
			goto done
		default:
		}
		expert := a.pack.ExpertForFinding(openhack.HintsFromFinding(f))
		if expert == nil {
			continue
		}
		expertHits[expert.ID]++

		enriched := f
		if enriched.EvidenceFields == nil {
			enriched.EvidenceFields = map[string]string{}
		}
		enriched.EvidenceFields["openhackExpert"] = expert.ID
		enriched.EvidenceFields["openhackExpertTitle"] = expert.Title

		if a.aiClient != nil && llmCalls < maxOpenHackExpertCalls {
			sysPrompt := a.pack.SystemPromptFor(expert.ID)
			assessment := a.aiClient.RunOpenHackExpert(ctx, sysPrompt, expert.ID, f)
			if assessment.Decision != "" {
				llmCalls++
				applyExpertAssessment(&enriched, assessment)
				Emit(input.Emit, model.ScanEvent{
					Type:      model.ScanEventInfo,
					AgentName: a.Name(),
					Message: fmt.Sprintf("OpenHack expert %q assessed %q → %s (sev=%s, conf=%.2f)",
						expert.ID, truncate(f.Title, 60), assessment.Decision, assessment.RecommendedSeverity, assessment.Confidence),
				})
			} else {
				fallbackCalls++
				applyLocalExpertNote(&enriched, expert, "ai_no_response")
			}
		} else {
			fallbackCalls++
			reason := "no_ai_client"
			if llmCalls >= maxOpenHackExpertCalls {
				reason = "call_cap_reached"
			}
			applyLocalExpertNote(&enriched, expert, reason)
		}
		output.Findings = append(output.Findings, enriched)
		_ = i
	}

done:
	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.Metadata["openhack_llm_calls"] = fmt.Sprintf("%d", llmCalls)
	output.Metadata["openhack_local_fallbacks"] = fmt.Sprintf("%d", fallbackCalls)
	output.Metadata["openhack_experts_used"] = fmt.Sprintf("%d", len(expertHits))
	output.DebugNotes = fmt.Sprintf(
		"OpenHackExpertAgent: reviewed %d finding(s) via %d expert(s); %d LLM call(s), %d local fallback(s)",
		len(output.Findings), len(expertHits), llmCalls, fallbackCalls,
	)
	return output, nil
}

// applyExpertAssessment writes the LLM's expert review onto the finding's
// EvidenceFields. The original finding fields are preserved so downstream
// dedup keeps working; the recommended severity is only adopted when the
// model returned a higher-rated tier than the source.
func applyExpertAssessment(f *model.Finding, a ai.OpenHackExpertAssessment) {
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	if a.Decision != "" {
		f.EvidenceFields["openhackDecision"] = a.Decision
	}
	if a.Rationale != "" {
		f.EvidenceFields["openhackRationale"] = a.Rationale
	}
	if a.RecommendedSeverity != "" {
		f.EvidenceFields["openhackRecommendedSeverity"] = a.RecommendedSeverity
		if recommended := model.Severity(a.RecommendedSeverity); severityWeight(recommended) > severityWeight(f.Severity) {
			f.Severity = recommended
		}
	}
	if a.Confidence > 0 && (f.Confidence == 0 || a.Confidence > f.Confidence) {
		f.Confidence = a.Confidence
	}
	if len(a.ProofObligations) > 0 {
		f.EvidenceFields["openhackProofObligations"] = strings.Join(a.ProofObligations, " | ")
	}
	if len(a.FollowUpProbes) > 0 {
		f.EvidenceFields["openhackFollowUpProbes"] = strings.Join(a.FollowUpProbes, " | ")
	}
	if len(a.EvidenceGaps) > 0 {
		f.EvidenceFields["openhackEvidenceGaps"] = strings.Join(a.EvidenceGaps, " | ")
	}
}

func applyLocalExpertNote(f *model.Finding, exp *openhack.Expert, reason string) {
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["openhackFallback"] = reason
	// Surface a deterministic plain-English reminder of the quality gate so
	// the operator still sees the OpenHack framing even without an LLM.
	f.EvidenceFields["openhackQualityGate"] = "Attacker-controlled input may reach boundary or sink in path, and guard quality is missing, uncertain, or class-specific."
	if exp != nil && len(exp.StandardRefs) > 0 {
		f.EvidenceFields["openhackStandardRefs"] = strings.Join(exp.StandardRefs, ", ")
	}
}

func severityWeight(s model.Severity) int {
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
