package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/openhack"
)

// OpenHackTriageAgent runs the OpenHack finding-triage prompt over the
// accumulated finding set. Per the OpenHack contract, only "accepted" and
// "downgraded" decisions may materialise a final finding; the agent
// therefore filters out findings the triage decision tagged as "rejected"
// or "duplicate", and keeps "needs_context" findings with a metadata flag
// for the operator to revisit.
//
// The agent honours the same call cap as OpenHackExpertAgent so the triage
// loop is bounded against very large finding sets. Findings beyond the cap
// are passed through unchanged with a metadata note explaining the skip.
//
// As with the expert agent, when no AI provider is configured the agent
// performs a deterministic local fallback: it accepts the source finding,
// keeps its severity, and tags it with the OpenHack triage reminder so
// downstream rendering/reporting stays consistent.
type OpenHackTriageAgent struct {
	aiClient *ai.Client
	pack     *openhack.Pack
	enabled  bool
}

// NewOpenHackTriageAgent constructs the agent. Both aiClient and pack may be
// nil; nil pack causes the agent to load the embedded default pack lazily.
func NewOpenHackTriageAgent(aiClient *ai.Client, pack *openhack.Pack, enabled bool) *OpenHackTriageAgent {
	if pack == nil {
		pack, _ = openhack.LoadDefault()
	}
	return &OpenHackTriageAgent{aiClient: aiClient, pack: pack, enabled: enabled}
}

func (a *OpenHackTriageAgent) Name() string  { return "openhack_triage" }
func (a *OpenHackTriageAgent) Enabled() bool { return a.enabled }

const maxOpenHackTriageCalls = 20

func (a *OpenHackTriageAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
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
		output.DebugNotes = "OpenHackTriageAgent: no findings to triage"
		output.Metadata["findings_count"] = "0"
		return output, nil
	}
	if a.pack == nil {
		output.Status = "skipped"
		output.DebugNotes = "OpenHackTriageAgent: prompt pack failed to load"
		output.Metadata["findings_count"] = "0"
		return output, nil
	}

	systemPrompt := a.pack.SystemPromptFor("finding-triage")
	if systemPrompt == "" {
		output.Status = "skipped"
		output.DebugNotes = "OpenHackTriageAgent: finding-triage prompt missing from pack"
		output.Metadata["findings_count"] = "0"
		return output, nil
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   fmt.Sprintf("OpenHack finding-triage starting on %d candidate(s)", len(allFindings)),
	})

	accepted, rejected, deferred, llmCalls, fallbacks := 0, 0, 0, 0, 0
	for _, f := range allFindings {
		select {
		case <-ctx.Done():
			output.Status = "partial"
			goto done
		default:
		}
		enriched := f
		if enriched.EvidenceFields == nil {
			enriched.EvidenceFields = map[string]string{}
		}

		if a.aiClient != nil && llmCalls < maxOpenHackTriageCalls {
			decision := a.aiClient.RunOpenHackTriage(ctx, systemPrompt, f)
			if decision.Decision != "" {
				llmCalls++
				keep := applyTriageDecision(&enriched, decision)
				switch decision.Decision {
				case "accepted", "downgraded":
					accepted++
				case "rejected", "duplicate":
					rejected++
				default:
					deferred++
				}
				if !keep {
					Emit(input.Emit, model.ScanEvent{
						Type:      model.ScanEventInfo,
						AgentName: a.Name(),
						Message: fmt.Sprintf("OpenHack triage suppressed %q → %s (%s)",
							truncate(f.Title, 60), decision.Decision, decision.SeverityRationale),
					})
					continue
				}
				output.Findings = append(output.Findings, enriched)
				continue
			}
			fallbacks++
		} else {
			fallbacks++
		}
		applyLocalTriageNote(&enriched, a.aiClient == nil)
		accepted++
		output.Findings = append(output.Findings, enriched)
	}

done:
	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.Metadata["openhack_triage_accepted"] = fmt.Sprintf("%d", accepted)
	output.Metadata["openhack_triage_rejected"] = fmt.Sprintf("%d", rejected)
	output.Metadata["openhack_triage_deferred"] = fmt.Sprintf("%d", deferred)
	output.Metadata["openhack_triage_llm_calls"] = fmt.Sprintf("%d", llmCalls)
	output.Metadata["openhack_triage_fallbacks"] = fmt.Sprintf("%d", fallbacks)
	output.DebugNotes = fmt.Sprintf(
		"OpenHackTriageAgent: %d accepted, %d rejected, %d deferred (LLM=%d, local=%d)",
		accepted, rejected, deferred, llmCalls, fallbacks,
	)
	return output, nil
}

// applyTriageDecision writes the triage outcome onto the finding and reports
// whether the finding should be kept. Rejected / duplicate decisions return
// false so the caller suppresses the finding from the output set.
func applyTriageDecision(f *model.Finding, d ai.OpenHackTriageDecision) bool {
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["openhackTriageDecision"] = d.Decision
	if d.SeverityRationale != "" {
		f.EvidenceFields["openhackTriageSeverityRationale"] = d.SeverityRationale
	}
	if d.EvidenceAssessment != "" {
		f.EvidenceFields["openhackTriageEvidence"] = d.EvidenceAssessment
	}
	if len(d.EvidenceGaps) > 0 {
		f.EvidenceFields["openhackTriageEvidenceGaps"] = strings.Join(d.EvidenceGaps, " | ")
	}
	if len(d.RequiredChanges) > 0 {
		f.EvidenceFields["openhackTriageRequiredChanges"] = strings.Join(d.RequiredChanges, " | ")
	}
	if d.StandardisedTitle != "" {
		f.EvidenceFields["openhackTriageStandardisedTitle"] = d.StandardisedTitle
	}
	if d.Confidence > 0 && (f.Confidence == 0 || d.Confidence < f.Confidence) {
		// Triage confidence is a downward gate — never inflate confidence.
		f.Confidence = d.Confidence
	}
	if sev := model.Severity(d.FinalSeverity); sev != "" {
		// Adopt the triage severity in both directions because triage is
		// explicitly responsible for the final severity rating.
		f.Severity = sev
	}

	switch d.Decision {
	case "rejected", "duplicate":
		return false
	case "needs_context":
		f.EvidenceFields["openhackTriageNeedsContext"] = "true"
		return true
	default:
		// "accepted", "downgraded", anything else → keep.
		return true
	}
}

func applyLocalTriageNote(f *model.Finding, noAI bool) {
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["openhackTriageDecision"] = "accepted_local"
	reason := "ai_no_response"
	if noAI {
		reason = "no_ai_client"
	}
	f.EvidenceFields["openhackTriageFallback"] = reason
	f.EvidenceFields["openhackTriageRequiredChanges"] = "Re-run triage with an AI provider configured to enforce OpenHack quality bar."
}
