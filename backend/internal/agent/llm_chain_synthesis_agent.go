package agent

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/impact"
	"auto-bughunter/backend/internal/model"
)

// LLMChainSynthesisAgent sends the accumulated finding set to the AI and asks
// it to reason about novel multi-step attack chains not covered by the static
// exploit-chain rules. Results are validated for structural completeness and
// filtered for minimum confidence before being surfaced as findings.
type LLMChainSynthesisAgent struct {
	aiClient *ai.Client
	enabled  bool
}

// NewLLMChainSynthesisAgent constructs a LLMChainSynthesisAgent.
func NewLLMChainSynthesisAgent(aiClient *ai.Client, enabled bool) *LLMChainSynthesisAgent {
	return &LLMChainSynthesisAgent{
		aiClient: aiClient,
		enabled:  enabled,
	}
}

func (a *LLMChainSynthesisAgent) Name() string  { return "llm_chain_synthesis" }
func (a *LLMChainSynthesisAgent) Enabled() bool { return a.enabled }

// Run synthesizes novel exploit chains from the finding set and returns them
// as model.Finding entries so they participate in deduplication, scoring and
// reporting alongside any other findings.
func (a *LLMChainSynthesisAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if a.aiClient == nil {
		output.DebugNotes = "LLMChainSynthesisAgent: skipped — AI client not configured"
		return output, nil
	}

	allFindings := input.AllFindings
	if len(allFindings) == 0 {
		allFindings = input.Previous.Findings
	}
	if len(allFindings) == 0 {
		output.DebugNotes = "LLMChainSynthesisAgent: no findings to synthesize chains from"
		return output, nil
	}

	// Convert findings to a lightweight representation for the LLM.
	goals := impact.GoalsOrDefault(input.Options)
	findingSet := make([]map[string]string, 0, len(allFindings))
	for _, f := range allFindings {
		enriched := impact.EnrichFinding(f, goals)
		findingSet = append(findingSet, map[string]string{
			"id":          enriched.ID,
			"category":    enriched.Category,
			"severity":    string(enriched.Severity),
			"title":       enriched.Title,
			"cwe":         enriched.CWE,
			"url":         enriched.AffectedURL,
			"proofState":  string(enriched.ProofState),
			"impactScore": fmt.Sprintf("%.2f", enriched.ImpactScore),
			"bountyScore": fmt.Sprintf("%.2f", enriched.BountyScore),
		})
	}

	chains := a.aiClient.SynthesizeChains(ctx, input.Target, findingSet, goals)
	if len(chains) == 0 {
		output.DebugNotes = "LLMChainSynthesisAgent: AI returned no novel chains"
		return output, nil
	}

	output.Metadata["chains_synthesized"] = fmt.Sprintf("%d", len(chains))

	for _, chain := range chains {
		if len(chain.Steps) == 0 {
			continue
		}
		fid := "llm-chain-" + chainSynthesisSlug(chain.ID)
		finding := model.Finding{
			ID:       fid,
			Category: "access-control",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("[LLM-Synthesized Chain] %s", chain.Title),
			Description: "The AI planner identified a novel multi-step exploit chain by reasoning across " +
				"the accumulated finding set. This chain is not covered by static rules and describes " +
				"how an attacker can combine multiple individual vulnerabilities to achieve a higher-impact " +
				"outcome. Validate each step manually before including in a report.\n\n" +
				"Impact: " + chain.Impact,
			Evidence: fmt.Sprintf(
				"Source findings: %s | Chain steps: %d | AI confidence: %.0f%%",
				strings.Join(chain.SourceIDs, ", "),
				len(chain.Steps),
				chain.Confidence*100,
			),
			Recommendation: "Validate the individual steps of this chain against the application. " +
				"If confirmed, remediate the constituent vulnerabilities; fixing any single link in the " +
				"chain typically breaks the end-to-end exploit.",
			Confidence:        chain.Confidence,
			Sources:           []string{"llm-chain-synthesis"},
			ReproductionSteps: chain.Steps,
			BusinessTags:      []string{"llm-synthesized-chain"},
			EvidenceFields: map[string]string{
				"validationType": "llm-synthesis",
				"chainID":        chain.ID,
				"sourceIDs":      strings.Join(chain.SourceIDs, ","),
				"confidence":     fmt.Sprintf("%.2f", chain.Confidence),
			},
		}
		output.Findings = append(output.Findings, impact.EnrichFinding(finding, goals))
	}

	output.DebugNotes = fmt.Sprintf(
		"LLMChainSynthesisAgent: AI synthesized %d novel chains from %d findings.",
		len(chains), len(allFindings),
	)
	return output, nil
}

func chainSynthesisSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
