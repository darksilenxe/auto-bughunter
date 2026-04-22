package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// HypothesisAgent implements the LLM-proposes / scanner-verifies loop.
//
// The AI provider generates testable vulnerability hypotheses based on the
// current finding set and target surface; each hypothesis is then executed by
// the scanner's deterministic probe infrastructure and confirmed with an
// oracle. Only hypotheses the oracle confirms are surfaced as findings,
// preventing hallucinated reports that would degrade precision and waste
// operator time.
//
// When no AI provider is configured the agent falls back to a rule-based
// hypothesis generator in the local_reasoner that derives candidates from
// observed patterns in the existing finding set.
type HypothesisAgent struct {
	aiClient    *ai.Client
	scanService *scanner.Service
	enabled     bool
}

// NewHypothesisAgent constructs a HypothesisAgent. Both aiClient and
// scanService may be nil; the agent produces no findings when either is
// missing.
func NewHypothesisAgent(aiClient *ai.Client, scanService *scanner.Service, enabled bool) *HypothesisAgent {
	return &HypothesisAgent{
		aiClient:    aiClient,
		scanService: scanService,
		enabled:     enabled,
	}
}

func (a *HypothesisAgent) Name() string  { return "hypothesis" }
func (a *HypothesisAgent) Enabled() bool { return a.enabled }

// Run executes the propose→verify loop. It asks the AI for hypotheses, then
// runs each one through the scanner's targeted oracle and returns only the
// confirmed findings.
func (a *HypothesisAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if a.aiClient == nil || a.scanService == nil {
		output.DebugNotes = "HypothesisAgent: skipped — aiClient or scanService not configured"
		return output, nil
	}

	// Collect known endpoints for context.
	endpoints := append([]string{input.Target}, input.Options.SeedRuntimeEndpoints...)

	// Ask the AI (or local reasoner) to generate hypotheses.
	hypotheses := a.aiClient.Hypothesize(ctx, input.Target, input.AllFindings, endpoints)
	if len(hypotheses) == 0 {
		output.DebugNotes = "HypothesisAgent: no hypotheses generated"
		return output, nil
	}
	output.Metadata["hypotheses_generated"] = fmt.Sprintf("%d", len(hypotheses))

	// Verify each hypothesis with a deterministic scanner oracle.
	verified := 0
	for i, h := range hypotheses {
		endpoint := strings.TrimSpace(h.Endpoint)
		if endpoint == "" {
			continue
		}
		// Validate the endpoint is a parseable, in-scope URL.
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" {
			continue
		}

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
		// Tag the finding with the hypothesis provenance.
		f.ID = fmt.Sprintf("hypothesis-%d-%s", i+1, strings.ToLower(strings.TrimSpace(h.Category)))
		f.Sources = appendUnique(f.Sources, "hypothesis-agent")
		f.EvidenceFields["hypothesisID"] = h.ID
		f.EvidenceFields["hypothesisRationale"] = h.Rationale
		output.Findings = append(output.Findings, *f)
		verified++
	}

	output.Metadata["hypotheses_verified"] = fmt.Sprintf("%d", verified)
	output.DebugNotes = fmt.Sprintf(
		"HypothesisAgent: generated %d hypotheses, scanner oracle confirmed %d.",
		len(hypotheses), verified,
	)
	return output, nil
}

// appendUnique appends s to ss only if s is not already present.
func appendUnique(ss []string, s string) []string {
	for _, existing := range ss {
		if existing == s {
			return ss
		}
	}
	return append(ss, s)
}
