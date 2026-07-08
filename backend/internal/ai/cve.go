package ai

import (
	"context"
	"encoding/json"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// CVEPoCRequest is a single AI-proposed HTTP request intended to validate
// (not merely theorize about) a CVE against the live target. Callers must
// treat every field as untrusted input: it is validated against safety.
// ValidateOutboundURL and the scan scope, and executed only when the
// operator has explicitly enabled CVE PoC execution.
type CVEPoCRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Description string            `json:"description,omitempty"`
	// ExpectedIndicator is a short string the AI expects to observe in the
	// response (status code, header, or body substring) if the CVE is
	// actually exploitable. Used by the agent to decide whether a PoC
	// replay confirms exploitability instead of merely completing.
	ExpectedIndicator string `json:"expectedIndicator,omitempty"`
}

// CVEAnalysis is the structured "reverse engineering" write-up the AI
// provider returns for a single CVE-tagged finding.
type CVEAnalysis struct {
	CVEID             string         `json:"cveId"`
	Summary           string         `json:"summary"`
	RootCause         string         `json:"rootCause"`
	AttackVector      string         `json:"attackVector"`
	AffectedComponent string         `json:"affectedComponent"`
	Impact            string         `json:"impact"`
	CWE               string         `json:"cwe,omitempty"`
	CVSSVector        string         `json:"cvssVector,omitempty"`
	CVSSScore         float64        `json:"cvssScore,omitempty"`
	References        []string       `json:"references,omitempty"`
	PoC               *CVEPoCRequest `json:"poc,omitempty"`
}

const cveAnalysisSchema = `{"cveId":string,"summary":string,"rootCause":string,"attackVector":string,"affectedComponent":string,"impact":string,"cwe":string,"cvssVector":string,"cvssScore":number,"references":[string],"poc":{"method":string,"url":string,"headers":{},"body":string,"description":string,"expectedIndicator":string}}`

const cveAnalysisInstructions = "You are reverse-engineering a specific CVE that was detected against a live target during an authorized security assessment. Explain the underlying vulnerability mechanism (root cause), describe how the flaw is triggered (attack vector), and propose ONE concrete HTTP-based proof-of-concept request scoped to the supplied target and finding evidence that would validate exploitability. The PoC url MUST be on the same host as the supplied target — never propose a request to a different host. Only propose a PoC when it can be expressed as a single bounded, non-destructive HTTP request (no destructive payloads, no data exfiltration beyond a benign marker/read). If no safe PoC is possible, omit the poc field entirely. Do not fabricate CVSS/CWE data if unknown — use the provided knownCVE fields when present instead of inventing new ones."

const cveAnalysisReminder = "Output strict JSON matching the requested outputContract. No prose outside the JSON."

// ReverseEngineerCVE asks the AI provider to reverse-engineer a single
// CVE-tagged finding: explain its root cause and attack vector, and propose
// a bounded, same-host HTTP PoC request that would validate exploitability.
//
// known is the offline/NVD knowledge-base record for cveID, if any; its
// fields are passed to the model as authoritative context so the model does
// not need to invent CVSS/CWE/reference data it doesn't have grounded
// knowledge of.
//
// Returns a zero-value CVEAnalysis (empty CVEID) when no AI provider is
// configured or the model's response cannot be parsed. Callers should treat
// an empty CVEID as "reverse engineering unavailable — fall back to catalog
// data only".
//
// Routing: like RunOpenHackExpert, this uses the planning/coding provider
// when configured because root-cause analysis benefits from the larger
// reasoning budget, falling back to the primary provider otherwise.
func (c *Client) ReverseEngineerCVE(
	ctx context.Context,
	target string,
	finding model.Finding,
	cveID string,
	known *KnownCVE,
) CVEAnalysis {
	if c == nil || !c.shouldCallProvider() {
		return CVEAnalysis{}
	}
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return CVEAnalysis{}
	}

	userPayload := map[string]any{
		"cveId":          cveID,
		"target":         strings.TrimSpace(target),
		"finding":        compactFinding(finding),
		"outputContract": cveAnalysisSchema,
		"instructions":   cveAnalysisInstructions,
	}
	if known != nil {
		userPayload["knownCVE"] = known
	}
	if guidance := c.retrieveKnowledgeGuidance(
		ctx,
		"cve-reverse-engineer",
		cveID+" "+finding.Title,
		knowledgeCategoriesForFinding(finding),
		4,
		1200,
	); guidance != "" {
		userPayload["knowledgeGuidance"] = guidance
	}
	body, err := json.Marshal(userPayload)
	if err != nil {
		return CVEAnalysis{}
	}

	messages := []Message{
		{Role: "system", Content: cveAnalysisInstructions + " " + cveAnalysisReminder},
		{Role: "user", Content: string(body)},
	}
	content, err := c.planningComplete(ctx, messages, 0.2, true)
	if err != nil || strings.TrimSpace(content) == "" {
		return CVEAnalysis{}
	}
	var out CVEAnalysis
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return CVEAnalysis{}
	}
	out.CVSSScore = clampCVSS(out.CVSSScore)
	if len(out.References) > 8 {
		out.References = out.References[:8]
	}
	return out
}

// KnownCVE is the subset of curated/live CVE knowledge-base data passed to
// the model as grounding context. It mirrors internal/cve.Record without
// importing that package here to avoid a dependency cycle risk; callers
// construct it from cve.Record.
type KnownCVE struct {
	Summary    string   `json:"summary,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
	CVSSVector string   `json:"cvssVector,omitempty"`
	CVSSScore  float64  `json:"cvssScore,omitempty"`
	References []string `json:"references,omitempty"`
}

func clampCVSS(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 10 {
		return 10
	}
	return v
}
