package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/cve"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/scope"
)

// CVEResearchAgent ("cve_reverse_engineer") reverse-engineers CVE-tagged
// findings discovered elsewhere in the scan (retire.js Identifiers.CVE,
// nuclei cve-* template IDs, Metasploit native probe titles, or any other
// probe that embeds a "CVE-YYYY-NNNNN" identifier in its finding text).
//
// For each detected CVE it:
//  1. Looks up a curated offline knowledge-base record (internal/cve) to
//     ground the analysis in known CVSS/CWE/reference data.
//  2. Asks the AI provider to reverse-engineer the vulnerability's root
//     cause/attack vector and to propose a bounded, same-host HTTP PoC
//     request — falling back to catalog-only data when no AI provider is
//     configured or the model produces no usable analysis.
//  3. Validates any AI-proposed PoC request through safety.ValidateOutboundURL
//     and the scan scope before ever considering executing it.
//  4. Executes the PoC only when input.Options.EnableCVEPoCExecution is set
//     (opt-in, since this performs a live exploitation attempt); otherwise it
//     records the proposed PoC as an unfired reproduction step.
//
// The agent never invents PoC requests itself — it only ever fires what the
// AI proposed, and only after the safety/scope gates above pass.
type CVEResearchAgent struct {
	enabled            bool
	aiClient           *ai.Client
	discoverRecentCVEs func(context.Context, []model.Finding, cve.DiscoveryOptions) ([]cve.DiscoveredCVE, error)
}

// maxCVEsPerRun bounds how many distinct CVE identifiers are analysed in a
// single agent execution, to keep AI cost and PoC request volume bounded.
const maxCVEsPerRun = 8

// cvePoCTimeout bounds how long the agent waits for a single PoC HTTP
// request to complete before giving up on validation.
const cvePoCTimeout = 15 * time.Second

// NewCVEResearchAgent constructs the agent. aiClient may be nil; when nil the
// agent still emits catalog-grounded findings for detected CVEs (title,
// summary, CWE/CVSS from the offline knowledge base, references) but performs
// no AI-driven root-cause analysis and proposes no PoC.
func NewCVEResearchAgent(enabled bool, aiClient *ai.Client) *CVEResearchAgent {
	return &CVEResearchAgent{
		enabled:            enabled,
		aiClient:           aiClient,
		discoverRecentCVEs: cve.DiscoverRecentWebCVEs,
	}
}

func (a *CVEResearchAgent) Name() string  { return "cve_reverse_engineer" }
func (a *CVEResearchAgent) Enabled() bool { return a.enabled }

func (a *CVEResearchAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
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
		output.DebugNotes = "CVEResearchAgent: no findings available; skipping"
		return output, nil
	}

	target := strings.TrimSpace(input.Target)
	if target == "" {
		output.DebugNotes = "CVEResearchAgent: no target; skipping"
		return output, nil
	}

	recentDiscovered := 0
	recentDiscoveryNote := ""
	if input.Options.UseRecentCVEFeed && a.discoverRecentCVEs != nil {
		recentCVEs, err := a.discoverRecentCVEs(ctx, allFindings, cve.DiscoveryOptions{})
		if err != nil {
			recentDiscoveryNote = fmt.Sprintf(" recent-discovery-error=%v.", err)
		} else {
			for _, rec := range recentCVEs {
				finding := buildRecentCVEFinding(rec.Record, rec.MatchedTechnologies)
				output.Findings = append(output.Findings, finding)
				Emit(input.Emit, model.ScanEvent{
					Type:         model.ScanEventFinding,
					AgentName:    a.Name(),
					FindingTitle: finding.Title,
					Severity:     string(finding.Severity),
					Message:      fmt.Sprintf("[%s] %s", finding.Severity, finding.Title),
				})
			}
			recentDiscovered = len(recentCVEs)
		}
	}

	// Detect CVEs across all findings, remembering the first finding each
	// CVE was seen on so the AI analysis has real evidence to work from.
	type cveHit struct {
		id      string
		finding model.Finding
	}
	seen := map[string]bool{}
	var hits []cveHit
	for _, f := range allFindings {
		for _, id := range cve.DetectFindingCVEs(f) {
			if seen[id] {
				continue
			}
			seen[id] = true
			hits = append(hits, cveHit{id: id, finding: f})
		}
	}

	if len(hits) == 0 {
		output.Metadata["cves_detected"] = "0"
		output.Metadata["cves_analyzed"] = "0"
		output.Metadata["pocs_proposed"] = "0"
		output.Metadata["pocs_executed"] = "0"
		output.Metadata["pocs_confirmed"] = "0"
		output.Metadata["cves_recent_discovered"] = fmt.Sprintf("%d", recentDiscovered)
		if recentDiscovered == 0 {
			output.DebugNotes = "CVEResearchAgent: no CVE identifiers detected in findings; skipping"
		} else {
			output.DebugNotes = fmt.Sprintf("CVEResearchAgent: no existing CVE-tagged findings; recent discovery added %d CVE(s).", recentDiscovered)
		}
		return output, nil
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventAgentStart,
		AgentName: a.Name(),
		Message:   fmt.Sprintf("CVE reverse-engineering agent starting — %d CVE(s) detected", len(hits)),
	})

	if len(hits) > maxCVEsPerRun {
		hits = hits[:maxCVEsPerRun]
	}

	client := &http.Client{Timeout: cvePoCTimeout}

	analyzed := 0
	pocsProposed := 0
	pocsExecuted := 0
	pocsConfirmed := 0

	for _, hit := range hits {
		select {
		case <-ctx.Done():
			output.Status = "partial"
			goto done
		default:
		}

		known, hasKnown := cve.Lookup(hit.id)

		var analysis ai.CVEAnalysis
		if a.aiClient != nil {
			var knownForAI *ai.KnownCVE
			if hasKnown {
				knownForAI = &ai.KnownCVE{
					Summary:    known.Summary,
					CWE:        known.CWE,
					CVSSVector: known.CVSSVector,
					CVSSScore:  known.CVSSScore,
					References: known.References,
				}
			}
			analysis = a.aiClient.ReverseEngineerCVE(ctx, target, hit.finding, hit.id, knownForAI)
		}
		analyzed++

		finding := buildCVEFinding(hit.id, hit.finding, known, hasKnown, analysis)

		if analysis.PoC != nil {
			pocsProposed++
			pocFinding, executed, confirmed := a.evaluateCVEPoC(ctx, client, input, hit.id, *analysis.PoC, &finding)
			if executed {
				pocsExecuted++
			}
			if confirmed {
				pocsConfirmed++
			}
			finding = pocFinding
		}

		output.Findings = append(output.Findings, finding)
		Emit(input.Emit, model.ScanEvent{
			Type:         model.ScanEventFinding,
			AgentName:    a.Name(),
			FindingTitle: finding.Title,
			Severity:     string(finding.Severity),
			Message:      fmt.Sprintf("[%s] %s", finding.Severity, finding.Title),
		})
	}

done:
	output.Metadata["cves_detected"] = fmt.Sprintf("%d", len(hits))
	output.Metadata["cves_analyzed"] = fmt.Sprintf("%d", analyzed)
	output.Metadata["pocs_proposed"] = fmt.Sprintf("%d", pocsProposed)
	output.Metadata["pocs_executed"] = fmt.Sprintf("%d", pocsExecuted)
	output.Metadata["pocs_confirmed"] = fmt.Sprintf("%d", pocsConfirmed)
	output.Metadata["cves_recent_discovered"] = fmt.Sprintf("%d", recentDiscovered)
	output.DebugNotes = fmt.Sprintf(
		"CVEResearchAgent: analysed %d of %d detected CVE(s); recent discovery added %d CVE(s); proposed %d PoC(s), executed %d, confirmed %d.%s",
		analyzed, len(hits), recentDiscovered, pocsProposed, pocsExecuted, pocsConfirmed, recentDiscoveryNote,
	)
	return output, nil
}

func buildRecentCVEFinding(rec cve.Record, matchedTech []string) model.Finding {
	cveID := cve.Normalize(rec.ID)
	title := fmt.Sprintf("Newly published CVE relevant to detected stack: %s", cveID)
	evidence := "source=nvd-recent"
	if rec.PublishedDate != "" {
		evidence += ", published=" + rec.PublishedDate
	}
	if len(matchedTech) > 0 {
		evidence += ", matchedTech=" + strings.Join(matchedTech, ",")
	}
	desc := strings.TrimSpace(rec.Summary)
	if desc == "" {
		desc = fmt.Sprintf("%s was recently published and appears relevant to observed technologies.", cveID)
	}
	return model.Finding{
		ID:             fmt.Sprintf("recent-cve-%s", strings.ToLower(cveID)),
		Category:       "known_vulnerability",
		Severity:       model.SeverityInfo,
		Title:          title,
		Description:    desc,
		Evidence:       evidence,
		Recommendation: "Validate affected component versions and patch status against this newly published CVE.",
		CWE:            rec.CWE,
		CVSSVector:     rec.CVSSVector,
		CVSSScore:      rec.CVSSScore,
		References:     append([]string{}, rec.References...),
		Sources:        []string{"cve-discovery", "nvd-recent"},
		Confidence:     0.55,
		EvidenceFields: map[string]string{
			"cveId":              cveID,
			"cveKnowledgeSource": rec.Source,
			"publishedDate":      rec.PublishedDate,
			"matchedTech":        strings.Join(matchedTech, ","),
		},
	}
}

// buildCVEFinding assembles the base finding for a detected CVE, populating
// standard model.Finding fields from the offline knowledge-base record and/or
// the AI analysis so the reporting pipeline requires no new document type.
func buildCVEFinding(cveID string, source model.Finding, known cve.Record, hasKnown bool, analysis ai.CVEAnalysis) model.Finding {
	summary := analysis.Summary
	rootCause := analysis.RootCause
	attackVector := analysis.AttackVector
	impact := analysis.Impact
	cwe := analysis.CWE
	cvssVector := analysis.CVSSVector
	cvssScore := analysis.CVSSScore
	refs := append([]string{}, analysis.References...)
	aiPowered := strings.TrimSpace(analysis.CVEID) != ""

	if hasKnown {
		if summary == "" {
			summary = known.Summary
		}
		if cwe == "" {
			cwe = known.CWE
		}
		if cvssVector == "" {
			cvssVector = known.CVSSVector
		}
		if cvssScore == 0 {
			cvssScore = known.CVSSScore
		}
		for _, r := range known.References {
			refs = appendUnique(refs, r)
		}
	}
	refs = appendUnique(refs, "https://nvd.nist.gov/vuln/detail/"+cveID)

	if summary == "" {
		summary = fmt.Sprintf("%s was detected against this target but no catalog or AI-derived summary is available.", cveID)
	}

	description := summary
	if rootCause != "" {
		description = description + "\n\nRoot cause: " + rootCause
	}
	if attackVector != "" {
		description = description + "\n\nAttack vector: " + attackVector
	}
	if !aiPowered {
		description = description + "\n\n(AI reverse-engineering was unavailable for this finding; the above reflects catalog data only.)"
	}

	severity := source.Severity
	if severity == "" {
		severity = severityFromCVSS(cvssScore)
	}

	category := source.Category
	if category == "" {
		category = "known_vulnerability"
	}

	sources := appendUnique(append([]string{}, source.Sources...), "cve-reverse-engineer")

	reproSteps := []string{
		fmt.Sprintf("Confirm the affected component/version referenced in the original finding (%s).", source.Title),
	}
	if attackVector != "" {
		reproSteps = append(reproSteps, "Attack vector: "+attackVector)
	}

	f := model.Finding{
		ID:                fmt.Sprintf("cve-reverse-engineer-%s", strings.ToLower(cveID)),
		Category:          category,
		Severity:          severity,
		Title:             fmt.Sprintf("%s — reverse-engineered analysis (%s)", cveID, source.Title),
		Description:       description,
		Evidence:          source.Evidence,
		Recommendation:    source.Recommendation,
		Impact:            impact,
		CWE:               cwe,
		CVSSVector:        cvssVector,
		CVSSScore:         cvssScore,
		AffectedURL:       source.AffectedURL,
		AffectedParameter: source.AffectedParameter,
		References:        refs,
		ReproductionSteps: reproSteps,
		Sources:           sources,
		Confidence:        source.Confidence,
		EvidenceFields: map[string]string{
			"cveId":              cveID,
			"sourceFindingId":    source.ID,
			"cveAiPowered":       fmt.Sprintf("%t", aiPowered),
			"cveKnowledgeSource": known.Source,
		},
	}
	if f.Recommendation == "" {
		f.Recommendation = "Apply the vendor patch or mitigation for " + cveID + " and verify the fix with a follow-up scan."
	}
	return f
}

// evaluateCVEPoC validates the AI-proposed PoC request against SSRF and scan
// scope guards, then — only when explicitly enabled — fires it and folds the
// outcome into the finding's PoC, ProofArtifacts, and ProofState fields.
// It always returns an updated finding (with the proposed PoC recorded as a
// reproduction step) even when execution is disabled or the request is
// rejected by a safety/scope gate.
func (a *CVEResearchAgent) evaluateCVEPoC(
	ctx context.Context,
	client *http.Client,
	input AgentInput,
	cveID string,
	poc ai.CVEPoCRequest,
	finding *model.Finding,
) (model.Finding, bool, bool) {
	f := *finding

	method := strings.ToUpper(strings.TrimSpace(poc.Method))
	if method == "" {
		method = http.MethodGet
	}
	pocURL := strings.TrimSpace(poc.URL)

	pocSummary := fmt.Sprintf("%s %s", method, pocURL)
	if poc.Description != "" {
		pocSummary = poc.Description + " :: " + pocSummary
	}
	f.PoC = pocSummary
	f.ReproductionSteps = append(f.ReproductionSteps, fmt.Sprintf("Proposed PoC request: %s %s", method, pocURL))

	if pocURL == "" {
		return f, false, false
	}

	// Safety gate 1: standard outbound SSRF protections (blocks internal/
	// metadata/loopback hosts regardless of scope configuration).
	if err := safety.ValidateOutboundURL(pocURL); err != nil {
		f.ReproductionSteps = append(f.ReproductionSteps, fmt.Sprintf("PoC request rejected by safety policy: %v", err))
		return f, false, false
	}

	// Safety gate 2: the PoC must target the same host as the scan target —
	// an AI-proposed request to a different host is never executed, since
	// this agent's mandate is to validate findings on the assessed target,
	// not to pivot to arbitrary hosts.
	targetHost := hostOf(input.Target)
	pocHost := hostOf(pocURL)
	if targetHost == "" || pocHost == "" || !strings.EqualFold(targetHost, pocHost) {
		f.ReproductionSteps = append(f.ReproductionSteps, "PoC request rejected: proposed host does not match the scan target")
		return f, false, false
	}

	// Safety gate 3: honour configured scan scope (excluded paths/hosts).
	if !scope.IsURLInScope(pocURL, input.Scope) {
		f.ReproductionSteps = append(f.ReproductionSteps, "PoC request rejected: outside configured scan scope")
		return f, false, false
	}

	if !input.Options.EnableCVEPoCExecution {
		f.ReproductionSteps = append(f.ReproductionSteps, "PoC execution is disabled (enable via EnableCVEPoCExecution to validate live exploitability).")
		return f, false, false
	}

	var bodyReader io.Reader
	if poc.Body != "" {
		bodyReader = bytes.NewReader([]byte(poc.Body))
	}
	req, err := http.NewRequestWithContext(ctx, method, pocURL, bodyReader)
	if err != nil {
		f.ReproductionSteps = append(f.ReproductionSteps, fmt.Sprintf("PoC request could not be built: %v", err))
		return f, false, false
	}
	scanner.ApplyAuthProfile(req, input.AuthProfile)
	for k, v := range poc.Headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		f.ReproductionSteps = append(f.ReproductionSteps, fmt.Sprintf("PoC request failed: %v", err))
		return f, true, false
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()

	transcript := fmt.Sprintf("Request: %s %s\nStatus: %d\nBody (truncated): %s",
		method, pocURL, resp.StatusCode, truncateBody(string(respBody), 500))

	confirmed := false
	if indicator := strings.TrimSpace(poc.ExpectedIndicator); indicator != "" {
		confirmed = strings.Contains(fmt.Sprintf("%d", resp.StatusCode), indicator) ||
			strings.Contains(string(respBody), indicator) ||
			responseHeadersContain(resp.Header, indicator)
	}

	f.ProofArtifacts = append(f.ProofArtifacts, model.ProofArtifact{
		Type:        "cve_poc",
		Label:       fmt.Sprintf("%s PoC replay", cveID),
		Value:       transcript,
		Description: poc.Description,
	})
	if confirmed {
		f.ProofState = model.ProofStateExploited
		if f.Confidence < 0.9 {
			f.Confidence = 0.9
		}
		f.ReproductionSteps = append(f.ReproductionSteps, "PoC replay confirmed the expected indicator — exploitability demonstrated live.")
	} else {
		f.ReproductionSteps = append(f.ReproductionSteps, "PoC replay executed but did not confirm the expected indicator; treat as unverified.")
	}

	return f, true, confirmed
}

// severityFromCVSS maps a CVSS v3 base score to a model.Severity using the
// standard NVD qualitative rating bands. Returns SeverityInfo for a zero or
// unrecognised score.
func severityFromCVSS(score float64) model.Severity {
	switch {
	case score >= 9.0:
		return model.SeverityCritical
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// hostOf returns the lower-cased hostname of a URL, or "" if it cannot be
// parsed.
func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func responseHeadersContain(h http.Header, needle string) bool {
	for _, values := range h {
		for _, v := range values {
			if strings.Contains(v, needle) {
				return true
			}
		}
	}
	return false
}

func truncateBody(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
