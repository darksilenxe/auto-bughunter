package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/impact"
	"auto-bughunter/backend/internal/model"
)

// SupportedBugBountyPlatforms enumerates the bug-bounty platform identifiers
// accepted by RenderBugBountyMarkdownForPlatform / RenderBugBountyZipForPlatform.
// Empty / unknown values fall back to the platform-agnostic format that is
// portable across HackerOne, Bugcrowd and Intigriti.
var SupportedBugBountyPlatforms = []string{"hackerone", "bugcrowd", "intigriti"}

// FindingToBugBountySubmission converts a finding into the canonical
// BugBountySubmission structure, applying enrichment first so that CVSS/CWE/
// References are populated when available.
func FindingToBugBountySubmission(f model.Finding, target string) model.BugBountySubmission {
	enriched := impact.EnrichFinding(EnrichFinding(f), f.ImpactGoals)
	prerequisites := []string(nil)
	if enriched.Exploitability != nil {
		prerequisites = append(prerequisites, enriched.Exploitability.Prerequisites...)
	}
	return model.BugBountySubmission{
		Title:          enriched.Title,
		Severity:       enriched.Severity,
		CVSSVector:     enriched.CVSSVector,
		CVSSScore:      enriched.CVSSScore,
		CWE:            enriched.CWE,
		Asset:          findingAsset(enriched, target),
		Summary:        enriched.Description,
		Steps:          enriched.ReproductionSteps,
		Impact:         enriched.Impact,
		ImpactScore:    enriched.ImpactScore,
		BountyScore:    enriched.BountyScore,
		ProofState:     enriched.ProofState,
		Goals:          append([]model.ImpactGoal(nil), enriched.ImpactGoals...),
		Prerequisites:  prerequisites,
		ProofArtifacts: append([]model.ProofArtifact(nil), enriched.ProofArtifacts...),
		Remediation:    enriched.Recommendation,
		References:     enriched.References,
		Attachments:    impact.BuildSubmissionAttachments(enriched),
	}
}

// RenderBugBountyMarkdown returns a Markdown bug-bounty submission for a
// single finding in the platform-agnostic format that HackerOne, Bugcrowd
// and Intigriti all accept.
func RenderBugBountyMarkdown(f model.Finding, target string) string {
	return RenderBugBountyMarkdownForPlatform(f, target, "")
}

// RenderBugBountyMarkdownForPlatform renders the same submission body as
// RenderBugBountyMarkdown plus a platform-specific header banner and submission
// hints when platform is one of SupportedBugBountyPlatforms. Unknown values
// fall back to the platform-agnostic format.
func RenderBugBountyMarkdownForPlatform(f model.Finding, target, platform string) string {
	enriched := impact.EnrichFinding(EnrichFinding(f), f.ImpactGoals)
	sub := FindingToBugBountySubmission(enriched, target)
	var b strings.Builder
	b.WriteString("# " + sub.Title + "\n\n")

	if banner := platformBanner(platform); banner != "" {
		b.WriteString(banner)
	}
	if mapping := PlatformFieldMapping(platform); len(mapping) > 0 {
		b.WriteString("## Platform Field Mapping\n\n")
		keys := make([]string, 0, len(mapping))
		for k := range mapping {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(fmt.Sprintf("- **%s** → `%s`\n", k, mapping[k]))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Summary\n\n")
	if sub.Summary != "" {
		b.WriteString(sub.Summary + "\n\n")
	} else {
		b.WriteString("_No description provided._\n\n")
	}

	b.WriteString("## Vulnerability Details\n\n")
	rows := [][2]string{
		{"Severity", sevDisplay(sub.Severity)},
		{"CWE", sub.CWE},
		{"CVSS", fmtCVSS(sub.CVSSScore, sub.CVSSVector)},
		{"Asset", sub.Asset},
	}
	if enriched.AffectedParameter != "" {
		rows = append(rows, [2]string{"Affected Parameter", enriched.AffectedParameter})
	}
	for _, row := range rows {
		if strings.TrimSpace(row[1]) != "" {
			b.WriteString(fmt.Sprintf("- **%s:** %s\n", row[0], row[1]))
		}
	}
	if sub.ProofState != "" {
		b.WriteString(fmt.Sprintf("- **Proof State:** %s\n", strings.ReplaceAll(string(sub.ProofState), "_", " ")))
	}
	if sub.ImpactScore > 0 {
		b.WriteString(fmt.Sprintf("- **Impact Score:** %.2f\n", sub.ImpactScore))
	}
	if sub.BountyScore > 0 {
		b.WriteString(fmt.Sprintf("- **Bounty Score:** %.2f\n", sub.BountyScore))
	}
	b.WriteString("\n")

	// Severity rationale: deterministic explanation of why this severity
	// rating was chosen, helping triagers cross-check the analyst's call
	// without re-deriving CVSS/CWE/exploitability themselves.
	rationale := SeverityRationale(enriched)
	if len(rationale) > 0 {
		b.WriteString("## Severity Rationale\n\n")
		for _, line := range rationale {
			b.WriteString("- " + line + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Steps to Reproduce\n\n")
	if len(sub.Steps) == 0 {
		b.WriteString("_No reproduction steps recorded for this finding._\n\n")
	} else {
		for i, step := range sub.Steps {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		b.WriteString("\n")
	}

	if enriched.Evidence != "" {
		b.WriteString("## Evidence\n\n```\n" + enriched.Evidence + "\n```\n\n")
	}
	if curl := strings.TrimSpace(enriched.EvidenceFields["curlReproducer"]); curl != "" {
		b.WriteString("## Reproducer\n\n```bash\n" + curl + "\n```\n\n")
	} else if enriched.PoC != "" {
		b.WriteString("## Proof of Concept\n\n```\n" + enriched.PoC + "\n```\n\n")
	}

	// Reproducibility evidence checklist tells the triager which artifacts
	// are bundled and which are missing — turning the submission into a
	// reproducibility bundle by default.
	b.WriteString("## Reproducibility Evidence\n\n")
	for _, line := range reproducibilityChecklist(enriched) {
		b.WriteString("- " + line + "\n")
	}
	b.WriteString("\n")

	if len(sub.Goals) > 0 {
		b.WriteString("## Target Impact Goals\n\n")
		for _, goal := range sub.Goals {
			b.WriteString("- " + strings.ReplaceAll(string(goal), "_", " ") + "\n")
		}
		b.WriteString("\n")
	}

	if len(sub.Prerequisites) > 0 {
		b.WriteString("## Exploit Preconditions\n\n")
		for _, pre := range sub.Prerequisites {
			b.WriteString("- " + pre + "\n")
		}
		b.WriteString("\n")
	}

	if len(sub.ProofArtifacts) > 0 {
		b.WriteString("## Proof Artifacts\n\n")
		for _, artifact := range sub.ProofArtifacts {
			line := "- **" + artifact.Label + "**"
			if artifact.Value != "" {
				line += ": " + artifact.Value
			}
			if artifact.Description != "" {
				line += " — " + artifact.Description
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Impact\n\n")
	if sub.Impact != "" {
		b.WriteString(sub.Impact + "\n\n")
	} else {
		b.WriteString("_Impact assessment not available._\n\n")
	}

	b.WriteString("## Suggested Remediation\n\n")
	if sub.Remediation != "" {
		b.WriteString(sub.Remediation + "\n\n")
	} else {
		b.WriteString("_No remediation guidance recorded._\n\n")
	}

	if len(sub.References) > 0 {
		b.WriteString("## References\n\n")
		for _, r := range sub.References {
			b.WriteString("- " + r + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n")
	b.WriteString("_Generated by Auto Bughunter at " + time.Now().UTC().Format(time.RFC3339) + "_\n")
	return b.String()
}

// SeverityRationale returns a short, deterministic, human-readable list of
// reasons the finding's severity rating was assigned. Reads from CVSS, CWE,
// confidence, exploitability and business tags so triagers can cross-check
// analyst severity calls without re-deriving the model themselves.
func SeverityRationale(f model.Finding) []string {
	out := []string{
		"Assigned severity: " + sevDisplay(f.Severity) + ".",
	}
	if f.CVSSVector != "" || f.CVSSScore > 0 {
		out = append(out, fmt.Sprintf("CVSS %s aligns with the assigned severity tier.", fmtCVSS(f.CVSSScore, f.CVSSVector)))
	}
	if f.CWE != "" {
		out = append(out, "Mapped to "+f.CWE+", which is the recognised weakness class for this finding.")
	}
	if f.Confidence > 0 {
		out = append(out, fmt.Sprintf("Detection confidence reported at %.2f.", f.Confidence))
	}
	if f.Exploitability != nil {
		if f.Exploitability.Reachable {
			out = append(out, "Exploitability analysis confirmed the affected surface is reachable.")
		}
		if f.Exploitability.RequiredRole != "" {
			out = append(out, "Required role for exploitation: "+f.Exploitability.RequiredRole+".")
		}
		if status := strings.TrimSpace(f.Exploitability.VerifiedStatus); status != "" {
			out = append(out, "Operator verification status: "+status+".")
		}
	}
	if len(f.BusinessTags) > 0 {
		out = append(out, "Business context tags: "+strings.Join(f.BusinessTags, ", ")+".")
	}
	return out
}

// reproducibilityChecklist returns a deterministic evidence checklist (✅/⚠)
// describing which reproducibility artifacts are bundled with this submission.
// This makes it obvious to triagers what is and isn't included.
func reproducibilityChecklist(f model.Finding) []string {
	mark := func(present bool, label string) string {
		if present {
			return "✅ " + label
		}
		return "⚠️  " + label + " (not captured)"
	}
	out := []string{
		mark(len(f.ReproductionSteps) > 0, "Step-by-step reproduction"),
		mark(strings.TrimSpace(f.Evidence) != "", "Raw request/response evidence"),
		mark(strings.TrimSpace(f.EvidenceFields["curlReproducer"]) != "", "Curl reproducer"),
		mark(strings.TrimSpace(f.PoC) != "", "Proof-of-concept payload"),
		mark(f.AffectedURL != "", "Affected URL recorded"),
		mark(f.AffectedParameter != "", "Affected parameter recorded"),
	}
	if f.Exploitability != nil {
		out = append(out, mark(f.Exploitability.Reachable, "Exploitability reachability analysis"))
	}
	return out
}

// SubmissionReadinessScore computes a 0–100 score indicating how complete a
// finding's submission artifact is. Each field that a bug-bounty platform
// triager expects contributes to the score. A score >= 90 enables the
// one-click submit action in the export wizard.
//
// Field weights (total when all present = 100):
//
//	Title              10
//	Description/Summary 10
//	Severity           10
//	AffectedURL        10
//	ReproductionSteps  15
//	Evidence           10
//	CWE                 5
//	CVSSScore           5
//	Impact              5
//	Recommendation      5
//	ProofArtifacts      5
//	Confidence >= 0.7   5
//	AffectedParameter   5
func SubmissionReadinessScore(f model.Finding) model.SubmissionReadinessResult {
	score := 0
	missing := []string{}

	add := func(points int, present bool, label string) {
		if present {
			score += points
		} else {
			missing = append(missing, label)
		}
	}

	add(10, strings.TrimSpace(f.Title) != "", "title")
	add(10, strings.TrimSpace(f.Description) != "", "description / summary")
	add(10, f.Severity != "" && f.Severity != model.SeverityInfo, "severity (non-informational)")
	add(10, strings.TrimSpace(f.AffectedURL) != "", "affected URL")
	add(15, len(f.ReproductionSteps) > 0, "step-by-step reproduction steps")
	add(10, strings.TrimSpace(f.Evidence) != "", "raw evidence (request/response or screenshot)")
	add(5, strings.TrimSpace(f.CWE) != "", "CWE mapping")
	add(5, f.CVSSScore > 0, "CVSS score")
	add(5, strings.TrimSpace(f.Impact) != "", "business impact statement")
	add(5, strings.TrimSpace(f.Recommendation) != "", "remediation recommendation")
	add(5, len(f.ProofArtifacts) > 0, "proof artifacts (PoC, screenshot, OAST token)")
	add(5, f.Confidence >= 0.7, "detection confidence >= 0.70")
	add(5, strings.TrimSpace(f.AffectedParameter) != "", "affected parameter or injection point")

	if score > 100 {
		score = 100
	}
	return model.SubmissionReadinessResult{
		Score:         score,
		MissingFields: missing,
		ReadyToSubmit: score >= 90,
	}
}

func platformBanner(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "hackerone":
		return "> **Submission target:** HackerOne. Paste sections below into the report form; the asset is pre-populated under *Vulnerability Details*.\n\n"
	case "bugcrowd":
		return "> **Submission target:** Bugcrowd. Use the *VRT* category that aligns with the CWE listed under *Vulnerability Details*.\n\n"
	case "intigriti":
		return "> **Submission target:** Intigriti. Map the CWE listed under *Vulnerability Details* to the matching Intigriti severity guideline.\n\n"
	}
	return ""
}

// PlatformFieldMapping returns the canonical Auto Bughunter section -> platform
// field mapping used by the bug-bounty template engine.
func PlatformFieldMapping(platform string) map[string]string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "hackerone":
		return map[string]string{
			"Asset":                 "affected_endpoints",
			"Impact":                "impact",
			"Proof of Concept":      "steps_to_reproduce",
			"Summary":               "weakness_description",
			"Suggested Remediation": "suggested_fix",
			"Title":                 "title",
			"Vulnerability Details": "vulnerability_information",
		}
	case "bugcrowd":
		return map[string]string{
			"Asset":                 "target",
			"Impact":                "business_impact",
			"Proof of Concept":      "steps_to_reproduce",
			"Summary":               "vulnerability_summary",
			"Suggested Remediation": "remediation_recommendation",
			"Title":                 "submission_title",
			"Vulnerability Details": "vrt_vulnerability_type",
		}
	case "intigriti":
		return map[string]string{
			"Asset":                 "asset",
			"Impact":                "impact",
			"Proof of Concept":      "reproduction_steps",
			"Summary":               "summary",
			"Suggested Remediation": "recommendation",
			"Title":                 "title",
			"Vulnerability Details": "vulnerability_type",
		}
	default:
		return nil
	}
}

var safeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// safeFilename produces a filesystem-safe filename component from an
// arbitrary string by replacing all non-alphanumeric characters with `-` and
// trimming leading/trailing separators.
func safeFilename(s string) string {
	if s == "" {
		return "finding"
	}
	cleaned := safeFilenameRe.ReplaceAllString(s, "-")
	cleaned = strings.Trim(cleaned, "-_.")
	if cleaned == "" {
		return "finding"
	}
	if len(cleaned) > 80 {
		cleaned = cleaned[:80]
	}
	return cleaned
}

// RenderBugBountyZip produces a zip archive containing one Markdown
// submission file per finding plus a top-level `INDEX.md` summary.
func RenderBugBountyZip(job *model.ScanJob) ([]byte, error) {
	return RenderBugBountyZipForPlatform(job, "")
}

// RenderBugBountyZipForPlatform is the platform-aware variant of
// RenderBugBountyZip. The platform value is included in the index banner and
// each submission file when supplied.
func RenderBugBountyZipForPlatform(job *model.ScanJob, platform string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	target := ""
	var pack *model.ProgramProfilePack
	if job != nil {
		target = job.Target
		pack = job.Options.ProgramProfilePack
	}

	if job != nil && job.CoverageMap != nil {
		raw, err := json.MarshalIndent(job.CoverageMap, "", "  ")
		if err == nil {
			cmWriter, err := zw.Create("COVERAGE_MAP.json")
			if err != nil {
				return nil, err
			}
			if _, err := cmWriter.Write(raw); err != nil {
				return nil, err
			}
		}
		heatmap := renderCoverageHeatmapMarkdown(job.CoverageMap)
		if strings.TrimSpace(heatmap) != "" {
			hmWriter, err := zw.Create("COVERAGE_HEATMAP.md")
			if err != nil {
				return nil, err
			}
			if _, err := hmWriter.Write([]byte(heatmap)); err != nil {
				return nil, err
			}
		}
	}

	var index strings.Builder
	index.WriteString("# Bug Bounty Submission Bundle\n\n")
	if banner := platformBanner(platform); banner != "" {
		index.WriteString(banner)
	}

	if job != nil {
		index.WriteString("**Target:** " + job.Target + "  \n")
		index.WriteString("**Scan ID:** " + job.ID + "  \n")
		index.WriteString("\n")
	}
	index.WriteString("| # | Severity | Title | BountyScore | Payout Estimate | Ranking Rationale | File |\n")
	index.WriteString("|---|----------|-------|-------------|-----------------|-------------------|------|\n")

	if job != nil {
		findings := impact.RankFindingsWithPack(job.Findings, job.Options.ImpactGoals, pack)
		for i, f := range findings {
			fname := fmt.Sprintf("%02d-%s-%s.md", i+1, strings.ToLower(string(f.Severity)), safeFilename(f.ID))
			content := RenderBugBountyMarkdownForPlatform(f, target, platform)
			fileWriter, err := zw.Create(fname)
			if err != nil {
				return nil, err
			}
			if _, err := fileWriter.Write([]byte(content)); err != nil {
				return nil, err
			}
			payoutEst := payoutEstimate(f, pack)
			rationale := payoutRationale(f, i+1, pack)
			bountyStr := ""
			if f.BountyScore > 0 {
				bountyStr = fmt.Sprintf("%.2f", f.BountyScore)
			}
			index.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s | %s |\n",
				i+1, sevDisplay(f.Severity), f.Title, bountyStr, payoutEst, rationale, fname))
		}
	}

	idxWriter, err := zw.Create("INDEX.md")
	if err != nil {
		return nil, err
	}
	if _, err := idxWriter.Write([]byte(index.String())); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// payoutEstimate returns a human-readable estimated payout string for a
// finding using the ProgramProfilePack's EstimatedPayoutUSD map. Returns an
// empty string when no estimate is available.
func payoutEstimate(f model.Finding, pack *model.ProgramProfilePack) string {
	if pack == nil || len(pack.EstimatedPayoutUSD) == 0 {
		return ""
	}
	cat := strings.ToLower(strings.TrimSpace(f.Category))
	if amt, ok := pack.EstimatedPayoutUSD[cat]; ok && amt > 0 {
		return fmt.Sprintf("$%.0f", amt)
	}
	return ""
}

// payoutRationale builds a brief ranking rationale string for the INDEX.md
// table, explaining the top contributing factors to the finding's rank.
func payoutRationale(f model.Finding, rank int, pack *model.ProgramProfilePack) string {
	parts := []string{fmt.Sprintf("Ranked #%d", rank)}
	if len(f.ImpactGoals) > 0 {
		parts = append(parts, strings.ReplaceAll(string(f.ImpactGoals[0]), "_", " ")+" goal match")
	}
	if f.BountyScore > 0 {
		parts = append(parts, fmt.Sprintf("BountyScore %.2f", f.BountyScore))
	}
	if pack != nil && len(pack.EstimatedPayoutUSD) > 0 {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if amt, ok := pack.EstimatedPayoutUSD[cat]; ok && amt > 0 {
			parts = append(parts, fmt.Sprintf("est. $%.0f", amt))
		}
	}
	return strings.Join(parts, " — ")
}

func renderCoverageHeatmapMarkdown(cm *model.CoverageMap) string {
	if cm == nil || len(cm.Areas) == 0 {
		return ""
	}
	areas := append([]model.CoverageMapArea(nil), cm.Areas...)
	sort.SliceStable(areas, func(i, j int) bool {
		if areas[i].ROIScore == areas[j].ROIScore {
			return areas[i].Key < areas[j].Key
		}
		return areas[i].ROIScore > areas[j].ROIScore
	})
	var b strings.Builder
	b.WriteString("# Coverage Heatmap\n\n")
	b.WriteString(fmt.Sprintf("- **Target:** %s\n", cm.Target))
	b.WriteString(fmt.Sprintf("- **Generated At:** %s\n", cm.GeneratedAt.UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- **Coverage Ratio:** %.2f\n\n", cm.CoverageRatio))
	b.WriteString("| Surface | Type | ROI | Probed | Source |\n")
	b.WriteString("|---|---|---:|:---:|---|\n")
	limit := len(areas)
	if limit > 50 {
		limit = 50
	}
	for _, area := range areas[:limit] {
		probed := "❌"
		if area.Probed {
			probed = "✅"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %.2f | %s | %s |\n", area.Key, area.Type, area.ROIScore, probed, area.Source))
	}
	return b.String()
}
