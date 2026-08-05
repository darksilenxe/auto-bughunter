package report

import (
	"encoding/json"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// sarifVersion is the SARIF schema version emitted by RenderSARIF.
const sarifVersion = "2.1.0"

// sarifSchema is the canonical SARIF 2.1.0 JSON schema URL.
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// SARIF object model (minimal subset sufficient for findings interchange with
// GitHub code scanning, DefectDojo, and other SARIF consumers).
type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription sarifText              `json:"shortDescription"`
	FullDescription  sarifText              `json:"fullDescription,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Help             *sarifText             `json:"help,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifFix struct {
	Description    sarifText            `json:"description"`
	ArtifactChanges []sarifArtifactChange `json:"artifactChanges,omitempty"`
}

type sarifArtifactChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements,omitempty"`
}

type sarifReplacement struct {
	DeletedRegion sarifRegion `json:"deletedRegion"`
	InsertedContent sarifText  `json:"insertedContent,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifResult struct {
	RuleID           string                 `json:"ruleId"`
	Level            string                 `json:"level"`
	Message          sarifText              `json:"message"`
	Locations        []sarifLocation        `json:"locations,omitempty"`
	RelatedLocations []sarifRelatedLocation `json:"relatedLocations,omitempty"`
	Fixes            []sarifFix             `json:"fixes,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifRelatedLocation struct {
	ID               int                   `json:"id"`
	Message          sarifText             `json:"message,omitempty"`
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// RenderSARIF produces a SARIF 2.1.0 document from the scan findings, suitable
// for upload to GitHub code scanning or ingestion by SARIF-aware triage tools.
// It is safe to call with a nil job.
func RenderSARIF(job *model.ScanJob, opts model.ReportTemplateOptions, ctx ...ReportContext) ([]byte, error) {
	findings := reportFindings(job)

	rulesByID := map[string]bool{}
	rules := make([]sarifRule, 0, len(findings))
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := sarifRuleID(f)
		if !rulesByID[ruleID] {
			rulesByID[ruleID] = true
			rule := sarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: sarifText{Text: nonEmpty(f.Title, ruleID)},
				FullDescription:  sarifText{Text: f.Description},
				Properties:       map[string]interface{}{},
			}
			// Build a rich tags list from CWE, OWASP, and MITRE techniques.
			tags := make([]string, 0, 4)
			if f.CWE != "" {
				rule.Properties["cwe"] = f.CWE
				tags = append(tags, f.CWE)
			}
			if f.OWASPCategory != "" {
				rule.Properties["owasp"] = f.OWASPCategory
				tags = append(tags, f.OWASPCategory)
			}
			for _, t := range f.MITRETechniques {
				tags = append(tags, t)
			}
			if len(tags) > 0 {
				rule.Properties["tags"] = tags
			}
			// Populate the human-readable help text with the recommendation so
			// SARIF consumers (GitHub Code Scanning, DefectDojo) surface it.
			if f.Recommendation != "" {
				rule.Help = &sarifText{Text: f.Recommendation}
			} else if len(f.ReproductionSteps) > 0 {
				rule.Help = &sarifText{Text: strings.Join(f.ReproductionSteps, " | ")}
			}
			rules = append(rules, rule)
		}

		res := sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: sarifMessage(f)},
			Properties: map[string]interface{}{
				"severity":   string(f.Severity),
				"confidence": f.Confidence,
				"category":   f.Category,
			},
		}
		if f.StableFingerprint != "" {
			res.Properties["stableFingerprint"] = f.StableFingerprint
		}
		if f.TimeToExploit != "" {
			res.Properties["timeToExploit"] = f.TimeToExploit
		}
		if uri := nonEmpty(f.AffectedURL, jobTarget(job)); uri != "" {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}}
		}
		// relatedLocations: add the affected parameter as a second location
		// so reviewers can see exactly where the vulnerable input is.
		if f.AffectedParameter != "" && f.AffectedURL != "" {
			res.RelatedLocations = []sarifRelatedLocation{{
				ID:      1,
				Message: sarifText{Text: "Vulnerable parameter: " + f.AffectedParameter},
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.AffectedURL},
				},
			}}
		}
		// fixes: populate from ReproductionSteps/Recommendation so GitHub
		// Code Scanning and other SARIF consumers can surface remediation hints.
		if f.Recommendation != "" {
			fix := sarifFix{
				Description: sarifText{Text: f.Recommendation},
			}
			res.Fixes = append(res.Fixes, fix)
		}
		if len(f.ReproductionSteps) > 0 && f.Recommendation == "" {
			fix := sarifFix{
				Description: sarifText{Text: strings.Join(f.ReproductionSteps, "; ")},
			}
			res.Fixes = append(res.Fixes, fix)
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "auto-bughunter",
				InformationURI: "https://github.com/darksilenxe/auto-bughunter",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

// sarifRuleID derives a stable rule identifier from the finding category and
// CWE so that repeated instances of the same issue class share a rule.
func sarifRuleID(f model.Finding) string {
	parts := make([]string, 0, 2)
	if c := strings.TrimSpace(f.Category); c != "" {
		parts = append(parts, c)
	}
	if cwe := strings.TrimSpace(f.CWE); cwe != "" {
		parts = append(parts, cwe)
	}
	if len(parts) == 0 {
		return nonEmpty(f.ID, "finding")
	}
	return strings.Join(parts, "/")
}

// sarifLevel maps an internal severity to a SARIF result level.
func sarifLevel(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow, model.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

func sarifMessage(f model.Finding) string {
	msg := f.Title
	if f.Evidence != "" {
		msg += " — " + f.Evidence
	}
	if msg == "" {
		msg = f.Description
	}
	return msg
}

func jobTarget(job *model.ScanJob) string {
	if job == nil {
		return ""
	}
	return job.Target
}

// reportFindings returns the findings to export, tolerating a nil job.
func reportFindings(job *model.ScanJob) []model.Finding {
	if job == nil {
		return nil
	}
	return job.Findings
}
