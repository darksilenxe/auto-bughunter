package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// SARIF (Static Analysis Results Interchange Format) v2.1.0 export.
// See https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//
// We model only the subset of SARIF needed to describe scan findings, so
// downstream tools (GitHub code scanning, Microsoft Defender, etc.) can
// ingest the report directly.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool          `json:"tool"`
	Results     []sarifResult      `json:"results"`
	Invocations []sarifInvocation  `json:"invocations,omitempty"`
	Properties  map[string]any     `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name,omitempty"`
	ShortDescription     *sarifMessage           `json:"shortDescription,omitempty"`
	FullDescription      *sarifMessage           `json:"fullDescription,omitempty"`
	HelpURI              string                  `json:"helpUri,omitempty"`
	Help                 *sarifMessage           `json:"help,omitempty"`
	DefaultConfiguration *sarifConfiguration     `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any          `json:"properties,omitempty"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex,omitempty"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

// severityToSARIFLevel maps internal severity to a SARIF level. SARIF accepts
// "none", "note", "warning", or "error".
func severityToSARIFLevel(s model.Severity) string {
	switch s {
	case model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow:
		return "note"
	case model.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// buildSARIF converts a ScanJob into a SARIF v2.1.0 document.
func buildSARIF(job *model.ScanJob) sarifLog {
	rulesIndex := map[string]int{}
	rules := make([]sarifRule, 0)
	results := make([]sarifResult, 0, len(job.Findings))

	// Stable ordering for reproducible output.
	findings := make([]model.Finding, len(job.Findings))
	copy(findings, job.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRankSARIF(findings[i].Severity) > severityRankSARIF(findings[j].Severity)
		}
		return findings[i].ID < findings[j].ID
	})

	for _, f := range findings {
		ruleID := sanitizeRuleID(f.Category, f.Title)
		idx, ok := rulesIndex[ruleID]
		if !ok {
			idx = len(rules)
			rulesIndex[ruleID] = idx
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &sarifMessage{Text: nonEmpty(f.Title, f.Category)},
				FullDescription:  &sarifMessage{Text: nonEmpty(f.Description, f.Title)},
				Help:             &sarifMessage{Text: nonEmpty(f.Recommendation, "See finding details for remediation guidance.")},
				DefaultConfiguration: &sarifConfiguration{
					Level: severityToSARIFLevel(f.Severity),
				},
				Properties: map[string]any{
					"category":  f.Category,
					"tags":      []string{"security", strings.ToLower(string(f.Severity))},
					"precision": precisionFromConfidence(f.Confidence),
				},
			})
		}

		props := map[string]any{
			"category": f.Category,
			"severity": string(f.Severity),
		}
		if f.Confidence > 0 {
			props["confidence"] = f.Confidence
		}
		if len(f.Sources) > 0 {
			props["sources"] = f.Sources
		}
		if f.DriftStatus != "" {
			props["driftStatus"] = f.DriftStatus
		}
		if len(f.BusinessTags) > 0 {
			props["businessTags"] = f.BusinessTags
		}
		if f.Exploitability != nil {
			props["exploitability"] = f.Exploitability
		}

		msgText := f.Description
		if msgText == "" {
			msgText = f.Title
		}
		if f.Evidence != "" {
			msgText = msgText + "\n\nEvidence: " + truncate(f.Evidence, 4000)
		}

		results = append(results, sarifResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: msgText},
			Locations: []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: locationForFinding(f, job.Target)},
				}},
			},
			Properties: props,
		})
	}

	invocations := []sarifInvocation{}
	if !job.StartedAt.IsZero() {
		inv := sarifInvocation{
			ExecutionSuccessful: job.Status != "failed",
			StartTimeUTC:        job.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		}
		if job.CompletedAt != nil {
			inv.EndTimeUTC = job.CompletedAt.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		invocations = append(invocations, inv)
	}

	return sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "auto-bughunter",
						InformationURI: "https://github.com/darksilenxe/auto-bughunter",
						Rules:          rules,
					},
				},
				Results:     results,
				Invocations: invocations,
				Properties: map[string]any{
					"target":    job.Target,
					"scanId":    job.ID,
					"status":    job.Status,
					"createdAt": job.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
				},
			},
		},
	}
}

func severityRankSARIF(s model.Severity) int {
	switch s {
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	}
	return 0
}

func precisionFromConfidence(c float64) string {
	switch {
	case c >= 0.9:
		return "very-high"
	case c >= 0.75:
		return "high"
	case c >= 0.5:
		return "medium"
	case c > 0:
		return "low"
	default:
		return "medium"
	}
}

func sanitizeRuleID(category, title string) string {
	cat := strings.ToLower(strings.TrimSpace(category))
	if cat == "" {
		cat = "finding"
	}
	t := strings.ToLower(strings.TrimSpace(title))
	if t == "" {
		t = "issue"
	}
	out := make([]rune, 0, len(cat)+1+len(t))
	for _, r := range cat + "/" + t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '/', r == '-':
			out = append(out, r)
		case r == ' ', r == '_':
			out = append(out, '-')
		}
	}
	return strings.Trim(string(out), "-/")
}

func locationForFinding(f model.Finding, fallback string) string {
	if f.EvidenceFields != nil {
		for _, key := range []string{"url", "endpoint", "uri", "target", "host"} {
			if v, ok := f.EvidenceFields[key]; ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	if fallback != "" {
		return fallback
	}
	return "unknown"
}

func nonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// handleScanSARIF returns the scan findings rendered as a SARIF v2.1.0
// document so they can be uploaded to GitHub code scanning or any other
// SARIF-aware sink. GET /api/scan/{id}/sarif
func (s *Server) handleScanSARIF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Path is /api/scan/{id}/sarif
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	id := strings.TrimSuffix(trimmed, "/sarif")
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid scan id"})
		return
	}

	job, err := s.repo.GetJob(r.Context(), id)
	if err != nil || job == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	doc := buildSARIF(job)
	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Content-Disposition", `attachment; filename="scan-`+id+`.sarif.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		// Header is already written for content-type; best effort.
		return
	}
}
