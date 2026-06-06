package scanner

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/toolclient"
)

// semgrepSeverity maps semgrep severity strings to model.Severity.
func semgrepSeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR", "HIGH", "CRITICAL":
		return model.SeverityHigh
	case "WARNING", "MEDIUM":
		return model.SeverityMedium
	case "INFO", "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// RunSemgrepSAST sends a source-code snippet to the Semgrep sidecar and maps
// the results to model.Finding values with Category "sast".
//
// This is a best-effort integration: when the semgrep service is unavailable or
// returns no findings the caller receives an empty slice (no error surfaced).
// The scanner never blocks a scan on an unavailable sidecar.
func (s *Service) RunSemgrepSAST(ctx context.Context, snippet, language string) []model.Finding {
	if !s.cfg.EnableSemgrep {
		return nil
	}
	if strings.TrimSpace(snippet) == "" {
		return nil
	}

	client := toolclient.NewSemgrepClient()
	if !client.IsAvailable(ctx) {
		return nil
	}

	timeoutSecs := int(s.cfg.IntegrationTimeout.Seconds())
	if timeoutSecs <= 0 {
		timeoutSecs = 60
	}

	result, err := client.Scan(ctx, snippet, language, timeoutSecs)
	if err != nil || result == nil {
		return nil
	}
	if result.TimedOut || result.Error != "" {
		return nil
	}

	findings := make([]model.Finding, 0, len(result.Findings))
	for i, sf := range result.Findings {
		ruleID := strings.TrimSpace(sf.RuleID)
		if ruleID == "" {
			ruleID = fmt.Sprintf("semgrep-rule-%d", i)
		}
		lang := strings.TrimSpace(sf.Language)
		if lang == "" {
			lang = language
		}

		findings = append(findings, model.Finding{
			ID:             fmt.Sprintf("semgrep-%s-%d", ruleID, sf.Line),
			Category:       "sast",
			Severity:       semgrepSeverity(sf.Severity),
			Title:          fmt.Sprintf("Semgrep: %s", ruleID),
			Description:    sf.Message,
			Evidence:       fmt.Sprintf("rule=%s language=%s line=%d", ruleID, lang, sf.Line),
			Recommendation: "Review the flagged code construct. Consult the Semgrep rule documentation for remediation guidance.",
		})
	}
	return findings
}
