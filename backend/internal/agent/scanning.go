package agent

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type ScanningAgent struct {
	scanService *scanner.Service
	enabled     bool
}

func NewScanningAgent(scanService *scanner.Service, enabled bool) *ScanningAgent {
	return &ScanningAgent{
		scanService: scanService,
		enabled:     enabled,
	}
}

func (a *ScanningAgent) Name() string {
	return "scanning"
}

func (a *ScanningAgent) Enabled() bool {
	return a.enabled
}

func (a *ScanningAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	findings, err := a.scanService.Run(ctx, scanner.RunInput{
		Target:      input.Target,
		AuthProfile: input.AuthProfile,
		Options:     input.Options,
		Scope:       input.Scope,
		Emit:        input.Emit,
	})
	if err != nil {
		if hasAuth(input.AuthProfile) {
			unauthFindings, fallbackErr := a.scanService.Run(ctx, scanner.RunInput{
				Target:      input.Target,
				AuthProfile: model.ScanAuthProfile{},
				Options:     input.Options,
				Scope:       input.Scope,
				Emit:        input.Emit,
			})
			if fallbackErr == nil {
				output.Findings = append(output.Findings, unauthFindings...)
				output.Findings = append(output.Findings, model.Finding{
					ID:             "auth-coverage-gap-fallback",
					Category:       "coverage",
					Severity:       model.SeverityMedium,
					Title:          "Authenticated scan fallback triggered",
					Description:    "Primary scan path failed with provided authentication profile; unauthenticated fallback completed to preserve partial coverage.",
					Evidence:       err.Error(),
					Recommendation: "Validate authentication material and rerun to regain full authenticated coverage.",
					Confidence:     0.93,
					Sources:        []string{"scanner"},
					DriftStatus:    "new",
					EvidenceFields: map[string]string{
						"mode": "authenticated->unauthenticated-fallback",
					},
					BusinessTags: []string{"auth-required"},
					Exploitability: &model.Exploitability{
						Reachable:       true,
						RequiredRole:    "authenticated-user",
						Prerequisites:   []string{"valid_session_or_token"},
						AttackPathHints: []string{"restore-auth-profile", "rerun-authenticated-scan"},
					},
				})
				output.Metadata["auth_fallback"] = "used"
				output.Metadata["targets_attempted"] = "1"
				output.Metadata["targets_skipped"] = "0"
				output.DebugNotes = "Built-in security checks executed with unauthenticated fallback."
				return output, nil
			}
		}
		return output, err
	}

	output.Findings = findings
	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(findings))
	attempted, skipped, reasons := extractCoverageTelemetry(findings)
	if attempted == 0 {
		attempted = 1
	}
	output.Metadata["targets_attempted"] = fmt.Sprintf("%d", attempted)
	output.Metadata["targets_skipped"] = fmt.Sprintf("%d", skipped)
	if len(reasons) > 0 {
		output.Metadata["skipped_reasons"] = strings.Join(reasons, ",")
	}
	if hasAuth(input.AuthProfile) {
		output.Metadata["auth_mode"] = "authenticated"
	} else {
		output.Metadata["auth_mode"] = "unauthenticated"
	}
	if input.Options.AggressiveExploitation {
		output.Metadata["aggressive_exploitation"] = "true"
	}
	output.DebugNotes = "Built-in security checks executed."
	return output, nil
}

func hasAuth(profile model.ScanAuthProfile) bool {
	return len(profile.Headers) > 0 ||
		len(profile.Cookies) > 0 ||
		strings.TrimSpace(profile.BasicAuthUsername) != "" ||
		strings.TrimSpace(profile.BasicAuthPassword) != "" ||
		(strings.TrimSpace(profile.Username) != "" && strings.TrimSpace(profile.Password) != "")
}

func extractCoverageTelemetry(findings []model.Finding) (int, int, []string) {
	attempted := 0
	skipped := 0
	reasonsSet := map[string]struct{}{}
	for _, f := range findings {
		if f.ID != "integration-coverage-telemetry" {
			continue
		}
		if v, ok := f.EvidenceFields["targetsAttempted"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil {
				attempted += parsed
			}
		}
		if v, ok := f.EvidenceFields["targetsSkipped"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil {
				skipped += parsed
			}
		}
		if v, ok := f.EvidenceFields["skippedReasons"]; ok && strings.TrimSpace(v) != "" {
			for _, reason := range strings.Split(v, ",") {
				r := strings.TrimSpace(reason)
				if r != "" {
					reasonsSet[r] = struct{}{}
				}
			}
		}
	}
	reasons := make([]string, 0, len(reasonsSet))
	for r := range reasonsSet {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return attempted, skipped, reasons
}
