package scanner

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
)

func (s *Service) runOptionalIntegrations(ctx context.Context, input RunInput) []model.Finding {
	findings := []model.Finding{}
	if input.Options.UseNucleiIntegration {
		findings = append(findings, s.runNuclei(ctx, input.Target)...)
	}
	if input.Options.UseZAPBaselineIntegration {
		findings = append(findings, s.runZAPBaseline(ctx, input.Target)...)
	}
	return findings
}

func (s *Service) runNuclei(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableNuclei {
		return []model.Finding{{
			ID:             "nuclei-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Nuclei integration requested but disabled",
			Description:    "The job requested Nuclei but ENABLE_NUCLEI_INTEGRATION is false.",
			Evidence:       "ENABLE_NUCLEI_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.NucleiBinary); err != nil {
		return []model.Finding{{
			ID:             "nuclei-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei binary not found",
			Description:    "Nuclei integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install nuclei in the backend image or set NUCLEI_BINARY to a valid path.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.NucleiBinary, "-u", target, "-severity", "medium,high,critical", "-silent")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "nuclei-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei integration failed",
			Description:    "Nuclei did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate nuclei templates/network access and rerun.",
		}}
	}

	lines := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "Nuclei integration found no reported issues"
	if lines > 0 {
		severity = model.SeverityMedium
		title = "Nuclei integration reported potential issues"
	}

	evidence := "matches=" + strconv.Itoa(lines)

	return []model.Finding{{
		ID:             "nuclei-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Optional Nuclei integration executed with medium/high/critical severity scope.",
		Evidence:       evidence,
		Recommendation: "Review raw tool output in logs and validate each reported item before remediation.",
	}}
}

func (s *Service) runZAPBaseline(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableZAPBaseline {
		return []model.Finding{{
			ID:             "zap-baseline-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "ZAP Baseline integration requested but disabled",
			Description:    "The job requested ZAP Baseline but ENABLE_ZAP_BASELINE_INTEGRATION is false.",
			Evidence:       "ENABLE_ZAP_BASELINE_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.ZAPBaselineBinary); err != nil {
		return []model.Finding{{
			ID:             "zap-baseline-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline binary not found",
			Description:    "ZAP Baseline integration is enabled but command is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install zap-baseline.py or set ZAP_BASELINE_BINARY to a valid path.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.ZAPBaselineBinary, "-t", target, "-m", "1", "-I")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "zap-baseline-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline integration failed",
			Description:    "ZAP Baseline did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate ZAP runtime dependencies and rerun.",
		}}
	}

	warns := strings.Count(strings.ToUpper(stdout.String()), "WARN")
	severity := model.SeverityInfo
	title := "ZAP Baseline integration found no warning markers"
	if warns > 0 {
		severity = model.SeverityMedium
		title = "ZAP Baseline integration reported warning markers"
	}

	return []model.Finding{{
		ID:             "zap-baseline-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Optional OWASP ZAP Baseline integration executed in passive mode.",
		Evidence:       "warnMarkers=" + strconv.Itoa(warns),
		Recommendation: "Review full ZAP baseline report and verify findings before remediation.",
	}}
}

func countNonEmptyLines(s string) int {
	count := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}
