package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/toolclient"
)

func (s *Service) runNuclei(ctx context.Context, target string) []model.Finding {
	// Try HTTP service first when explicitly enabled, and also auto-fallback to
	// the HTTP wrapper when the local exec path is unavailable but the service
	// is healthy. This keeps the default sidecar-based deployment working even
	// when the backend image omits docker-cli for legacy exec-mode shims.
	if s.shouldRunNucleiViaHTTP(ctx) {
		return s.runNucleiHTTP(ctx, target)
	}
	return s.runNucleiExec(ctx, target)
}

func (s *Service) shouldRunNucleiViaHTTP(ctx context.Context) bool {
	if httpToolServicesEnabled() {
		return true
	}
	if commandPreflight(ctx, s.cfg.NucleiBinary, "-version") {
		return false
	}
	client := toolclient.NewNucleiClient()
	return serviceHealthCheck(ctx, client.IsAvailable)
}

func (s *Service) runNucleiHTTP(ctx context.Context, target string) []model.Finding {
	budget, ok := s.heavyToolBudget(ctx)
	if !ok {
		return []model.Finding{heavyToolBudgetExceededFinding("nuclei", "Nuclei", target)}
	}

	client := toolclient.NewNucleiClient()

	// Check if service is available
	if !client.IsAvailable(ctx) {
		return []model.Finding{{
			ID:             "nuclei-service-unavailable",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei HTTP service unavailable",
			Description:    "Nuclei HTTP wrapper service is not reachable.",
			Evidence:       "service_url=" + os.Getenv("NUCLEI_SERVICE_URL"),
			Recommendation: "Ensure nuclei-service container is running and healthy.",
		}}
	}

	timeoutSecs := int(budget.Seconds())
	args := []string{"-u", target, "-severity", "medium,high,critical", "-silent"}
	if s.scannerProxy.Enabled && strings.TrimSpace(s.scannerProxy.URL) != "" {
		args = append(args, "-proxy", s.scannerProxy.URL)
	}

	result, err := client.Execute(ctx, args, timeoutSecs)
	if err != nil {
		if ctx.Err() != nil {
			return []model.Finding{{
				ID:             "nuclei-timeout",
				Category:       "integration",
				Severity:       model.SeverityLow,
				Title:          "Nuclei integration timed out",
				Description:    "Nuclei did not complete before the overall scan context ended.",
				Evidence:       "requested_timeout=" + budget.String(),
				Recommendation: "Increase SCAN_TIMEOUT_SECONDS, reduce scan scope, or disable earlier optional integrations.",
			}}
		}
		return []model.Finding{{
			ID:             "nuclei-http-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei HTTP service error",
			Description:    "Failed to execute nuclei via HTTP service.",
			Evidence:       err.Error(),
			Recommendation: "Check nuclei-service logs and retry.",
		}}
	}

	if result.TimedOut {
		return []model.Finding{{
			ID:             "nuclei-timeout",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei integration timed out",
			Description:    "Nuclei did not complete before the integration timeout.",
			Evidence:       "timeout=" + budget.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	lines := countNonEmptyLines(result.Stdout)
	if result.ExitCode != 0 && lines == 0 {
		return []model.Finding{{
			ID:             "nuclei-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei integration failed",
			Description:    "Nuclei did not complete successfully.",
			Evidence:       strings.TrimSpace(result.Stderr + "\n" + result.Stdout),
			Recommendation: "Validate nuclei templates/network access and rerun.",
		}}
	}

	severity := model.SeverityInfo
	title := "Nuclei integration found no reported issues"
	if lines > 0 {
		severity = model.SeverityMedium
		title = "Nuclei integration reported potential issues"
	}

	evidence := "matches=" + strconv.Itoa(lines) + " (via HTTP service)"

	return []model.Finding{{
		ID:             "nuclei-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Optional Nuclei integration executed with medium/high/critical severity scope via HTTP service.",
		Evidence:       evidence,
		Recommendation: "Review raw tool output in logs and validate each reported item before remediation.",
	}}
}

func (s *Service) runNucleiExec(ctx context.Context, target string) []model.Finding {
	budget, ok := s.heavyToolBudget(ctx)
	if !ok {
		return []model.Finding{heavyToolBudgetExceededFinding("nuclei", "Nuclei", target)}
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

	ictx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	args := []string{"-u", target, "-severity", "medium,high,critical", "-silent"}
	if s.scannerProxy.Enabled && strings.TrimSpace(s.scannerProxy.URL) != "" {
		args = append(args, "-proxy", s.scannerProxy.URL)
	}
	cmd := exec.CommandContext(ictx, s.cfg.NucleiBinary, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(ictx.Err(), context.DeadlineExceeded) {
		return []model.Finding{{
			ID:             "nuclei-timeout",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei integration timed out",
			Description:    "Nuclei did not complete before the integration timeout.",
			Evidence:       "timeout=" + budget.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}
	lines := countNonEmptyLines(stdout.String())
	if err != nil && lines == 0 {
		return []model.Finding{{
			ID:             "nuclei-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Nuclei integration failed",
			Description:    "Nuclei did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String() + "\n" + stdout.String()),
			Recommendation: "Validate nuclei templates/network access and rerun.",
		}}
	}

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
	// Try HTTP service first when explicitly enabled, and also auto-fallback to
	// the HTTP wrapper when the local exec path is unavailable but the service
	// is healthy. This avoids false runtime failures from shim binaries that are
	// present on PATH but cannot reach docker compose from the backend image.
	if s.shouldRunZAPBaselineViaHTTP(ctx) {
		return s.runZAPBaselineHTTP(ctx, target)
	}
	return s.runZAPBaselineExec(ctx, target)
}

func (s *Service) shouldRunZAPBaselineViaHTTP(ctx context.Context) bool {
	if httpToolServicesEnabled() {
		return true
	}
	if commandPreflight(ctx, s.cfg.ZAPBaselineBinary, "-h") {
		return false
	}
	client := toolclient.NewZapClient()
	return serviceHealthCheck(ctx, client.IsAvailable)
}

func (s *Service) runZAPBaselineHTTP(ctx context.Context, target string) []model.Finding {
	budget, ok := s.heavyToolBudget(ctx)
	if !ok {
		return []model.Finding{heavyToolBudgetExceededFinding("zap-baseline", "ZAP Baseline", target)}
	}

	client := toolclient.NewZapClient()

	// Check if service is available
	if !client.IsAvailable(ctx) {
		serviceURL := os.Getenv("ZAP_SERVICE_URL")
		if serviceURL == "" {
			serviceURL = "http://zap-service:8094"
		}
		return []model.Finding{{
			ID:             "zap-baseline-service-unavailable",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline HTTP service unavailable",
			Description:    "ZAP Baseline HTTP wrapper service is not reachable.",
			Evidence:       "service_url=" + serviceURL,
			Recommendation: "Ensure zap-service container is running and healthy.",
		}}
	}

	timeoutSecs := int(budget.Seconds())
	args := []string{"-t", target, "-m", "1", "-I"}

	result, err := client.Execute(ctx, args, timeoutSecs)
	if err != nil {
		if ctx.Err() != nil {
			return []model.Finding{{
				ID:             "zap-baseline-timeout",
				Category:       "integration",
				Severity:       model.SeverityLow,
				Title:          "ZAP Baseline integration timed out",
				Description:    "ZAP Baseline did not complete before the overall scan context ended.",
				Evidence:       "requested_timeout=" + budget.String(),
				Recommendation: "Increase SCAN_TIMEOUT_SECONDS, reduce scan scope, or disable earlier optional integrations.",
			}}
		}
		return []model.Finding{{
			ID:             "zap-baseline-http-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline HTTP service error",
			Description:    "Failed to execute zap-baseline.py via HTTP service.",
			Evidence:       err.Error(),
			Recommendation: "Check zap-service logs and retry.",
		}}
	}

	if result.TimedOut {
		return []model.Finding{{
			ID:             "zap-baseline-timeout",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline integration timed out",
			Description:    "ZAP Baseline did not complete before the integration timeout.",
			Evidence:       "timeout=" + budget.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	return buildZAPBaselineFinding(result.Stdout, result.Stderr, result.ExitCode, " (via HTTP service)")
}

func (s *Service) runZAPBaselineExec(ctx context.Context, target string) []model.Finding {
	budget, ok := s.heavyToolBudget(ctx)
	if !ok {
		return []model.Finding{heavyToolBudgetExceededFinding("zap-baseline", "ZAP Baseline", target)}
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

	ictx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.ZAPBaselineBinary, "-t", target, "-m", "1", "-I")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(ictx.Err(), context.DeadlineExceeded) {
		return []model.Finding{{
			ID:             "zap-baseline-timeout",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline integration timed out",
			Description:    "ZAP Baseline did not complete before the integration timeout.",
			Evidence:       "timeout=" + budget.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}
	// zap-baseline.py exits non-zero when it finds WARN/FAIL markers (by design).
	// buildZAPBaselineFinding parses output content to distinguish a real execution
	// error (empty stdout) from expected non-zero exit with actual findings.
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	return buildZAPBaselineFinding(stdout.String(), stderr.String(), exitCode, "")
}

// zapMarkerCountRe matches a ZAP baseline marker label immediately followed by
// a numeric count, e.g. "FAIL-NEW: 0" or "WARN-NEW: 4". Per-alert detail lines
// (e.g. "WARN-NEW: Cross-Domain ... [10017] x 3") are followed by descriptive
// text rather than a bare number, so they never match this pattern.
var zapMarkerCountRe = regexp.MustCompile(`(?i)(FAIL-NEW|FAIL-INPROG|WARN-NEW|WARN-INPROG):\s*(\d+)`)

// countZAPBaselineMarkers parses zap-baseline.py output to count actual FAIL and
// WARN markers. zap-baseline.py prints a summary footer line of the form:
//
//	FAIL-NEW: 0  FAIL-INPROG: 0  WARN-NEW: 4  WARN-INPROG: 0  INFO: 0  IGNORE: 0  PASS: 50
//
// where each label is followed by a numeric count. Naively counting the
// substrings "FAIL-"/"WARN-" is wrong because those label headers are always
// present in the footer (even with zero findings), which caused a false
// High-severity "fail markers" finding on every run. We instead read the
// numeric counts from the summary footer. When the footer is missing (e.g.
// truncated/aborted output) we fall back to counting per-alert marker lines.
func countZAPBaselineMarkers(outText string) (fails, warns int) {
	for _, line := range strings.Split(outText, "\n") {
		upper := strings.ToUpper(line)
		// The summary footer uniquely lists every marker bucket including PASS.
		if strings.Contains(upper, "FAIL-NEW:") && strings.Contains(upper, "PASS:") {
			for _, m := range zapMarkerCountRe.FindAllStringSubmatch(line, -1) {
				n, err := strconv.Atoi(m[2])
				if err != nil {
					continue
				}
				switch strings.ToUpper(m[1]) {
				case "FAIL-NEW", "FAIL-INPROG":
					fails += n
				case "WARN-NEW", "WARN-INPROG":
					warns += n
				}
			}
			return fails, warns
		}
	}
	// Fallback: no summary footer present. Count per-alert marker lines directly.
	for _, line := range strings.Split(outText, "\n") {
		trimmed := strings.TrimSpace(strings.ToUpper(line))
		switch {
		case strings.HasPrefix(trimmed, "FAIL-NEW:"), strings.HasPrefix(trimmed, "FAIL-INPROG:"):
			fails++
		case strings.HasPrefix(trimmed, "WARN-NEW:"), strings.HasPrefix(trimmed, "WARN-INPROG:"):
			warns++
		}
	}
	return fails, warns
}

func buildZAPBaselineFinding(outText, errText string, exitCode int, evidenceSuffix string) []model.Finding {
	fails, warns := countZAPBaselineMarkers(outText)
	if exitCode != 0 && warns == 0 && fails == 0 && strings.TrimSpace(outText) == "" {
		return []model.Finding{{
			ID:             "zap-baseline-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline integration failed",
			Description:    "ZAP Baseline did not complete successfully.",
			Evidence:       strings.TrimSpace(errText + "\n" + outText),
			Recommendation: "Validate ZAP runtime dependencies and rerun.",
		}}
	}

	severity := model.SeverityInfo
	title := "ZAP Baseline integration found no warning markers"
	if fails > 0 {
		severity = model.SeverityHigh
		title = "ZAP Baseline integration reported fail markers"
	} else if warns > 0 {
		severity = model.SeverityMedium
		title = "ZAP Baseline integration reported warning markers"
	}

	return []model.Finding{{
		ID:             "zap-baseline-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Optional OWASP ZAP Baseline integration executed in passive mode.",
		Evidence:       "failMarkers=" + strconv.Itoa(fails) + ", warnMarkers=" + strconv.Itoa(warns) + evidenceSuffix,
		Recommendation: "Review full ZAP baseline report and verify findings before remediation.",
	}}
}

func httpToolServicesEnabled() bool {
	useHTTPMode := os.Getenv("USE_HTTP_TOOL_SERVICES")
	return useHTTPMode == "true" || useHTTPMode == "1"
}

func commandPreflight(parent context.Context, binary string, args ...string) bool {
	if strings.TrimSpace(binary) == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(parent, integrationPreflightTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func serviceHealthCheck(parent context.Context, check func(context.Context) bool) bool {
	ctx, cancel := context.WithTimeout(parent, integrationPreflightTimeout)
	defer cancel()
	return check(ctx)
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
