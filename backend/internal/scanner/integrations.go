package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/nikto"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
	"auto-bughunter/backend/internal/sqlmap"
	"auto-bughunter/backend/internal/wordlist"
	"auto-bughunter/backend/internal/wpscan"
)

// integrationState carries context discovered in earlier pipeline phases to later ones.
type integrationState struct {
	// DiscoveredHosts holds hostnames found by subfinder. They are used as additional
	// targets by httpx, naabu, and nuclei in subsequent phases.
	DiscoveredHosts  []string
	OutOfScopeHosts  []string
	TargetsAttempted int
	TargetsSkipped   int
	SkippedReasons   map[string]int
}

// runOptionalIntegrations executes the opted-in integrations in a dependency-aware order:
//
//	Phase 1 — Discovery:   subfinder, dnsx, shuffledns, certificate-transparency, amass(native-go)
//	Phase 2 — Port scan:   naabu  (target + discovered hosts)
//	Phase 3 — HTTP probe:  httpx  (target + discovered hosts)
//	Phase 4 — Crawling:    katana, ffuf, gobuster
//	Phase 5 — TLS/network: tlsx, cdncheck, asnmap
//	Phase 6 — CMS scan:    WPScan (native Go; auto-triggers if WordPress detected and enabled)
//	Phase 6b — Web scan:   Nikto  (native Go; full web application pen-test)
//	Phase 6c — SQL inject: SQLMap (native Go; error-based, boolean-blind, time-based blind)
//	Phase 7 — Vuln scan:   nuclei (target + discovered hosts), zap
func (s *Service) runOptionalIntegrations(ctx context.Context, input RunInput) []model.Finding {
	findings := []model.Finding{}
	state := &integrationState{SkippedReasons: map[string]int{}}

	emitCmd := func(tool, args string) {
		if input.Emit != nil {
			input.Emit(model.ScanEvent{
				Type:    model.ScanEventCommand,
				Command: tool + " " + args,
				Message: fmt.Sprintf("Running integration tool: %s", tool),
			})
		}
	}

	// Phase 1 — Subdomain & DNS discovery.
	if input.Options.UseSubfinderIntegration {
		emitCmd("subfinder", "-d "+input.Target)
		findings = append(findings, s.runSubfinder(ctx, input.Target, state)...)
	}
	if input.Options.UseDnsxIntegration {
		emitCmd("dnsx", "-d "+input.Target)
		findings = append(findings, s.runDnsx(ctx, input.Target)...)
	}
	if input.Options.UseShuffleDNSIntegration {
		emitCmd("shuffledns", "-d "+input.Target)
		findings = append(findings, s.runShuffleDNS(ctx, input.Target, state, input.Scope)...)
	}
	if input.Options.UseCertTransparency {
		emitCmd("cert-transparency", input.Target)
		findings = append(findings, s.runCertificateTransparency(ctx, input.Target, state, input.Scope)...)
	}
	if input.Options.UseAmassIntegration {
		emitCmd("amass", "enum -d "+input.Target)
		findings = append(findings, s.runAmassNative(ctx, input.Target, state, input.Scope)...)
	}

	// Phase 2 — Port scanning (primary target + any subdomains found in phase 1).
	if input.Options.UseNaabuIntegration {
		targets, skipped := expandTargetsWithScope(input.Target, state, input.Scope)
		state.TargetsAttempted += len(targets)
		state.TargetsSkipped += skipped
		if skipped > 0 {
			state.SkippedReasons["out_of_scope"] += skipped
		}
		for _, t := range targets {
			emitCmd("naabu", "-host "+t)
			findings = append(findings, s.runNaabu(ctx, t)...)
		}
	}

	// Phase 3 — HTTP probing (primary target + discovered hosts).
	if input.Options.UseHttpxIntegration {
		targets, skipped := expandTargetsWithScope(input.Target, state, input.Scope)
		state.TargetsAttempted += len(targets)
		state.TargetsSkipped += skipped
		if skipped > 0 {
			state.SkippedReasons["out_of_scope"] += skipped
		}
		for _, t := range targets {
			emitCmd("httpx", "-u "+t)
			findings = append(findings, s.runHttpx(ctx, t)...)
		}
	}

	// Phase 4 — Content & endpoint discovery.
	if input.Options.UseKatanaIntegration {
		katanaDepth := 2
		if len(state.DiscoveredHosts) >= 8 {
			katanaDepth = 3
		}
		emitCmd("katana", fmt.Sprintf("-u %s -depth %d", input.Target, katanaDepth))
		findings = append(findings, s.runKatana(ctx, input.Target, katanaDepth)...)
	}
	if input.Options.UseFFUFIntegration {
		emitCmd("ffuf", "-u "+input.Target+"/FUZZ")
		findings = append(findings, s.runFFUF(ctx, input.Target, input.Scope)...)
	}
	if input.Options.UseGobusterIntegration {
		emitCmd("gobuster", "dir -u "+input.Target)
		findings = append(findings, s.runGobuster(ctx, input.Target, input.Scope)...)
	}

	// Phase 5 — TLS and infrastructure analysis.
	if input.Options.UseTlsxIntegration {
		emitCmd("tlsx", "-u "+input.Target)
		findings = append(findings, s.runTlsx(ctx, input.Target)...)
	}
	if input.Options.UseCdncheckIntegration {
		emitCmd("cdncheck", "-i "+input.Target)
		findings = append(findings, s.runCdncheck(ctx, input.Target)...)
	}
	if input.Options.UseAsnmapIntegration {
		emitCmd("asnmap", "-i "+input.Target)
		findings = append(findings, s.runAsnmap(ctx, input.Target)...)
	}

	// Phase 6 — CMS scanning.
	// Exactly one of the two branches below executes (they are mutually exclusive):
	// • explicit opt-in: UseWPScanIntegration=true → runWPScan (reports "not WordPress" if non-WP)
	// • auto-trigger:    EnableWPScan=true in config → probe silently; only run if WP detected
	if input.Options.UseWPScanIntegration {
		emitCmd("wpscan", "--url "+input.Target)
		findings = append(findings, s.runWPScan(ctx, input.Target, input.AuthProfile)...)
	} else if s.cfg.EnableWPScan {
		result := wpscan.Scan(ctx, input.Target, input.AuthProfile)
		if result.IsWordPress {
			findings = append(findings, model.Finding{
				ID:             "wpscan-auto-triggered",
				Category:       "integration",
				Severity:       model.SeverityInfo,
				Title:          "WPScan auto-triggered: WordPress detected",
				Description:    "WordPress was automatically detected on the target. WPScan ran without an explicit user request because ENABLE_WPSCAN_INTEGRATION is true.",
				Evidence:       "target=" + input.Target,
				Recommendation: "Review the WPScan findings below for WordPress-specific vulnerabilities.",
			})
			findings = append(findings, result.Findings...)
		}
	}

	// Phase 6b — Web application scanning (Nikto).
	// • explicit opt-in: UseNiktoIntegration=true → runNikto
	// • auto-trigger:    EnableNikto=true in config → run silently and prepend an info finding
	if input.Options.UseNiktoIntegration {
		if !s.cfg.AllowDestructive {
			findings = append(findings, model.Finding{
				ID:             "nikto-blocked-by-safety-policy",
				Category:       "safety",
				Severity:       model.SeverityInfo,
				Title:          "Nikto blocked by safety policy",
				Description:    "Destructive or high-impact checks are disabled by default.",
				Evidence:       "ALLOW_DESTRUCTIVE_CHECKS=false",
				Recommendation: "Enable ALLOW_DESTRUCTIVE_CHECKS=true only when the program scope explicitly permits this testing.",
			})
		} else {
			emitCmd("nikto", "-h "+input.Target)
			findings = append(findings, s.runNikto(ctx, input.Target, input.AuthProfile)...)
		}
	} else if s.cfg.EnableNikto {
		if !s.cfg.AllowDestructive {
			findings = append(findings, model.Finding{
				ID:             "nikto-auto-blocked-by-safety-policy",
				Category:       "safety",
				Severity:       model.SeverityInfo,
				Title:          "Nikto auto-run blocked by safety policy",
				Description:    "Nikto auto-run was skipped because destructive checks are disabled by default.",
				Evidence:       "ALLOW_DESTRUCTIVE_CHECKS=false",
				Recommendation: "Enable ALLOW_DESTRUCTIVE_CHECKS=true only when the program scope explicitly permits this testing.",
			})
		} else {
			findings = append(findings, model.Finding{
				ID:             "nikto-auto-triggered",
				Category:       "integration",
				Severity:       model.SeverityInfo,
				Title:          "Nikto auto-triggered",
				Description:    "Nikto ran without an explicit per-scan request because ENABLE_NIKTO_INTEGRATION is true in the server configuration.",
				Evidence:       "target=" + input.Target,
				Recommendation: "Review the Nikto findings below for web application security issues.",
			})
			result := nikto.Scan(ctx, input.Target, input.AuthProfile)
			findings = append(findings, result.Findings...)
		}
	}

	// Phase 6c — SQL injection scanning (SQLMap).
	if input.Options.UseSQLMapIntegration {
		if !s.cfg.AllowDestructive {
			findings = append(findings, model.Finding{
				ID:             "sqlmap-blocked-by-safety-policy",
				Category:       "safety",
				Severity:       model.SeverityInfo,
				Title:          "SQLMap blocked by safety policy",
				Description:    "Destructive or high-impact checks are disabled by default.",
				Evidence:       "ALLOW_DESTRUCTIVE_CHECKS=false",
				Recommendation: "Enable ALLOW_DESTRUCTIVE_CHECKS=true only when the program scope explicitly permits this testing.",
			})
		} else {
			emitCmd("sqlmap", "-u "+input.Target)
			findings = append(findings, s.runSQLMap(ctx, input.Target, input.AuthProfile)...)
		}
	} else if s.cfg.EnableSQLMap {
		if !s.cfg.AllowDestructive {
			findings = append(findings, model.Finding{
				ID:             "sqlmap-auto-blocked-by-safety-policy",
				Category:       "safety",
				Severity:       model.SeverityInfo,
				Title:          "SQLMap auto-run blocked by safety policy",
				Description:    "SQLMap auto-run was skipped because destructive checks are disabled by default.",
				Evidence:       "ALLOW_DESTRUCTIVE_CHECKS=false",
				Recommendation: "Enable ALLOW_DESTRUCTIVE_CHECKS=true only when the program scope explicitly permits this testing.",
			})
		} else {
			findings = append(findings, model.Finding{
				ID:             "sqlmap-auto-triggered",
				Category:       "integration",
				Severity:       model.SeverityInfo,
				Title:          "SQLMap auto-triggered",
				Description:    "The native Go SQLMap scanner ran without an explicit per-scan request because ENABLE_SQLMAP_INTEGRATION is true in the server configuration.",
				Evidence:       "target=" + input.Target,
				Recommendation: "Review the SQLMap findings below for SQL injection vulnerabilities.",
			})
			result := sqlmap.Scan(ctx, input.Target, input.AuthProfile)
			findings = append(findings, result.Findings...)
		}
	}

	// Phase 7 — Vulnerability scanning (primary target + discovered hosts).
	if input.Options.UseNucleiIntegration {
		targets, skipped := expandTargetsWithScope(input.Target, state, input.Scope)
		state.TargetsAttempted += len(targets)
		state.TargetsSkipped += skipped
		if skipped > 0 {
			state.SkippedReasons["out_of_scope"] += skipped
		}
		for _, t := range targets {
			emitCmd("nuclei", "-u "+t)
			findings = append(findings, s.runNuclei(ctx, t)...)
		}
	}
	if input.Options.UseZAPBaselineIntegration {
		emitCmd("zap-baseline.py", "-t "+input.Target)
		findings = append(findings, s.runZAPBaseline(ctx, input.Target)...)
	}
	findings = append(findings, buildIntegrationCoverageFinding(state))

	return findings
}

// expandTargets returns the primary target URL plus a URL for each subdomain in state,
// sharing the same URL scheme as the primary target. Hosts that duplicate the primary
// target's hostname are skipped to avoid scanning the same host twice.
func expandTargets(target string, state *integrationState, scanScope model.ScanScope) []string {
	targets, _ := expandTargetsWithScope(target, state, scanScope)
	return targets
}

func expandTargetsWithScope(target string, state *integrationState, scanScope model.ScanScope) ([]string, int) {
	targets := []string{target}
	if len(state.DiscoveredHosts) == 0 {
		filtered := scope.FilterTargets(targets, scanScope)
		return filtered, len(targets) - len(filtered)
	}
	u, err := url.Parse(target)
	if err != nil {
		return targets, 0
	}
	primaryHost := strings.ToLower(u.Hostname())
	for _, host := range state.DiscoveredHosts {
		if strings.ToLower(host) == primaryHost {
			continue
		}
		targets = append(targets, u.Scheme+"://"+host)
	}
	filtered := scope.FilterTargets(targets, scanScope)
	safeTargets := make([]string, 0, len(filtered))
	rejected := 0
	for _, t := range filtered {
		if err := safety.ValidateOutboundURL(t); err != nil {
			rejected++
			continue
		}
		safeTargets = append(safeTargets, t)
	}
	return safeTargets, (len(targets) - len(filtered)) + rejected
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

func (s *Service) runSubfinder(ctx context.Context, target string, state *integrationState) []model.Finding {
	if !s.cfg.EnableSubfinder {
		return []model.Finding{{
			ID:             "subfinder-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Subfinder integration requested but disabled",
			Description:    "The job requested Subfinder but ENABLE_SUBFINDER_INTEGRATION is false.",
			Evidence:       "ENABLE_SUBFINDER_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.SubfinderBinary); err != nil {
		return []model.Finding{{
			ID:             "subfinder-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Subfinder binary not found",
			Description:    "Subfinder integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install subfinder in the backend image or set SUBFINDER_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.SubfinderBinary, "-d", host, "-silent")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "subfinder-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Subfinder integration failed",
			Description:    "Subfinder did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate subfinder configuration and network access, then rerun.",
		}}
	}

	// Populate shared state so subsequent phases (httpx, naabu, nuclei) can probe
	// each discovered subdomain in addition to the primary target.
	subdomains := 0
	for _, line := range strings.Split(stdout.String(), "\n") {
		host := normalizeDiscoveredHost(line)
		if host == "" {
			continue
		}
		if !scope.IsHostInScope(host, defaultSubdomainScope(target)) {
			state.OutOfScopeHosts = append(state.OutOfScopeHosts, host)
			state.SkippedReasons["discovered_out_of_scope"]++
			continue
		}
		state.DiscoveredHosts = append(state.DiscoveredHosts, host)
		subdomains++
	}

	severity := model.SeverityInfo
	title := "Subfinder found no subdomains"
	if subdomains > 0 {
		severity = model.SeverityMedium
		title = "Subfinder discovered subdomains"
	}

	return []model.Finding{{
		ID:             "subfinder-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery Subfinder passive subdomain enumeration executed.",
		Evidence:       "subdomains=" + strconv.Itoa(subdomains),
		Recommendation: "Review discovered subdomains; each may represent additional attack surface.",
	}}
}

func (s *Service) runHttpx(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableHttpx {
		return []model.Finding{{
			ID:             "httpx-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "httpx integration requested but disabled",
			Description:    "The job requested httpx but ENABLE_HTTPX_INTEGRATION is false.",
			Evidence:       "ENABLE_HTTPX_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.HttpxBinary); err != nil {
		return []model.Finding{{
			ID:             "httpx-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "httpx binary not found",
			Description:    "httpx integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install httpx in the backend image or set HTTPX_BINARY to a valid path.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.HttpxBinary, "-u", target, "-silent", "-status-code", "-title", "-tech-detect")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "httpx-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "httpx integration failed",
			Description:    "httpx did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate httpx configuration and target accessibility, then rerun.",
		}}
	}

	lines := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "httpx found no active HTTP services"
	if lines > 0 {
		title = "httpx probed active HTTP services"
	}

	return []model.Finding{{
		ID:             "httpx-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery httpx HTTP probing and technology detection executed.",
		Evidence:       "probed=" + strconv.Itoa(lines),
		Recommendation: "Review identified technologies and HTTP service metadata for outdated or misconfigured components.",
	}}
}

func (s *Service) runNaabu(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableNaabu {
		return []model.Finding{{
			ID:             "naabu-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Naabu integration requested but disabled",
			Description:    "The job requested Naabu but ENABLE_NAABU_INTEGRATION is false.",
			Evidence:       "ENABLE_NAABU_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.NaabuBinary); err != nil {
		return []model.Finding{{
			ID:             "naabu-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Naabu binary not found",
			Description:    "Naabu integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install naabu in the backend image or set NAABU_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.NaabuBinary, "-host", host, "-silent", "-top-ports", "1000")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "naabu-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Naabu integration failed",
			Description:    "Naabu did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate naabu configuration and network access, then rerun.",
		}}
	}

	openPorts := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "Naabu found no open ports"
	if openPorts > 0 {
		severity = model.SeverityMedium
		title = "Naabu discovered open ports"
	}

	return []model.Finding{{
		ID:             "naabu-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery Naabu port scan executed against top 1000 ports.",
		Evidence:       "openPorts=" + strconv.Itoa(openPorts),
		Recommendation: "Review open ports; close or restrict unnecessary services.",
	}}
}

func (s *Service) runDnsx(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableDnsx {
		return []model.Finding{{
			ID:             "dnsx-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "dnsx integration requested but disabled",
			Description:    "The job requested dnsx but ENABLE_DNSX_INTEGRATION is false.",
			Evidence:       "ENABLE_DNSX_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.DnsxBinary); err != nil {
		return []model.Finding{{
			ID:             "dnsx-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "dnsx binary not found",
			Description:    "dnsx integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install dnsx in the backend image or set DNSX_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.DnsxBinary, "-d", host, "-silent", "-a", "-cname", "-mx", "-txt")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "dnsx-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "dnsx integration failed",
			Description:    "dnsx did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate dnsx configuration and DNS access, then rerun.",
		}}
	}

	records := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "dnsx found no DNS records"
	if records > 0 {
		title = "dnsx resolved DNS records"
	}

	return []model.Finding{{
		ID:             "dnsx-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery dnsx DNS enumeration executed (A, CNAME, MX, TXT records).",
		Evidence:       "records=" + strconv.Itoa(records),
		Recommendation: "Review DNS records for dangling CNAMEs, exposed mail servers, and sensitive TXT entries.",
	}}
}

func (s *Service) runShuffleDNS(ctx context.Context, target string, state *integrationState, scanScope model.ScanScope) []model.Finding {
	if !s.cfg.EnableShuffleDNS {
		return []model.Finding{{
			ID:             "shuffledns-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "ShuffleDNS integration requested but disabled",
			Description:    "The job requested ShuffleDNS but ENABLE_SHUFFLEDNS_INTEGRATION is false.",
			Evidence:       "ENABLE_SHUFFLEDNS_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.ShuffleDNSBinary); err != nil {
		return []model.Finding{{
			ID:             "shuffledns-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ShuffleDNS binary not found",
			Description:    "ShuffleDNS integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install shuffledns in the backend image or set SHUFFLEDNS_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.ShuffleDNSBinary, "-d", host, "-silent")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "shuffledns-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ShuffleDNS integration failed",
			Description:    "ShuffleDNS did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate shuffledns options, resolvers, and network access, then rerun.",
		}}
	}

	discovered := make([]string, 0)
	for _, line := range strings.Split(stdout.String(), "\n") {
		host := normalizeDiscoveredHost(line)
		if host == "" {
			continue
		}
		if !scope.IsHostInScope(host, scanScope) {
			state.OutOfScopeHosts = append(state.OutOfScopeHosts, host)
			state.SkippedReasons["discovered_out_of_scope"]++
			continue
		}
		discovered = append(discovered, host)
	}
	addDiscoveredHosts(state, discovered)

	severity := model.SeverityInfo
	title := "ShuffleDNS found no subdomains"
	if len(discovered) > 0 {
		severity = model.SeverityMedium
		title = "ShuffleDNS discovered subdomains"
	}
	return []model.Finding{{
		ID:             "shuffledns-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery ShuffleDNS subdomain discovery executed.",
		Evidence:       "subdomains=" + strconv.Itoa(len(discovered)),
		Recommendation: "Review discovered subdomains and confirm they are in authorized scope.",
	}}
}

func (s *Service) runCertificateTransparency(ctx context.Context, target string, state *integrationState, scanScope model.ScanScope) []model.Finding {
	if !s.cfg.EnableCertTrans {
		return []model.Finding{{
			ID:             "cert-transparency-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Certificate Transparency integration requested but disabled",
			Description:    "The job requested Certificate Transparency discovery but ENABLE_CERTIFICATE_TRANSPARENCY_INTEGRATION is false.",
			Evidence:       "ENABLE_CERTIFICATE_TRANSPARENCY_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	host := hostFromTarget(target)
	if strings.TrimSpace(host) == "" {
		return nil
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ictx, http.MethodGet, "https://crt.sh/?q=%25."+url.QueryEscape(host)+"&output=json", nil)
	if err != nil {
		return []model.Finding{{
			ID:             "cert-transparency-request-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Certificate Transparency query failed",
			Description:    "The scanner could not prepare a certificate transparency query.",
			Evidence:       err.Error(),
			Recommendation: "Validate target host parsing and retry.",
		}}
	}
	client := &http.Client{Timeout: s.cfg.IntegrationTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return []model.Finding{{
			ID:             "cert-transparency-network-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Certificate Transparency query failed",
			Description:    "The scanner could not query certificate transparency logs from crt.sh.",
			Evidence:       err.Error(),
			Recommendation: "Validate network egress to crt.sh and retry.",
		}}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return []model.Finding{{
			ID:             "cert-transparency-http-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Certificate Transparency query returned unexpected status",
			Description:    "crt.sh did not return a successful response.",
			Evidence:       "status=" + strconv.Itoa(resp.StatusCode),
			Recommendation: "Retry later or use an alternative certificate transparency source.",
		}}
	}

	var records []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return []model.Finding{{
			ID:             "cert-transparency-parse-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Certificate Transparency response parse error",
			Description:    "The scanner could not parse the crt.sh response.",
			Evidence:       err.Error(),
			Recommendation: "Retry later and verify crt.sh output format.",
		}}
	}

	discoveredSet := map[string]struct{}{}
	for _, rec := range records {
		for _, raw := range strings.Split(rec.NameValue, "\n") {
			h := normalizeDiscoveredHost(raw)
			if h == "" {
				continue
			}
			if !scope.IsHostInScope(h, scanScope) {
				state.OutOfScopeHosts = append(state.OutOfScopeHosts, h)
				state.SkippedReasons["discovered_out_of_scope"]++
				continue
			}
			discoveredSet[h] = struct{}{}
		}
	}
	discovered := make([]string, 0, len(discoveredSet))
	for h := range discoveredSet {
		discovered = append(discovered, h)
	}
	addDiscoveredHosts(state, discovered)

	severity := model.SeverityInfo
	title := "Certificate Transparency found no hosts"
	if len(discovered) > 0 {
		severity = model.SeverityMedium
		title = "Certificate Transparency discovered hosts"
	}
	return []model.Finding{{
		ID:             "cert-transparency-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Certificate Transparency discovery via crt.sh executed.",
		Evidence:       "hosts=" + strconv.Itoa(len(discovered)),
		Recommendation: "Review discovered hosts for additional in-scope attack surface.",
	}}
}

func (s *Service) runAmassNative(ctx context.Context, target string, state *integrationState, scanScope model.ScanScope) []model.Finding {
	if !s.cfg.EnableAmass {
		return []model.Finding{{
			ID:             "amass-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Amass integration requested but disabled",
			Description:    "The job requested native Go Amass discovery but ENABLE_AMASS_INTEGRATION is false.",
			Evidence:       "ENABLE_AMASS_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	host := hostFromTarget(target)
	if strings.TrimSpace(host) == "" {
		return []model.Finding{{
			ID:             "amass-invalid-target",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Amass integration skipped",
			Description:    "Target host could not be derived for native Go Amass discovery.",
			Evidence:       "target=" + target,
			Recommendation: "Provide a valid absolute target URL and retry.",
		}}
	}

	discovered := map[string]struct{}{}

	ctHosts, ctErr := s.fetchCertificateTransparencyHosts(ctx, host, scanScope)
	for _, h := range ctHosts {
		discovered[h] = struct{}{}
	}

	amassSubdomainLabels := []string{
		"www", "api", "dev", "staging", "admin", "app", "auth", "portal", "cdn", "static",
		"internal", "test", "uat", "beta", "mail", "vpn", "sso",
	}
	for _, label := range amassSubdomainLabels {
		if ctx.Err() != nil {
			break
		}
		candidate := label + "." + host
		if !scope.IsHostInScope(candidate, scanScope) {
			state.OutOfScopeHosts = append(state.OutOfScopeHosts, candidate)
			state.SkippedReasons["discovered_out_of_scope"]++
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, candidate)
		cancel()
		if err == nil && len(ips) > 0 {
			discovered[candidate] = struct{}{}
		}
	}

	hosts := make([]string, 0, len(discovered))
	for h := range discovered {
		hosts = append(hosts, h)
	}
	addDiscoveredHosts(state, hosts)

	severity := model.SeverityInfo
	title := "Amass (native Go) found no subdomains"
	if len(hosts) > 0 {
		severity = model.SeverityMedium
		title = "Amass (native Go) discovered subdomains"
	}
	evidence := "subdomains=" + strconv.Itoa(len(hosts)) + "; ctSourceError=" + strconv.FormatBool(ctErr != nil)
	return []model.Finding{{
		ID:             "amass-native-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Native Go Amass-style passive discovery executed using certificate transparency plus DNS resolution of common labels.",
		Evidence:       evidence,
		Recommendation: "Review discovered hosts and expand authorized testing scope as appropriate.",
	}}
}

func (s *Service) fetchCertificateTransparencyHosts(ctx context.Context, host string, scanScope model.ScanScope) ([]string, error) {
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ictx, http.MethodGet, "https://crt.sh/?q=%25."+url.QueryEscape(host)+"&output=json", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: s.cfg.IntegrationTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &ctHTTPError{status: resp.StatusCode}
	}
	var records []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}
	discoveredSet := map[string]struct{}{}
	for _, rec := range records {
		for _, raw := range strings.Split(rec.NameValue, "\n") {
			h := normalizeDiscoveredHost(raw)
			if h == "" || !scope.IsHostInScope(h, scanScope) {
				continue
			}
			discoveredSet[h] = struct{}{}
		}
	}
	discovered := make([]string, 0, len(discoveredSet))
	for h := range discoveredSet {
		discovered = append(discovered, h)
	}
	return discovered, nil
}

type ctHTTPError struct {
	status int
}

func (e *ctHTTPError) Error() string {
	return "crt.sh unexpected status: " + strconv.Itoa(e.status)
}

func (s *Service) runKatana(ctx context.Context, target string, depth int) []model.Finding {
	if !s.cfg.EnableKatana {
		return []model.Finding{{
			ID:             "katana-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Katana integration requested but disabled",
			Description:    "The job requested Katana but ENABLE_KATANA_INTEGRATION is false.",
			Evidence:       "ENABLE_KATANA_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.KatanaBinary); err != nil {
		return []model.Finding{{
			ID:             "katana-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Katana binary not found",
			Description:    "Katana integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install katana in the backend image or set KATANA_BINARY to a valid path.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	if depth <= 0 {
		depth = 2
	}
	cmd := exec.CommandContext(ictx, s.cfg.KatanaBinary, "-u", target, "-silent", "-depth", strconv.Itoa(depth), "-js-crawl")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "katana-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Katana integration failed",
			Description:    "Katana did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate katana configuration and target accessibility, then rerun.",
		}}
	}

	endpoints := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "Katana found no crawlable endpoints"
	if endpoints > 0 {
		title = "Katana crawled endpoints"
	}

	return []model.Finding{{
		ID:             "katana-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery Katana web crawl executed with configurable depth and JS crawling enabled.",
		Evidence:       "endpoints=" + strconv.Itoa(endpoints) + ";depth=" + strconv.Itoa(depth),
		Recommendation: "Review crawled endpoints for sensitive paths, unprotected APIs, and exposed functionality.",
	}}
}

func (s *Service) runTlsx(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableTlsx {
		return []model.Finding{{
			ID:             "tlsx-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "tlsx integration requested but disabled",
			Description:    "The job requested tlsx but ENABLE_TLSX_INTEGRATION is false.",
			Evidence:       "ENABLE_TLSX_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.TlsxBinary); err != nil {
		return []model.Finding{{
			ID:             "tlsx-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "tlsx binary not found",
			Description:    "tlsx integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install tlsx in the backend image or set TLSX_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.TlsxBinary, "-u", host, "-silent", "-expired", "-self-signed", "-mismatched")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "tlsx-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "tlsx integration failed",
			Description:    "tlsx did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate tlsx configuration and target accessibility, then rerun.",
		}}
	}

	issues := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "tlsx found no TLS certificate issues"
	if issues > 0 {
		severity = model.SeverityMedium
		title = "tlsx detected TLS certificate issues"
	}

	return []model.Finding{{
		ID:             "tlsx-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery tlsx TLS certificate analysis executed (expired, self-signed, mismatched).",
		Evidence:       "issues=" + strconv.Itoa(issues),
		Recommendation: "Review and remediate any flagged TLS certificate issues before they impact service availability.",
	}}
}

func (s *Service) runCdncheck(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableCdncheck {
		return []model.Finding{{
			ID:             "cdncheck-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "cdncheck integration requested but disabled",
			Description:    "The job requested cdncheck but ENABLE_CDNCHECK_INTEGRATION is false.",
			Evidence:       "ENABLE_CDNCHECK_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.CdncheckBinary); err != nil {
		return []model.Finding{{
			ID:             "cdncheck-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "cdncheck binary not found",
			Description:    "cdncheck integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install cdncheck in the backend image or set CDNCHECK_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.CdncheckBinary, "-i", host, "-silent")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "cdncheck-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "cdncheck integration failed",
			Description:    "cdncheck did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate cdncheck configuration and network access, then rerun.",
		}}
	}

	detections := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "cdncheck detected no CDN/WAF/cloud provider"
	if detections > 0 {
		title = "cdncheck identified CDN/WAF/cloud infrastructure"
	}

	return []model.Finding{{
		ID:             "cdncheck-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery cdncheck CDN, WAF, and cloud provider detection executed.",
		Evidence:       "detections=" + strconv.Itoa(detections),
		Recommendation: "Factor identified CDN/WAF/cloud infrastructure into the overall risk assessment.",
	}}
}

func (s *Service) runAsnmap(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableAsnmap {
		return []model.Finding{{
			ID:             "asnmap-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "asnmap integration requested but disabled",
			Description:    "The job requested asnmap but ENABLE_ASNMAP_INTEGRATION is false.",
			Evidence:       "ENABLE_ASNMAP_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	if _, err := exec.LookPath(s.cfg.AsnmapBinary); err != nil {
		return []model.Finding{{
			ID:             "asnmap-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "asnmap binary not found",
			Description:    "asnmap integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install asnmap in the backend image or set ASNMAP_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.AsnmapBinary, "-a", host, "-silent")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "asnmap-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "asnmap integration failed",
			Description:    "asnmap did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate asnmap configuration and network access, then rerun.",
		}}
	}

	cidrs := countNonEmptyLines(stdout.String())
	severity := model.SeverityInfo
	title := "asnmap found no ASN/CIDR ranges"
	if cidrs > 0 {
		title = "asnmap mapped ASN/CIDR ranges"
	}

	return []model.Finding{{
		ID:             "asnmap-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery asnmap ASN to CIDR mapping executed.",
		Evidence:       "cidrs=" + strconv.Itoa(cidrs),
		Recommendation: "Review associated CIDRs to understand the network footprint and ensure all ranges are in scope.",
	}}
}

// hostFromTarget extracts the bare hostname from a full URL target string.
// If the target cannot be parsed or has no host component, it is returned unchanged.
func hostFromTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return target
	}
	return u.Hostname()
}

func normalizeDiscoveredHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return ""
	}
	return host
}

func addDiscoveredHosts(state *integrationState, hosts []string) {
	if state == nil || len(hosts) == 0 {
		return
	}
	seen := map[string]struct{}{}
	for _, h := range state.DiscoveredHosts {
		if h != "" {
			seen[strings.ToLower(h)] = struct{}{}
		}
	}
	for _, h := range hosts {
		nh := strings.ToLower(strings.TrimSpace(h))
		if nh == "" {
			continue
		}
		if _, ok := seen[nh]; ok {
			continue
		}
		seen[nh] = struct{}{}
		state.DiscoveredHosts = append(state.DiscoveredHosts, nh)
	}
}

func buildIntegrationCoverageFinding(state *integrationState) model.Finding {
	reasons := make([]string, 0, len(state.SkippedReasons))
	for reason, count := range state.SkippedReasons {
		reasons = append(reasons, reason+":"+strconv.Itoa(count))
	}
	sort.Strings(reasons)
	return model.Finding{
		ID:             "integration-coverage-telemetry",
		Category:       "coverage",
		Severity:       model.SeverityInfo,
		Title:          "Integration target coverage telemetry",
		Description:    "Telemetry snapshot for attempted and skipped integration targets with scope controls and reason codes.",
		Evidence:       "targetsAttempted=" + strconv.Itoa(state.TargetsAttempted) + ";targetsSkipped=" + strconv.Itoa(state.TargetsSkipped),
		Recommendation: "Review skipped target reasons and adjust scope approvals or retry policy as needed.",
		Sources:        []string{"integration"},
		Confidence:     0.98,
		EvidenceFields: map[string]string{
			"targetsAttempted": strconv.Itoa(state.TargetsAttempted),
			"targetsSkipped":   strconv.Itoa(state.TargetsSkipped),
			"skippedReasons":   strings.Join(reasons, ","),
			"inScopeHosts":     strconv.Itoa(len(state.DiscoveredHosts)),
			"outOfScopeHosts":  strconv.Itoa(len(state.OutOfScopeHosts)),
		},
		BusinessTags: []string{"coverage"},
		Exploitability: &model.Exploitability{
			Reachable:       true,
			RequiredRole:    "analyst",
			Prerequisites:   []string{"scope_configuration"},
			AttackPathHints: []string{"scope-tuning", "retry-policy-adjustment"},
		},
	}
}

func defaultSubdomainScope(target string) model.ScanScope {
	root := strings.TrimSpace(hostFromTarget(target))
	if root == "" {
		return model.ScanScope{}
	}
	return model.ScanScope{
		IncludeHosts: []string{root, "*." + root},
	}
}

// runWPScan executes the native Go WPScan assessment against target.
// It first probes whether the target runs WordPress and reports "not WordPress" if opted-in
// but no WordPress fingerprint is found.
func (s *Service) runWPScan(ctx context.Context, target string, authProfile model.ScanAuthProfile) []model.Finding {
	if !s.cfg.EnableWPScan {
		return []model.Finding{{
			ID:             "wpscan-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "WPScan integration requested but disabled",
			Description:    "The job requested WPScan but ENABLE_WPSCAN_INTEGRATION is false.",
			Evidence:       "ENABLE_WPSCAN_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	result := wpscan.Scan(ctx, target, authProfile)

	if !result.IsWordPress {
		return []model.Finding{{
			ID:             "wpscan-not-wordpress",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "WPScan: Target does not appear to be WordPress",
			Description:    "No WordPress fingerprints (wp-login.php, wp-content/, REST API) were detected on the target.",
			Evidence:       "target=" + target,
			Recommendation: "If the target is WordPress, verify that wp-login.php and wp-content are reachable from the scanner network.",
		}}
	}

	return result.Findings
}

// runNikto executes the native Go Nikto web application security scan against target.
func (s *Service) runNikto(ctx context.Context, target string, authProfile model.ScanAuthProfile) []model.Finding {
	if !s.cfg.EnableNikto {
		return []model.Finding{{
			ID:             "nikto-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Nikto integration requested but disabled",
			Description:    "The job requested Nikto but ENABLE_NIKTO_INTEGRATION is false.",
			Evidence:       "ENABLE_NIKTO_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	result := nikto.Scan(ctx, target, authProfile)
	return result.Findings
}

// runSQLMap executes the native Go SQLMap SQL injection scanner against target.
func (s *Service) runSQLMap(ctx context.Context, target string, authProfile model.ScanAuthProfile) []model.Finding {
	if !s.cfg.EnableSQLMap {
		return []model.Finding{{
			ID:             "sqlmap-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "SQLMap integration requested but disabled",
			Description:    "The job requested SQLMap but ENABLE_SQLMAP_INTEGRATION is false.",
			Evidence:       "ENABLE_SQLMAP_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}

	result := sqlmap.Scan(ctx, target, authProfile)
	return result.Findings
}

func (s *Service) runFFUF(ctx context.Context, target string, scanScope model.ScanScope) []model.Finding {
	if !s.cfg.EnableFFUF {
		return []model.Finding{{
			ID:             "ffuf-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "FFUF integration requested but disabled",
			Description:    "The job requested FFUF but ENABLE_FFUF_INTEGRATION is false.",
			Evidence:       "ENABLE_FFUF_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.FFUFBinary); err != nil {
		return []model.Finding{{
			ID:             "ffuf-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "FFUF binary not found",
			Description:    "FFUF integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install FFUF or set FFUF_BINARY to the binary path.",
		}}
	}
	wordlistPath, err := writeTemporaryWordlist(wordlist.GetCommonDirectoriesWithExternal(ctx))
	if err != nil {
		return []model.Finding{{
			ID:             "ffuf-wordlist-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "FFUF wordlist preparation failed",
			Description:    "Could not prepare a temporary wordlist for FFUF.",
			Evidence:       err.Error(),
			Recommendation: "Retry scan or provide runner filesystem permissions for temporary files.",
		}}
	}
	defer os.Remove(wordlistPath)

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.FFUFBinary, "-u", strings.TrimRight(target, "/")+"/FUZZ", "-w", wordlistPath, "-mc", "200,204,301,302,307,401,403", "-s")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "ffuf-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "FFUF timed out",
			Description:    "FFUF did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	paths := parsePathHits(outb.String(), target, scanScope)
	if len(paths) == 0 {
		return []model.Finding{{
			ID:             "ffuf-no-paths",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "FFUF found no candidate paths",
			Description:    "FFUF completed but did not report in-scope matches from the configured wordlist.",
			Evidence:       "target=" + target,
			Recommendation: "Try broader wordlists, different match filters, or authenticated profiles.",
		}}
	}
	return []model.Finding{{
		ID:             "ffuf-path-discovery",
		Category:       "discovery",
		Severity:       model.SeverityInfo,
		Title:          "FFUF discovered candidate paths",
		Description:    "FFUF discovered in-scope endpoint candidates using directory fuzzing.",
		Evidence:       strings.Join(limitStrings(paths, 20), ", "),
		Recommendation: "Review discovered paths for authentication, authorization, and input-validation flaws.",
		Sources:        []string{"ffuf"},
		Confidence:     0.8,
	}}
}

func (s *Service) runGobuster(ctx context.Context, target string, scanScope model.ScanScope) []model.Finding {
	if !s.cfg.EnableGobuster {
		return []model.Finding{{
			ID:             "gobuster-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Gobuster integration requested but disabled",
			Description:    "The job requested Gobuster but ENABLE_GOBUSTER_INTEGRATION is false.",
			Evidence:       "ENABLE_GOBUSTER_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.GobusterBinary); err != nil {
		return []model.Finding{{
			ID:             "gobuster-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Gobuster binary not found",
			Description:    "Gobuster integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install Gobuster or set GOBUSTER_BINARY to the binary path.",
		}}
	}
	wordlistPath, err := writeTemporaryWordlist(wordlist.GetCommonDirectoriesWithExternal(ctx))
	if err != nil {
		return []model.Finding{{
			ID:             "gobuster-wordlist-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Gobuster wordlist preparation failed",
			Description:    "Could not prepare a temporary wordlist for Gobuster.",
			Evidence:       err.Error(),
			Recommendation: "Retry scan or provide runner filesystem permissions for temporary files.",
		}}
	}
	defer os.Remove(wordlistPath)

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.GobusterBinary, "dir", "-u", target, "-w", wordlistPath, "-q", "--no-error")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "gobuster-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Gobuster timed out",
			Description:    "Gobuster did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	paths := parsePathHits(outb.String(), target, scanScope)
	if len(paths) == 0 {
		return []model.Finding{{
			ID:             "gobuster-no-paths",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Gobuster found no candidate paths",
			Description:    "Gobuster completed but did not report in-scope matches from the configured wordlist.",
			Evidence:       "target=" + target,
			Recommendation: "Try broader wordlists, file-extension checks, or authenticated profiles.",
		}}
	}
	return []model.Finding{{
		ID:             "gobuster-path-discovery",
		Category:       "discovery",
		Severity:       model.SeverityInfo,
		Title:          "Gobuster discovered candidate paths",
		Description:    "Gobuster discovered in-scope endpoint candidates using directory brute-force.",
		Evidence:       strings.Join(limitStrings(paths, 20), ", "),
		Recommendation: "Review discovered paths for sensitive content, auth bypass, and exposed administrative surfaces.",
		Sources:        []string{"gobuster"},
		Confidence:     0.8,
	}}
}

func writeTemporaryWordlist(entries []string) (string, error) {
	// Honour SHARED_TMP_DIR so the wordlist file lands in a directory
	// that's also mounted into the ffuf/gobuster sidecars at the same
	// path. Falls back to os.TempDir() when unset (e.g. running the
	// backend binary outside Docker Compose).
	dir := os.Getenv("SHARED_TMP_DIR")
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	f, err := os.CreateTemp(dir, "auto-bughunter-wordlist-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	seen := map[string]struct{}{}
	for _, entry := range entries {
		clean := strings.TrimSpace(strings.TrimPrefix(entry, "/"))
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		if _, err := f.WriteString(clean + "\n"); err != nil {
			return "", err
		}
	}
	return f.Name(), nil
}

func parsePathHits(rawOutput, target string, scanScope model.ScanScope) []string {
	lines := strings.Split(rawOutput, "\n")
	paths := make([]string, 0)
	seen := map[string]struct{}{}
	base := strings.TrimRight(target, "/")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field := strings.Fields(line)[0]
		path := ""
		switch {
		case strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://"):
			path = strings.TrimPrefix(field, base)
		case strings.HasPrefix(field, "/"):
			path = field
		default:
			path = "/" + strings.TrimPrefix(field, "/")
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		fullURL := base + path
		if !scope.IsURLInScope(fullURL, scanScope) {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func limitStrings(items []string, max int) []string {
	if max <= 0 || len(items) <= max {
		return items
	}
	return items[:max]
}
