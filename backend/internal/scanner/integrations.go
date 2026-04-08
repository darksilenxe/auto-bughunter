package scanner

import (
	"bytes"
	"context"
	"net/url"
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
	if input.Options.UseSubfinderIntegration {
		findings = append(findings, s.runSubfinder(ctx, input.Target)...)
	}
	if input.Options.UseHttpxIntegration {
		findings = append(findings, s.runHttpx(ctx, input.Target)...)
	}
	if input.Options.UseNaabuIntegration {
		findings = append(findings, s.runNaabu(ctx, input.Target)...)
	}
	if input.Options.UseDnsxIntegration {
		findings = append(findings, s.runDnsx(ctx, input.Target)...)
	}
	if input.Options.UseKatanaIntegration {
		findings = append(findings, s.runKatana(ctx, input.Target)...)
	}
	if input.Options.UseTlsxIntegration {
		findings = append(findings, s.runTlsx(ctx, input.Target)...)
	}
	if input.Options.UseCdncheckIntegration {
		findings = append(findings, s.runCdncheck(ctx, input.Target)...)
	}
	if input.Options.UseAsnmapIntegration {
		findings = append(findings, s.runAsnmap(ctx, input.Target)...)
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

func (s *Service) runSubfinder(ctx context.Context, target string) []model.Finding {
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

	subdomains := countNonEmptyLines(stdout.String())
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

func (s *Service) runKatana(ctx context.Context, target string) []model.Finding {
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

	cmd := exec.CommandContext(ictx, s.cfg.KatanaBinary, "-u", target, "-silent", "-depth", "2", "-js-crawl")
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
		Description:    "Project Discovery Katana web crawl executed with depth 2 and JS crawling enabled.",
		Evidence:       "endpoints=" + strconv.Itoa(endpoints),
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

func hostFromTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return target
	}
	return u.Hostname()
}
