package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/metrics"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/nikto"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
	"auto-bughunter/backend/internal/sqlmap"
	"auto-bughunter/backend/internal/toolclient"
	"auto-bughunter/backend/internal/wordlist"
	"auto-bughunter/backend/internal/wpscan"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// integrationState carries context discovered in earlier pipeline phases to later ones.
type integrationState struct {
	// mu guards the discovery registry fields below. Integration tools run
	// sequentially today, but the mutex keeps the accumulation safe if any
	// future phase parallelises tool execution.
	mu sync.Mutex

	// DiscoveredHosts holds hostnames found by subfinder. They are used as additional
	// targets by httpx, naabu, and nuclei in subsequent phases.
	DiscoveredHosts  []string
	OutOfScopeHosts  []string
	TargetsAttempted int
	TargetsSkipped   int
	SkippedReasons   map[string]int

	// DiscoveredEndpoints holds in-scope absolute URLs surfaced by content- and
	// route-discovery tools (ffuf, gobuster, kiterunner, gau, linkfinder,
	// katana). Deeper validation phases (sqlmap, commix, nuclei, xssmap) reuse
	// them as additional targets so a path discovered by one tool becomes an
	// active test target for the next.
	DiscoveredEndpoints []string

	// DiscoveredParams holds hidden HTTP parameter names surfaced by Arjun and
	// by ffuf parameter fuzzing. They are appended to validation targets so
	// injection tools have concrete inputs to exercise.
	DiscoveredParams []string
}

// maxValidationTargets caps how many discovered endpoints (plus the base
// target) are handed to the heavier active-validation tools (sqlmap, commix,
// nuclei, xssmap). It bounds scan time so a large discovery surface cannot blow
// the per-scan budget.
const maxValidationTargets = 6

// maxInjectionParams caps how many discovered parameter names are appended to a
// single validation URL when building injection points.
const maxInjectionParams = 8

// addEndpoints records in-scope absolute URLs in the discovery registry,
// de-duplicating against what is already present. nil-receiver safe.
func (st *integrationState) addEndpoints(urls ...string) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	seen := make(map[string]struct{}, len(st.DiscoveredEndpoints))
	for _, e := range st.DiscoveredEndpoints {
		seen[e] = struct{}{}
	}
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		st.DiscoveredEndpoints = append(st.DiscoveredEndpoints, u)
	}
}

// addParams records discovered HTTP parameter names in the registry,
// de-duplicating against what is already present. nil-receiver safe.
func (st *integrationState) addParams(names ...string) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	seen := make(map[string]struct{}, len(st.DiscoveredParams))
	for _, p := range st.DiscoveredParams {
		seen[p] = struct{}{}
	}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		st.DiscoveredParams = append(st.DiscoveredParams, n)
	}
}

// validationTargets returns the base target plus discovered endpoints (deduped
// and bounded by maxValidationTargets) for tools that crawl/probe a URL on
// their own (nuclei, xssmap). nil-receiver safe.
func (st *integrationState) validationTargets(base string) []string {
	targets := []string{base}
	seen := map[string]struct{}{base: {}}
	if st != nil {
		st.mu.Lock()
		for _, e := range st.DiscoveredEndpoints {
			if len(targets) >= maxValidationTargets {
				break
			}
			if _, ok := seen[e]; ok {
				continue
			}
			seen[e] = struct{}{}
			targets = append(targets, e)
		}
		st.mu.Unlock()
	}
	return targets
}

// injectionTargets returns validation targets with discovered parameters
// attached to any URL that lacks a query string, giving injection tools
// (sqlmap, commix) concrete inputs to test. nil-receiver safe.
func (st *integrationState) injectionTargets(base string) []string {
	targets := st.validationTargets(base)
	if st == nil {
		return targets
	}
	st.mu.Lock()
	params := append([]string(nil), st.DiscoveredParams...)
	st.mu.Unlock()
	if len(params) == 0 {
		return targets
	}
	params = limitStrings(params, maxInjectionParams)
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, withQueryParams(t, params))
	}
	return out
}

// withQueryParams appends the given parameter names (each set to a benign probe
// value) to rawURL when it has no existing query string. URLs that already
// carry query parameters are returned unchanged so their real inputs are
// preserved as the injection point.
func withQueryParams(rawURL string, params []string) string {
	if len(params) == 0 {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.RawQuery != "" {
		return rawURL
	}
	q := u.Query()
	for _, p := range params {
		q.Set(p, "1")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// cooldownAfterNuclei is a brief pause inserted after Nuclei finishes to let
// it fully tear down child processes and release transient network/socket
// pressure before any subsequent Phase 7 tool (vulnx, zap-baseline, xssmap)
// starts.  30 s gives Nuclei enough time to flush all child processes even on
// busy targets; the previous 5 s value caused Phase 7 tools to time out.
const cooldownAfterNuclei = 30 * time.Second

const integrationPreflightTimeout = 3 * time.Second

// runOptionalIntegrations executes the opted-in integrations in a dependency-aware order:
//
//	Phase 1 — Discovery:   cloudlist, subfinder, dnsx, shuffledns, certificate-transparency, amass(native-go), uncover
//	Phase 2 — Port scan:   naabu  (target + discovered hosts)
//	Phase 3 — HTTP probe:  httpx  (target + discovered hosts)
//	Phase 4 — Crawling:    katana, ffuf, gobuster, kiterunner, gau, arjun, linkfinder
//	Phase 5 — TLS/network: tlsx, cdncheck, asnmap
//	Phase 6 — CMS scan:    WPScan (native Go; auto-triggers if WordPress detected and enabled)
//	Phase 6b — Web scan:   Nikto  (native Go; full web application pen-test)
//	Phase 6c — SQL inject: SQLMap (native Go; error-based, boolean-blind, time-based blind)
//	Phase 6d — Cmd inject: commix (OS command injection; gated by ALLOW_DESTRUCTIVE_CHECKS)
//	Phase 7 — Vuln scan:   nuclei (target + discovered hosts), vulnx, retire.js, trufflehog, zap
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
	if input.Options.UseCloudlistIntegration {
		emitCmd("cloudlist", "-silent -host -id "+hostFromTarget(input.Target))
		findings = append(findings, s.runInstrumentedTool(ctx, "cloudlist", func() []model.Finding {
			return s.runCloudlist(ctx, input.Target)
		})...)
	}
	if input.Options.UseSubfinderIntegration {
		emitCmd("subfinder", "-d "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "subfinder", func() []model.Finding {
			return s.runSubfinder(ctx, input.Target, state)
		})...)
	}
	if input.Options.UseDnsxIntegration {
		emitCmd("dnsx", "-d "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "dnsx", func() []model.Finding {
			return s.runDnsx(ctx, input.Target)
		})...)
	}
	if input.Options.UseShuffleDNSIntegration {
		emitCmd("shuffledns", "-d "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "shuffledns", func() []model.Finding {
			return s.runShuffleDNS(ctx, input.Target, state, input.Scope)
		})...)
	}
	if input.Options.UseCertTransparency {
		emitCmd("cert-transparency", input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "cert-transparency", func() []model.Finding {
			return s.runCertificateTransparency(ctx, input.Target, state, input.Scope)
		})...)
	}
	if input.Options.UseAmassIntegration {
		emitCmd("amass", "enum -d "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "amass", func() []model.Finding {
			return s.runAmassNative(ctx, input.Target, state, input.Scope)
		})...)
	}
	if input.Options.UseUncoverIntegration {
		emitCmd("uncover", "-q "+hostFromTarget(input.Target))
		findings = append(findings, s.runInstrumentedTool(ctx, "uncover", func() []model.Finding {
			return s.runUncover(ctx, input.Target, state, input.Scope)
		})...)
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
			findings = append(findings, s.runInstrumentedTool(ctx, "naabu", func() []model.Finding {
				return s.runNaabu(ctx, t)
			})...)
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
			findings = append(findings, s.runInstrumentedTool(ctx, "httpx", func() []model.Finding {
				return s.runHttpx(ctx, t)
			})...)
		}
	}

	// Phase 4 — Content & endpoint discovery.
	if input.Options.UseKatanaIntegration {
		katanaDepth := 2
		if len(state.DiscoveredHosts) >= 8 {
			katanaDepth = 3
		}
		emitCmd("katana", fmt.Sprintf("-u %s -depth %d", input.Target, katanaDepth))
		findings = append(findings, s.runInstrumentedTool(ctx, "katana", func() []model.Finding {
			return s.runKatana(ctx, input.Target, katanaDepth, input.Scope, state)
		})...)
	}
	if input.Options.UseFFUFIntegration {
		emitCmd("ffuf", "-u "+input.Target+"/FUZZ")
		findings = append(findings, s.runInstrumentedTool(ctx, "ffuf", func() []model.Finding {
			return s.runFFUF(ctx, input.Target, input.Scope, state)
		})...)
	}
	if input.Options.UseGobusterIntegration {
		emitCmd("gobuster", "dir -u "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "gobuster", func() []model.Finding {
			return s.runGobuster(ctx, input.Target, input.Scope, state)
		})...)
	}
	if input.Options.UseKiterunnerIntegration {
		emitCmd("kiterunner", "scan "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "kiterunner", func() []model.Finding {
			return s.runKiterunner(ctx, input.Target, input.Scope, state)
		})...)
	}
	if input.Options.UseGauIntegration {
		emitCmd("gau", hostFromTarget(input.Target))
		findings = append(findings, s.runInstrumentedTool(ctx, "gau", func() []model.Finding {
			return s.runGau(ctx, input.Target, input.Scope, state)
		})...)
	}
	if input.Options.UseArjunIntegration {
		emitCmd("arjun", "-u "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "arjun", func() []model.Finding {
			return s.runArjun(ctx, input.Target, input.Scope, state)
		})...)
	}
	if input.Options.UseLinkFinderIntegration {
		emitCmd("linkfinder", "-i "+input.Target+" -o cli")
		findings = append(findings, s.runInstrumentedTool(ctx, "linkfinder", func() []model.Finding {
			return s.runLinkFinder(ctx, input.Target, input.Scope, state)
		})...)
	}

	// Phase 5 — TLS and infrastructure analysis.
	if input.Options.UseTlsxIntegration {
		emitCmd("tlsx", "-u "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "tlsx", func() []model.Finding {
			return s.runTlsx(ctx, input.Target)
		})...)
	}
	if input.Options.UseCdncheckIntegration {
		emitCmd("cdncheck", "-i "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "cdncheck", func() []model.Finding {
			return s.runCdncheck(ctx, input.Target)
		})...)
	}
	if input.Options.UseAsnmapIntegration {
		emitCmd("asnmap", "-i "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "asnmap", func() []model.Finding {
			return s.runAsnmap(ctx, input.Target)
		})...)
	}

	// Phase 6 — CMS scanning.
	// Exactly one of the two branches below executes (they are mutually exclusive):
	// • explicit opt-in: UseWPScanIntegration=true → runWPScan (reports "not WordPress" if non-WP)
	// • auto-trigger:    EnableWPScan=true in config → probe silently; only run if WP detected
	if input.Options.UseWPScanIntegration {
		emitCmd("wpscan", "--url "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "wpscan", func() []model.Finding {
			return s.runWPScan(ctx, input.Target, input.AuthProfile)
		})...)
	} else if s.cfg.EnableWPScan {
		startedAt := time.Now()
		result := wpscan.Scan(ctx, input.Target, input.AuthProfile)
		status := "skipped"
		if result.IsWordPress {
			status = "success"
		}
		metrics.ToolRun("wpscan", "scanner", status, time.Since(startedAt))
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
			metrics.ToolRun("nikto", "scanner", "skipped", 0)
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
			findings = append(findings, s.runInstrumentedTool(ctx, "nikto", func() []model.Finding {
				return s.runNikto(ctx, input.Target, input.AuthProfile)
			})...)
		}
	} else if s.cfg.EnableNikto {
		if !s.cfg.AllowDestructive {
			metrics.ToolRun("nikto", "scanner", "skipped", 0)
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
			findings = append(findings, s.runInstrumentedTool(ctx, "nikto", func() []model.Finding {
				return s.runNikto(ctx, input.Target, input.AuthProfile)
			})...)
		}
	}

	// Phase 6c — SQL injection scanning (SQLMap).
	if input.Options.UseSQLMapIntegration {
		if !s.cfg.AllowDestructive {
			metrics.ToolRun("sqlmap", "scanner", "skipped", 0)
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
			for _, vt := range state.injectionTargets(input.Target) {
				vt := vt
				emitCmd("sqlmap", "-u "+vt)
				findings = append(findings, s.runInstrumentedTool(ctx, "sqlmap", func() []model.Finding {
					return s.runSQLMap(ctx, vt, input.AuthProfile)
				})...)
			}
		}
	} else if s.cfg.EnableSQLMap {
		if !s.cfg.AllowDestructive {
			metrics.ToolRun("sqlmap", "scanner", "skipped", 0)
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
			for _, vt := range state.injectionTargets(input.Target) {
				vt := vt
				emitCmd("sqlmap", "-u "+vt)
				findings = append(findings, s.runInstrumentedTool(ctx, "sqlmap", func() []model.Finding {
					return s.runSQLMap(ctx, vt, input.AuthProfile)
				})...)
			}
		}
	}

	// Phase 6d — OS command injection scanning (commix).
	if input.Options.UseCommixIntegration {
		if !s.cfg.AllowDestructive {
			metrics.ToolRun("commix", "scanner", "skipped", 0)
			findings = append(findings, model.Finding{
				ID:             "commix-blocked-by-safety-policy",
				Category:       "safety",
				Severity:       model.SeverityInfo,
				Title:          "commix blocked by safety policy",
				Description:    "commix actively injects OS command payloads against the target. Destructive or high-impact checks are disabled by default.",
				Evidence:       "ALLOW_DESTRUCTIVE_CHECKS=false",
				Recommendation: "Enable ALLOW_DESTRUCTIVE_CHECKS=true only when the program scope explicitly permits active command-injection testing.",
			})
		} else {
			for _, vt := range state.injectionTargets(input.Target) {
				vt := vt
				emitCmd("commix", "--url="+vt)
				findings = append(findings, s.runInstrumentedTool(ctx, "commix", func() []model.Finding {
					return s.runCommix(ctx, vt, input.AuthProfile)
				})...)
			}
		}
	} else if s.cfg.EnableCommix {
		if !s.cfg.AllowDestructive {
			metrics.ToolRun("commix", "scanner", "skipped", 0)
			findings = append(findings, model.Finding{
				ID:             "commix-auto-blocked-by-safety-policy",
				Category:       "safety",
				Severity:       model.SeverityInfo,
				Title:          "commix auto-run blocked by safety policy",
				Description:    "commix auto-run was skipped because destructive checks are disabled by default.",
				Evidence:       "ALLOW_DESTRUCTIVE_CHECKS=false",
				Recommendation: "Enable ALLOW_DESTRUCTIVE_CHECKS=true only when the program scope explicitly permits this testing.",
			})
		} else {
			findings = append(findings, model.Finding{
				ID:             "commix-auto-triggered",
				Category:       "integration",
				Severity:       model.SeverityInfo,
				Title:          "commix auto-triggered",
				Description:    "commix ran without an explicit per-scan request because ENABLE_COMMIX_INTEGRATION is true in the server configuration.",
				Evidence:       "target=" + input.Target,
				Recommendation: "Review the commix findings below for OS command injection vulnerabilities.",
			})
			for _, vt := range state.injectionTargets(input.Target) {
				vt := vt
				emitCmd("commix", "--url="+vt)
				findings = append(findings, s.runInstrumentedTool(ctx, "commix", func() []model.Finding {
					return s.runCommix(ctx, vt, input.AuthProfile)
				})...)
			}
		}
	}

	// Phase 7 — Vulnerability scanning (primary target + discovered hosts).
	nucleiPhaseRan := false
	if input.Options.UseNucleiIntegration {
		targets, skipped := expandTargetsWithScope(input.Target, state, input.Scope)
		state.TargetsAttempted += len(targets)
		state.TargetsSkipped += skipped
		if skipped > 0 {
			state.SkippedReasons["out_of_scope"] += skipped
		}
		// Also probe the concrete endpoints discovered during Phase 4 so Nuclei
		// templates run against the surfaced attack surface, not just hosts.
		seenNuclei := map[string]struct{}{}
		for _, t := range targets {
			seenNuclei[t] = struct{}{}
		}
		for _, e := range state.validationTargets(input.Target) {
			if _, ok := seenNuclei[e]; ok {
				continue
			}
			seenNuclei[e] = struct{}{}
			targets = append(targets, e)
		}
		for _, t := range targets {
			emitCmd("nuclei", "-u "+t)
			findings = append(findings, s.runInstrumentedTool(ctx, "nuclei", func() []model.Finding {
				return s.runNuclei(ctx, t)
			})...)
		}
		nucleiPhaseRan = true
	}
	// One-time cooldown: give Nuclei time to fully tear down its child
	// processes and release network/socket pressure before any subsequent
	// Phase 7 agent (vulnx, zap-baseline, xssmap) starts.
	if nucleiPhaseRan && cooldownAfterNuclei > 0 {
		if input.Emit != nil {
			input.Emit(model.ScanEvent{
				Type:    model.ScanEventInfo,
				Message: fmt.Sprintf("Waiting %s for Nuclei to fully finish before starting remaining Phase 7 integrations", cooldownAfterNuclei),
			})
		}
		select {
		case <-ctx.Done():
			findings = append(findings, model.Finding{
				ID:             "phase7-skipped-nuclei-cooldown-context-ended",
				Category:       "integration",
				Severity:       model.SeverityInfo,
				Title:          "Phase 7 integrations skipped: scan context ended during post-Nuclei cooldown",
				Description:    "The scan context ended during the post-Nuclei cooldown window, so remaining Phase 7 integrations (vulnx, zap-baseline, xssmap) were not started.",
				Evidence:       "delay=" + cooldownAfterNuclei.String(),
				Recommendation: "Retry the scan with a longer SCAN_TIMEOUT_SECONDS (or a smaller target scope) so the post-Nuclei cooldown and remaining Phase 7 tools can complete.",
			})
			findings = append(findings, buildIntegrationCoverageFinding(state))
			return findings
		case <-time.After(cooldownAfterNuclei):
		}
	}
	if input.Options.UseVulnxIntegration {
		emitCmd("vulnx", "search --limit 20 --silent "+hostFromTarget(input.Target))
		findings = append(findings, s.runInstrumentedTool(ctx, "vulnx", func() []model.Finding {
			return s.runVulnx(ctx, input.Target)
		})...)
	}
	if input.Options.UseRetireJSIntegration {
		emitCmd("retire", "--path <downloaded-js> --outputformat json")
		findings = append(findings, s.runInstrumentedTool(ctx, "retire", func() []model.Finding {
			return s.runRetireJS(ctx, input)
		})...)
	}
	if input.Options.UseTruffleHogIntegration {
		emitCmd("trufflehog", "filesystem <downloaded-js> --json")
		findings = append(findings, s.runInstrumentedTool(ctx, "trufflehog", func() []model.Finding {
			return s.runTruffleHog(ctx, input)
		})...)
	}
	if input.Options.UseZAPBaselineIntegration {
		emitCmd("zap-baseline.py", "-t "+input.Target)
		findings = append(findings, s.runInstrumentedTool(ctx, "zap-baseline", func() []model.Finding {
			return s.runZAPBaseline(ctx, input.Target)
		})...)
	}
	if input.Options.UseXSSMapIntegration {
		if !s.cfg.AllowDestructive {
			metrics.ToolRun("xssmap", "scanner", "skipped", 0)
			findings = append(findings, model.Finding{
				ID:             "xssmap-blocked-by-safety-policy",
				Category:       "safety",
				Severity:       model.SeverityInfo,
				Title:          "XSSMap blocked by safety policy",
				Description:    "XSSMap actively sends XSS payloads against the target. Destructive or high-impact checks are disabled by default.",
				Evidence:       "ALLOW_DESTRUCTIVE_CHECKS=false",
				Recommendation: "Enable ALLOW_DESTRUCTIVE_CHECKS=true only when the program scope explicitly permits active XSS testing.",
			})
		} else {
			for _, vt := range state.injectionTargets(input.Target) {
				vt := vt
				emitCmd("xssmap", "scan --url "+vt)
				findings = append(findings, s.runInstrumentedTool(ctx, "xssmap", func() []model.Finding {
					return s.runXSSMap(ctx, vt)
				})...)
			}
		}
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

	timeoutSecs := int(s.cfg.IntegrationTimeout.Seconds())
	args := []string{"-u", target, "-severity", "medium,high,critical", "-silent"}
	if s.scannerProxy.Enabled && strings.TrimSpace(s.scannerProxy.URL) != "" {
		args = append(args, "-proxy", s.scannerProxy.URL)
	}

	result, err := client.Execute(ctx, args, timeoutSecs)
	if err != nil {
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
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
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
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
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

	timeoutSecs := int(s.cfg.IntegrationTimeout.Seconds())
	args := []string{"-t", target, "-m", "1", "-I"}

	result, err := client.Execute(ctx, args, timeoutSecs)
	if err != nil {
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
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	return buildZAPBaselineFinding(result.Stdout, result.Stderr, result.ExitCode, " (via HTTP service)")
}

func (s *Service) runZAPBaselineExec(ctx context.Context, target string) []model.Finding {
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
	if errors.Is(ictx.Err(), context.DeadlineExceeded) {
		return []model.Finding{{
			ID:             "zap-baseline-timeout",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "ZAP Baseline integration timed out",
			Description:    "ZAP Baseline did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
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

func (s *Service) runInstrumentedTool(ctx context.Context, tool string, fn func() []model.Finding) []model.Finding {
	startedAt := time.Now()
	findings := fn()
	metrics.ToolRun(tool, "scanner", classifyToolStatus(ctx, findings), time.Since(startedAt))
	return findings
}

func classifyToolStatus(ctx context.Context, findings []model.Finding) string {
	// Precedence: timeout/cancelled > error > skipped > success.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "cancelled"
	}
	status := "success"
	for _, f := range findings {
		id := strings.ToLower(strings.TrimSpace(f.ID))
		switch {
		case strings.Contains(id, "timeout"):
			return "timeout"
		case strings.Contains(id, "execution-error"),
			strings.Contains(id, "http-error"),
			strings.Contains(id, "wordlist-error"),
			strings.Contains(id, "service-unavailable"),
			strings.Contains(id, "binary-missing"),
			strings.Contains(id, "parse-error"),
			strings.Contains(id, "failed"):
			status = "error"
		case strings.Contains(id, "disabled"),
			strings.Contains(id, "blocked"),
			strings.Contains(id, "skipped"),
			strings.Contains(id, "not-wordpress"):
			if status == "success" {
				status = "skipped"
			}
		}
	}
	return status
}

// xssmapResult mirrors the JSON contract emitted by the `xssmap` CLI in the
// `xssmap` Docker Compose sidecar. We intentionally keep this contract small
// and forgiving so it survives upstream CLI tweaks: missing fields simply
// produce an unknown value in the resulting Finding evidence rather than a
// parse error.
type xssmapResult struct {
	Vulnerabilities []xssmapVuln `json:"vulnerabilities"`
}

type xssmapVuln struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Type      string `json:"type"`
	Evidence  string `json:"evidence"`
	Severity  string `json:"severity"`
}

func (s *Service) runXSSMap(ctx context.Context, target string) []model.Finding {
	if _, err := exec.LookPath(s.cfg.XSSMapBinary); err != nil {
		return []model.Finding{{
			ID:             "xssmap-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "XSSMap binary not found",
			Description:    "XSSMap integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install xssmap (or run the xssmap docker compose sidecar) or set XSSMAP_BINARY to a valid path.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	args := []string{"scan", "--url", target, "--output", "json"}
	if v := strings.TrimSpace(os.Getenv("XSSMAP_MAX_PAYLOADS")); v != "" {
		args = append(args, "--max-payloads", v)
	}
	if v := strings.TrimSpace(os.Getenv("XSSMAP_MODEL")); v != "" {
		args = append(args, "--model", v)
	} else if v := strings.TrimSpace(os.Getenv("OLLAMA_MODEL")); v != "" {
		args = append(args, "--model", v)
	}
	if v := strings.TrimSpace(os.Getenv("XSSMAP_OLLAMA_URL")); v != "" {
		args = append(args, "--ollama-url", v)
	}

	cmd := exec.CommandContext(ictx, s.cfg.XSSMapBinary, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(ictx.Err(), context.DeadlineExceeded) {
		return []model.Finding{{
			ID:             "xssmap-timeout",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "XSSMap integration timed out",
			Description:    "XSSMap did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS, lower XSSMAP_MAX_PAYLOADS, or reduce scan scope.",
		}}
	}

	out := strings.TrimSpace(stdout.String())
	if err != nil && out == "" {
		return []model.Finding{{
			ID:             "xssmap-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "XSSMap integration failed",
			Description:    "XSSMap did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String() + "\n" + out),
			Recommendation: "Validate xssmap runtime dependencies (Playwright/Ollama) and rerun.",
		}}
	}

	var parsed xssmapResult
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		// Fall back to a coarse summary based on raw output so we still surface
		// a finding even if the upstream CLI changes its JSON shape.
		lines := countNonEmptyLines(out)
		severity := model.SeverityInfo
		title := "XSSMap integration completed (unparsed output)"
		if lines > 0 {
			severity = model.SeverityMedium
			title = "XSSMap integration produced output that could not be parsed as JSON"
		}
		return []model.Finding{{
			ID:             "xssmap-summary",
			Category:       "integration",
			Severity:       severity,
			Title:          title,
			Description:    "XSSMap ran but its stdout was not valid JSON. Review the raw evidence below.",
			Evidence:       "parse_error=" + jerr.Error() + ", lines=" + strconv.Itoa(lines),
			Recommendation: "Inspect raw XSSMap logs or upgrade the xssmap sidecar to align its JSON contract.",
		}}
	}

	if len(parsed.Vulnerabilities) == 0 {
		return []model.Finding{{
			ID:             "xssmap-summary",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "XSSMap integration found no XSS",
			Description:    "Optional LLM-assisted XSS scanner (XSSMap) executed and reported no reflected/DOM XSS.",
			Evidence:       "vulnerabilities=0",
			Recommendation: "No action required. Re-run with a wider --max-payloads budget if confidence is needed.",
		}}
	}

	findings := make([]model.Finding, 0, len(parsed.Vulnerabilities)+1)
	for i, v := range parsed.Vulnerabilities {
		sev := normalizeXSSMapSeverity(v.Severity)
		evidence := fmt.Sprintf("url=%s, parameter=%s, payload=%s", v.URL, v.Parameter, v.Payload)
		if strings.TrimSpace(v.Evidence) != "" {
			evidence += ", evidence=" + v.Evidence
		}
		title := "XSSMap reported reflected XSS"
		if t := strings.TrimSpace(v.Type); t != "" {
			title = "XSSMap reported " + t + " XSS"
		}
		findings = append(findings, model.Finding{
			ID:             fmt.Sprintf("xssmap-finding-%d", i+1),
			Category:       "xss",
			Severity:       sev,
			Title:          title,
			Description:    "XSSMap (LLM-assisted XSS scanner) confirmed an XSS payload reflected on the target. Validate the payload manually before triage.",
			Evidence:       evidence,
			Recommendation: "Encode user-controlled input on output and reproduce the payload manually to confirm exploitability.",
		})
	}
	findings = append(findings, model.Finding{
		ID:             "xssmap-summary",
		Category:       "integration",
		Severity:       model.SeverityInfo,
		Title:          "XSSMap integration reported potential issues",
		Description:    "Optional LLM-assisted XSS scanner (XSSMap) executed and produced one or more candidate findings.",
		Evidence:       "vulnerabilities=" + strconv.Itoa(len(parsed.Vulnerabilities)),
		Recommendation: "Review each xssmap-finding-* entry and verify before remediation.",
	})
	return findings
}

func normalizeXSSMapSeverity(s string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	case "info", "informational":
		return model.SeverityInfo
	default:
		return model.SeverityMedium
	}
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

	findings := []model.Finding{{
		ID:             "httpx-summary",
		Category:       "integration",
		Severity:       severity,
		Title:          title,
		Description:    "Project Discovery httpx HTTP probing and technology detection executed.",
		Evidence:       "probed=" + strconv.Itoa(lines),
		Recommendation: "Review identified technologies and HTTP service metadata for outdated or misconfigured components.",
	}}
	findings = append(findings, s.runWappalyzergo(ctx, target))
	return findings
}

func (s *Service) runWappalyzergo(ctx context.Context, target string) model.Finding {
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ictx, http.MethodGet, target, nil)
	if err != nil {
		return model.Finding{
			ID:             "wappalyzergo-request-error",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "wappalyzergo request setup failed",
			Description:    "Technology fingerprinting via wappalyzergo could not initialize request context.",
			Evidence:       err.Error(),
			Recommendation: "Validate target URL formatting and retry.",
		}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return model.Finding{
			ID:             "wappalyzergo-http-error",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "wappalyzergo HTTP fetch failed",
			Description:    "Technology fingerprinting via wappalyzergo could not fetch target content.",
			Evidence:       err.Error(),
			Recommendation: "Ensure the target is reachable and in scope before rerunning.",
		}
	}
	defer resp.Body.Close()

	const maxFingerprintBodyBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFingerprintBodyBytes))
	if err != nil {
		return model.Finding{
			ID:             "wappalyzergo-read-error",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "wappalyzergo response read failed",
			Description:    "Technology fingerprinting via wappalyzergo could not read target response body.",
			Evidence:       err.Error(),
			Recommendation: "Retry scan after confirming target stability.",
		}
	}

	client, err := wappalyzer.New()
	if err != nil {
		return model.Finding{
			ID:             "wappalyzergo-init-error",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "wappalyzergo initialization failed",
			Description:    "Technology fingerprinting database could not be initialized.",
			Evidence:       err.Error(),
			Recommendation: "Rebuild backend dependencies and retry.",
		}
	}

	fingerprints := client.Fingerprint(resp.Header, body)
	technologies := make([]string, 0, len(fingerprints))
	for tech := range fingerprints {
		technologies = append(technologies, tech)
	}
	sort.Strings(technologies)

	title := "wappalyzergo detected no additional technologies"
	if len(technologies) > 0 {
		title = "wappalyzergo identified web technologies"
	}
	evidence := "technologies=" + strconv.Itoa(len(technologies))
	if len(technologies) > 0 {
		limit := min(8, len(technologies))
		evidence += ", top=" + strings.Join(technologies[:limit], ",")
	}
	return model.Finding{
		ID:             "wappalyzergo-summary",
		Category:       "integration",
		Severity:       model.SeverityInfo,
		Title:          title,
		Description:    "Project Discovery wappalyzergo technology fingerprinting executed alongside httpx -tech-detect.",
		Evidence:       evidence,
		Recommendation: "Correlate detected frameworks with version exposure and known CVEs.",
	}
}

func (s *Service) runCloudlist(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableCloudlist {
		return nil
	}
	if _, err := exec.LookPath(s.cfg.CloudlistBinary); err != nil {
		return []model.Finding{{
			ID:             "cloudlist-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "cloudlist binary not found",
			Description:    "Cloudlist integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install cloudlist in the backend image or set CLOUDLIST_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.CloudlistBinary, "-silent", "-host", "-id", host)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "cloudlist-execution-error",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "cloudlist integration did not return scoped assets",
			Description:    "Cloudlist could not complete provider-backed enumeration for this scoped host filter.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "If cloud inventory integration is intended, provide cloudlist provider credentials and rerun.",
		}}
	}

	matches := countNonEmptyLines(stdout.String())
	title := "cloudlist found no cloud assets matching target host"
	if matches > 0 {
		title = "cloudlist discovered cloud assets matching target host"
	}
	return []model.Finding{{
		ID:             "cloudlist-summary",
		Category:       "integration",
		Severity:       model.SeverityInfo,
		Title:          title,
		Description:    "Project Discovery cloudlist multi-cloud inventory enumeration executed with host filtering.",
		Evidence:       "host=" + host + ", assets=" + strconv.Itoa(matches),
		Recommendation: "Cross-check discovered cloud assets against authorized scope and exposed attack surface.",
	}}
}

func (s *Service) runVulnx(ctx context.Context, target string) []model.Finding {
	if !s.cfg.EnableVulnx {
		return []model.Finding{{
			ID:             "vulnx-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "vulnx integration requested but disabled",
			Description:    "The job requested vulnx but ENABLE_VULNX_INTEGRATION is false.",
			Evidence:       "ENABLE_VULNX_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.VulnxBinary); err != nil {
		return []model.Finding{{
			ID:             "vulnx-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "vulnx binary not found",
			Description:    "vulnx integration is enabled but binary is missing in the runtime image.",
			Evidence:       err.Error(),
			Recommendation: "Install vulnx in the backend image or set VULNX_BINARY to a valid path.",
		}}
	}

	host := hostFromTarget(target)
	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ictx, s.cfg.VulnxBinary, "search", "--limit", "20", "--silent", host)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return []model.Finding{{
			ID:             "vulnx-execution-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "vulnx integration failed",
			Description:    "vulnx did not complete successfully.",
			Evidence:       strings.TrimSpace(stderr.String()),
			Recommendation: "Validate vulnx configuration (including API auth/rate limits) and retry.",
		}}
	}

	matches := countNonEmptyLines(stdout.String())
	title := "vulnx found no vulnerability intelligence matches"
	if matches > 0 {
		title = "vulnx correlated vulnerability intelligence"
	}
	return []model.Finding{{
		ID:             "vulnx-summary",
		Category:       "integration",
		Severity:       model.SeverityInfo,
		Title:          title,
		Description:    "Project Discovery vulnx vulnerability intelligence query executed against the target host context.",
		Evidence:       "host=" + host + ", matches=" + strconv.Itoa(matches),
		Recommendation: "Review vulnx results and prioritize critical/high entries relevant to detected technologies.",
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

func (s *Service) runKatana(ctx context.Context, target string, depth int, scanScope model.ScanScope, state *integrationState) []model.Finding {
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
	// Capture the crawled URLs (one per line in -silent mode) into the shared
	// discovery registry so downstream validation tools can reuse them.
	crawled := make([]string, 0, endpoints)
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		if !scope.IsURLInScope(line, scanScope) {
			continue
		}
		crawled = append(crawled, line)
	}
	state.addEndpoints(crawled...)
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

func (s *Service) runFFUF(ctx context.Context, target string, scanScope model.ScanScope, state *integrationState) []model.Finding {
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
	paths = filterStateChangingPaths(ctx, s.httpClient, target, paths, model.ScanAuthProfile{}, scanScope, 5, s.cfg.IntegrationTimeout)

	// Record discovered paths as absolute, in-scope endpoint URLs so the deeper
	// validation phases (sqlmap, commix, nuclei, xssmap) can reuse them as
	// additional targets instead of only probing the base URL.
	baseTrim := strings.TrimRight(target, "/")
	endpointURLs := make([]string, 0, len(paths))
	for _, p := range paths {
		endpointURLs = append(endpointURLs, baseTrim+p)
	}
	state.addEndpoints(endpointURLs...)

	// Second pass: fuzz hidden query-string parameters so FFUF covers parameter
	// inputs, not just paths. Discovered parameter names are recorded so they
	// become injection points for sqlmap/commix downstream.
	params := s.ffufFuzzParameters(ctx, target, scanScope)
	state.addParams(params...)

	findings := make([]model.Finding, 0, 2)
	if len(paths) == 0 {
		findings = append(findings, model.Finding{
			ID:             "ffuf-no-paths",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "FFUF found no candidate paths",
			Description:    "FFUF completed but did not report in-scope matches from the configured wordlist.",
			Evidence:       "target=" + target,
			Recommendation: "Try broader wordlists, different match filters, or authenticated profiles.",
		})
	} else {
		findings = append(findings, model.Finding{
			ID:             "ffuf-path-discovery",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          "FFUF discovered candidate paths",
			Description:    "FFUF discovered in-scope endpoint candidates using directory fuzzing.",
			Evidence:       strings.Join(limitStrings(paths, 20), ", "),
			Recommendation: "Review discovered paths for authentication, authorization, and input-validation flaws.",
			Sources:        []string{"ffuf"},
			Confidence:     0.8,
		})
	}
	if len(params) > 0 {
		findings = append(findings, model.Finding{
			ID:             "ffuf-parameter-discovery",
			Category:       "discovery",
			Severity:       model.SeverityLow,
			Title:          "FFUF discovered hidden query parameters",
			Description:    "FFUF parameter fuzzing surfaced query-string parameters that change the application's response. Hidden parameters frequently expose additional, less-tested input-handling code paths.",
			Evidence:       fmt.Sprintf("target=%s; params=%s", target, strings.Join(limitStrings(params, 30), ", ")),
			Recommendation: "Fuzz the discovered parameters for injection, access-control, and business-logic flaws.",
			Sources:        []string{"ffuf"},
			Confidence:     0.7,
		})
	}
	return findings
}

// ffufParamProbeValue is the benign sentinel value assigned to the FUZZ
// parameter name during FFUF parameter mining.
const ffufParamProbeValue = "autobughunterprobe"

// commonParameterNames is a compact, built-in wordlist of frequently accepted
// HTTP parameter names used for FFUF parameter mining. It keeps the second FFUF
// pass fast and fully offline; broader external wordlists can be layered later.
var commonParameterNames = []string{
	"id", "user", "user_id", "userid", "uid", "account", "account_id", "name",
	"username", "email", "page", "p", "q", "query", "search", "s", "keyword",
	"sort", "order", "order_by", "dir", "filter", "category", "cat", "type",
	"action", "do", "cmd", "command", "exec", "func", "function", "method",
	"file", "filename", "path", "dir", "folder", "url", "uri", "redirect",
	"return", "return_url", "next", "callback", "continue", "dest", "destination",
	"ref", "referer", "lang", "language", "locale", "token", "key", "api_key",
	"apikey", "access_token", "auth", "session", "sid", "code", "debug", "test",
	"view", "format", "output", "limit", "offset", "start", "count", "size",
	"price", "amount", "qty", "quantity", "status", "state", "role", "group",
}

// ffufFuzzParameters runs a second FFUF pass that mines hidden query-string
// parameters on the target. It assigns a sentinel value to a FUZZed parameter
// name and relies on FFUF auto-calibration (-ac) to filter baseline responses,
// so only parameter names that alter the application's behaviour are reported.
// It returns the discovered parameter names (sorted, de-duplicated).
func (s *Service) ffufFuzzParameters(ctx context.Context, target string, scanScope model.ScanScope) []string {
	if !scope.IsURLInScope(target, scanScope) {
		return nil
	}
	wlPath, err := writeTemporaryWordlist(commonParameterNames)
	if err != nil {
		return nil
	}
	defer os.Remove(wlPath)

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	fuzzURL := strings.TrimRight(target, "/") + "/?FUZZ=" + ffufParamProbeValue
	cmd := exec.CommandContext(ictx, s.cfg.FFUFBinary, "-u", fuzzURL, "-w", wlPath, "-ac", "-mc", "all", "-s")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	_ = cmd.Run()
	if ictx.Err() == context.DeadlineExceeded {
		return nil
	}
	return parseFFUFParamHits(outb.String())
}

// parseFFUFParamHits parses the silent (-s) FFUF parameter-mining output, where
// each non-empty line is a matched FUZZ parameter name. It keeps syntactically
// valid parameter tokens and returns a sorted, de-duplicated list.
func parseFFUFParamHits(rawOutput string) []string {
	seen := map[string]struct{}{}
	params := make([]string, 0)
	for _, line := range strings.Split(rawOutput, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || name == ffufParamProbeValue {
			continue
		}
		if strings.Fields(name)[0] != name {
			// Skip banner/log lines that contain spaces.
			continue
		}
		if !isValidParamName(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		params = append(params, name)
	}
	sort.Strings(params)
	return params
}

// isValidParamName reports whether token looks like an HTTP parameter name
// (letters, digits, underscore, dash, or dot only) and is of a sane length.
func isValidParamName(token string) bool {
	if token == "" || len(token) > 64 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

func (s *Service) runGobuster(ctx context.Context, target string, scanScope model.ScanScope, state *integrationState) []model.Finding {
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
	paths = filterStateChangingPaths(ctx, s.httpClient, target, paths, model.ScanAuthProfile{}, scanScope, 5, s.cfg.IntegrationTimeout)
	baseTrim := strings.TrimRight(target, "/")
	gobusterEndpoints := make([]string, 0, len(paths))
	for _, p := range paths {
		gobusterEndpoints = append(gobusterEndpoints, baseTrim+p)
	}
	state.addEndpoints(gobusterEndpoints...)
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

// runKiterunner executes kiterunner (kr) to brute-force API routes against the
// target using an API-route wordlist. It mirrors the disabled/binary-missing/
// timeout/no-paths finding contract used by the ffuf and gobuster integrations.
func (s *Service) runKiterunner(ctx context.Context, target string, scanScope model.ScanScope, state *integrationState) []model.Finding {
	if !s.cfg.EnableKiterunner {
		return []model.Finding{{
			ID:             "kiterunner-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Kiterunner integration requested but disabled",
			Description:    "The job requested Kiterunner but ENABLE_KITERUNNER_INTEGRATION is false.",
			Evidence:       "ENABLE_KITERUNNER_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.KiterunnerBinary); err != nil {
		return []model.Finding{{
			ID:             "kiterunner-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Kiterunner binary not found",
			Description:    "Kiterunner integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install Kiterunner or set KITERUNNER_BINARY to the binary path.",
		}}
	}

	// Prefer a curated API-route wordlist (.kite/.txt) when one is available.
	// The kiterunner sidecar pre-downloads Assetnote route wordlists into
	// ASSETNOTE_WORDLIST_DIR (/wordlists); fall back to the shared scratch dir
	// and finally to a temporary wordlist derived from the common-directory
	// list (the same source ffuf/gobuster use).
	wordlistPath := findKiterunnerWordlistFile(os.Getenv("ASSETNOTE_WORDLIST_DIR"))
	if wordlistPath == "" {
		wordlistPath = findKiterunnerWordlistFile(os.Getenv("SHARED_TMP_DIR"))
	}
	cleanup := func() {}
	if wordlistPath == "" {
		tmp, err := writeTemporaryWordlist(wordlist.GetCommonDirectoriesWithExternal(ctx))
		if err != nil {
			return []model.Finding{{
				ID:             "kiterunner-wordlist-error",
				Category:       "integration",
				Severity:       model.SeverityLow,
				Title:          "Kiterunner wordlist preparation failed",
				Description:    "Could not prepare a temporary wordlist for Kiterunner.",
				Evidence:       err.Error(),
				Recommendation: "Retry scan or provide runner filesystem permissions for temporary files.",
			}}
		}
		wordlistPath = tmp
		cleanup = func() { os.Remove(tmp) }
	}
	defer cleanup()

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.KiterunnerBinary, "scan", strings.TrimRight(target, "/"), "-w", wordlistPath, "-x", "5", "-o", "text")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "kiterunner-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Kiterunner timed out",
			Description:    "Kiterunner did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	paths := parseKiterunnerHits(outb.String(), target, scanScope)
	paths = filterStateChangingPaths(ctx, s.httpClient, target, paths, model.ScanAuthProfile{}, scanScope, 5, s.cfg.IntegrationTimeout)
	baseTrim := strings.TrimRight(target, "/")
	krEndpoints := make([]string, 0, len(paths))
	for _, p := range paths {
		krEndpoints = append(krEndpoints, baseTrim+p)
	}
	state.addEndpoints(krEndpoints...)
	if len(paths) == 0 {
		return []model.Finding{{
			ID:             "kiterunner-no-paths",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Kiterunner found no candidate API routes",
			Description:    "Kiterunner completed but did not report in-scope API route matches from the configured wordlist.",
			Evidence:       "target=" + target,
			Recommendation: "Try a broader API-route wordlist (.kite) or authenticated profiles.",
		}}
	}
	return []model.Finding{{
		ID:             "kiterunner-route-discovery",
		Category:       "discovery",
		Severity:       model.SeverityInfo,
		Title:          "Kiterunner discovered candidate API routes",
		Description:    "Kiterunner discovered in-scope API endpoint candidates using route brute-force.",
		Evidence:       strings.Join(limitStrings(paths, 20), ", "),
		Recommendation: "Review discovered API routes for authentication, authorization, and input-validation flaws.",
		Sources:        []string{"kiterunner"},
		Confidence:     0.8,
	}}
}

// parseKiterunnerHits parses kiterunner text output. Each result line places the
// HTTP method and status first, with the matched URL as a later whitespace
// field (e.g. "GET 200 [ 363, 10, 1] https://host/api/v1/users 0cf6841"). It
// isolates the URL column, keeps only in-scope http(s) results, and returns a
// sorted, de-duplicated list of paths.
func parseKiterunnerHits(rawOutput, target string, scanScope model.ScanScope) []string {
	lines := strings.Split(rawOutput, "\n")
	paths := make([]string, 0)
	seen := map[string]struct{}{}
	methods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Result lines begin with an HTTP method token (e.g. "GET 200 ...").
		// This skips kiterunner's log/banner lines such as "[*] Scanning ...".
		if !methods[strings.ToUpper(fields[0])] {
			continue
		}
		// Locate the first http(s) field in the line; the leading fields are the
		// method, status and size columns, which must not be captured as a path.
		var rawURL string
		for _, field := range fields {
			if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
				rawURL = field
				break
			}
		}
		if rawURL == "" {
			continue
		}
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if !scope.IsURLInScope(rawURL, scanScope) {
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

// findKiterunnerWordlistFile locates a curated API-route wordlist within dir. It
// prefers a compiled ".kite" file under a "kiterunner" subdirectory, then falls
// back to any ".txt" file in dir. It returns "" when dir is empty, missing, or
// contains no suitable file.
func findKiterunnerWordlistFile(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return ""
	}
	sub := filepath.Join(dir, "kiterunner")
	if entries, err := os.ReadDir(sub); err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".kite") {
				names = append(names, e.Name())
			}
		}
		if len(names) > 0 {
			sort.Strings(names)
			return filepath.Join(sub, names[0])
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return filepath.Join(dir, names[0])
}

// runGau executes gau (GetAllUrls) to passively harvest historical URLs for the
// target host from open sources (Wayback Machine, Common Crawl, etc.). It is a
// passive, non-destructive integration: it queries third-party archives rather
// than the target itself.
func (s *Service) runGau(ctx context.Context, target string, scanScope model.ScanScope, state *integrationState) []model.Finding {
	if !s.cfg.EnableGau {
		return []model.Finding{{
			ID:             "gau-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "gau integration requested but disabled",
			Description:    "The job requested gau but ENABLE_GAU_INTEGRATION is false.",
			Evidence:       "ENABLE_GAU_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.GauBinary); err != nil {
		return []model.Finding{{
			ID:             "gau-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "gau binary not found",
			Description:    "gau integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install gau or set GAU_BINARY to the binary path.",
		}}
	}

	host := hostFromTarget(target)
	if host == "" {
		return []model.Finding{{
			ID:             "gau-invalid-target",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "gau could not derive a host from the target",
			Description:    "gau requires a hostname derived from the target URL.",
			Evidence:       "target=" + target,
			Recommendation: "Provide a target with a valid hostname.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.GauBinary, "--subs", "--threads", "5", host)
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "gau-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "gau timed out",
			Description:    "gau did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	urls := parseGauURLs(outb.String(), scanScope)
	state.addEndpoints(urls...)
	if len(urls) == 0 {
		return []model.Finding{{
			ID:             "gau-no-urls",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "gau found no archived URLs",
			Description:    "gau completed but did not return any in-scope archived URLs for the target host.",
			Evidence:       "host=" + host,
			Recommendation: "The target may have little public history; combine with active crawling (katana) for coverage.",
		}}
	}
	return []model.Finding{{
		ID:             "gau-url-discovery",
		Category:       "discovery",
		Severity:       model.SeverityInfo,
		Title:          "gau discovered archived URLs",
		Description:    "gau harvested historical, in-scope URLs from public archives (Wayback Machine, Common Crawl, etc.).",
		Evidence:       fmt.Sprintf("count=%d; %s", len(urls), strings.Join(limitStrings(urls, 20), ", ")),
		Recommendation: "Review archived URLs for forgotten endpoints, parameters, and exposed functionality, then probe in-scope candidates.",
		Sources:        []string{"gau"},
		Confidence:     0.8,
	}}
}

// parseGauURLs parses gau stdout (one URL per line), keeps only in-scope,
// well-formed http(s) URLs, and returns a sorted, de-duplicated list.
func parseGauURLs(rawOutput string, scanScope model.ScanScope) []string {
	lines := strings.Split(rawOutput, "\n")
	urls := make([]string, 0)
	seen := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		if _, err := url.Parse(line); err != nil {
			continue
		}
		if !scope.IsURLInScope(line, scanScope) {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		urls = append(urls, line)
	}
	sort.Strings(urls)
	return urls
}

// runArjun executes Arjun to discover hidden HTTP query/body parameters on the
// target endpoint. Arjun sends many requests with candidate parameter names but
// does not send exploit payloads, so it is treated as non-destructive.
func (s *Service) runArjun(ctx context.Context, target string, scanScope model.ScanScope, state *integrationState) []model.Finding {
	if !s.cfg.EnableArjun {
		return []model.Finding{{
			ID:             "arjun-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Arjun integration requested but disabled",
			Description:    "The job requested Arjun but ENABLE_ARJUN_INTEGRATION is false.",
			Evidence:       "ENABLE_ARJUN_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.ArjunBinary); err != nil {
		return []model.Finding{{
			ID:             "arjun-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Arjun binary not found",
			Description:    "Arjun integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install Arjun or set ARJUN_BINARY to the binary path.",
		}}
	}
	if !scope.IsURLInScope(target, scanScope) {
		return []model.Finding{{
			ID:             "arjun-out-of-scope",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Arjun target out of scope",
			Description:    "The target URL is not in scope for parameter discovery.",
			Evidence:       "target=" + target,
			Recommendation: "Adjust the scan scope to include the target before running Arjun.",
		}}
	}

	// Arjun writes machine-readable results to a JSON file that must live in a
	// directory shared with the arjun sidecar (SHARED_TMP_DIR), mirroring the
	// wordlist sharing used by ffuf/gobuster.
	outDir := os.Getenv("SHARED_TMP_DIR")
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return []model.Finding{{
				ID:             "arjun-output-error",
				Category:       "integration",
				Severity:       model.SeverityLow,
				Title:          "Arjun output preparation failed",
				Description:    "Could not prepare a shared output directory for Arjun.",
				Evidence:       err.Error(),
				Recommendation: "Ensure SHARED_TMP_DIR is writable by the backend container.",
			}}
		}
	}
	outFile, err := os.CreateTemp(outDir, "auto-bughunter-arjun-*.json")
	if err != nil {
		return []model.Finding{{
			ID:             "arjun-output-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "Arjun output preparation failed",
			Description:    "Could not create a temporary output file for Arjun.",
			Evidence:       err.Error(),
			Recommendation: "Retry scan or provide runner filesystem permissions for temporary files.",
		}}
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.ArjunBinary, "-u", target, "-oJ", outPath, "-t", "10", "-q")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "arjun-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Arjun timed out",
			Description:    "Arjun did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		data = nil
	}
	params := parseArjunParams(data)
	state.addParams(params...)
	if len(params) == 0 {
		return []model.Finding{{
			ID:             "arjun-no-params",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Arjun found no hidden parameters",
			Description:    "Arjun completed but did not discover any hidden parameters on the target endpoint.",
			Evidence:       "target=" + target,
			Recommendation: "Try additional endpoints, HTTP methods, or larger parameter wordlists.",
		}}
	}
	return []model.Finding{{
		ID:             "arjun-parameter-discovery",
		Category:       "discovery",
		Severity:       model.SeverityLow,
		Title:          "Arjun discovered hidden parameters",
		Description:    "Arjun discovered HTTP parameters that are not linked from the page but are accepted by the endpoint. Hidden parameters frequently expose additional, less-tested input-handling code paths.",
		Evidence:       fmt.Sprintf("target=%s; params=%s", target, strings.Join(limitStrings(params, 30), ", ")),
		Recommendation: "Fuzz the discovered parameters for injection, access-control, and business-logic flaws.",
		Sources:        []string{"arjun"},
		Confidence:     0.75,
	}}
}

// parseArjunParams parses Arjun's JSON output (-oJ). Arjun versions emit either
// {"<url>": ["p1","p2"]} or {"<url>": {"params": ["p1"], "method": "GET"}}, so
// both shapes are handled. Returns a sorted, de-duplicated list of parameters.
func parseArjunParams(data []byte) []string {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	params := make([]string, 0)
	add := func(list []string) {
		for _, p := range list {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			params = append(params, p)
		}
	}
	for _, v := range raw {
		var list []string
		if err := json.Unmarshal(v, &list); err == nil {
			add(list)
			continue
		}
		var obj struct {
			Params []string `json:"params"`
		}
		if err := json.Unmarshal(v, &obj); err == nil {
			add(obj.Params)
		}
	}
	sort.Strings(params)
	return params
}

// runCommix executes commix to detect OS command injection on the target. It is
// an active, destructive integration and must only run when AllowDestructive is
// enabled (enforced by the caller in runOptionalIntegrations).
func (s *Service) runCommix(ctx context.Context, target string, authProfile model.ScanAuthProfile) []model.Finding {
	if !s.cfg.EnableCommix {
		return []model.Finding{{
			ID:             "commix-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "commix integration requested but disabled",
			Description:    "The job requested commix but ENABLE_COMMIX_INTEGRATION is false.",
			Evidence:       "ENABLE_COMMIX_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.CommixBinary); err != nil {
		return []model.Finding{{
			ID:             "commix-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "commix binary not found",
			Description:    "commix integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install commix or set COMMIX_BINARY to the binary path.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	args := []string{"--url=" + target, "--batch", "--disable-coloring"}
	if cookie := joinCookieHeader(authProfile.Cookies); cookie != "" {
		args = append(args, "--cookie="+cookie)
	}
	cmd := exec.CommandContext(ictx, s.cfg.CommixBinary, args...)
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "commix-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "commix timed out",
			Description:    "commix did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	if commixReportsVulnerable(outb.String()) {
		return []model.Finding{{
			ID:             "commix-command-injection",
			Category:       "command-injection",
			Severity:       model.SeverityCritical,
			Title:          "commix detected OS command injection",
			Description:    "commix reported that the target appears vulnerable to OS command injection, which can allow arbitrary command execution on the host.",
			Evidence:       "target=" + target,
			Recommendation: "Treat as critical: validate the injection point manually, then remediate by removing shell invocation or strictly allow-listing and escaping inputs.",
			Sources:        []string{"commix"},
			Confidence:     0.85,
		}}
	}
	return []model.Finding{{
		ID:             "commix-no-injection",
		Category:       "integration",
		Severity:       model.SeverityInfo,
		Title:          "commix found no command injection",
		Description:    "commix completed but did not report an OS command injection vulnerability on the target.",
		Evidence:       "target=" + target,
		Recommendation: "Re-run against specific parameterised endpoints or with authenticated profiles for deeper coverage.",
	}}
}

// joinCookieHeader renders an auth profile cookie map as a single Cookie
// header value (name1=value1; name2=value2) with deterministic ordering.
func joinCookieHeader(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}
	keys := make([]string, 0, len(cookies))
	for k := range cookies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+cookies[k])
	}
	return strings.Join(parts, "; ")
}

// commixReportsVulnerable scans commix stdout for its vulnerability markers.
func commixReportsVulnerable(output string) bool {
	lower := strings.ToLower(output)
	markers := []string{
		"is vulnerable",
		"appears to be injectable",
		"injectable",
		"the ('--technique') option",
		"command injection vulnerability",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// jsDownloadMaxScripts caps how many in-scope script bundles the retire.js and
// trufflehog integrations download per scan, mirroring the secrets-in-JS probe
// budget so scan time stays bounded on apps that load many third-party scripts.
const jsDownloadMaxScripts = 8

// jsDownloadMaxBytes caps how much of any single script (or the target HTML) is
// read into memory before the retire.js / trufflehog scans run.
const jsDownloadMaxBytes int64 = 1 << 20

// runUncover queries Uncover (ProjectDiscovery) to surface internet-exposed
// hosts/services for the target from third-party search engines (Shodan,
// Censys, Fofa, …). It is a passive, non-destructive integration: it queries
// the configured search-engine APIs rather than the target itself. In-scope
// hosts are added to the shared discovery state so later phases can probe them.
func (s *Service) runUncover(ctx context.Context, target string, state *integrationState, scanScope model.ScanScope) []model.Finding {
	if !s.cfg.EnableUncover {
		return []model.Finding{{
			ID:             "uncover-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Uncover integration requested but disabled",
			Description:    "The job requested Uncover but ENABLE_UNCOVER_INTEGRATION is false.",
			Evidence:       "ENABLE_UNCOVER_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.UncoverBinary); err != nil {
		return []model.Finding{{
			ID:             "uncover-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Uncover binary not found",
			Description:    "Uncover integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install uncover or set UNCOVER_BINARY to the binary path.",
		}}
	}

	host := hostFromTarget(target)
	if host == "" {
		return []model.Finding{{
			ID:             "uncover-invalid-target",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Uncover could not derive a host from the target",
			Description:    "Uncover requires a hostname derived from the target URL.",
			Evidence:       "target=" + target,
			Recommendation: "Provide a target with a valid hostname.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.UncoverBinary, "-q", host, "-silent")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "uncover-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Uncover timed out",
			Description:    "Uncover did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or configure search-engine API keys for faster results.",
		}}
	}

	subScope := defaultSubdomainScope(target)
	inScope := make([]string, 0)
	endpoints := make([]string, 0)
	seen := map[string]struct{}{}
	for _, line := range strings.Split(outb.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hostPart := line
		// Uncover prints "host:port"; keep only the host portion for scoping.
		if idx := strings.LastIndex(line, ":"); idx > 0 && !strings.Contains(line[idx+1:], ".") {
			hostPart = line[:idx]
		}
		nh := normalizeDiscoveredHost(hostPart)
		if nh == "" {
			continue
		}
		if _, ok := seen[nh]; ok {
			continue
		}
		seen[nh] = struct{}{}
		endpoints = append(endpoints, line)
		if scope.IsHostInScope(nh, subScope) {
			inScope = append(inScope, nh)
		} else if state != nil {
			state.OutOfScopeHosts = append(state.OutOfScopeHosts, nh)
			state.SkippedReasons["discovered_out_of_scope"]++
		}
	}
	addDiscoveredHosts(state, inScope)
	sort.Strings(endpoints)

	if len(endpoints) == 0 {
		return []model.Finding{{
			ID:             "uncover-no-hosts",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "Uncover found no exposed hosts",
			Description:    "Uncover completed but returned no exposed hosts/services for the target. Search-engine API keys may be required for results.",
			Evidence:       "host=" + host,
			Recommendation: "Configure Shodan/Censys/Fofa API keys for Uncover, or rely on other discovery integrations.",
		}}
	}
	severity := model.SeverityInfo
	title := "Uncover discovered exposed hosts"
	if len(inScope) > 0 {
		severity = model.SeverityMedium
	}
	return []model.Finding{{
		ID:             "uncover-exposed-hosts",
		Category:       "discovery",
		Severity:       severity,
		Title:          title,
		Description:    "Uncover surfaced internet-exposed hosts/services for the target from third-party search engines (Shodan, Censys, Fofa, …).",
		Evidence:       fmt.Sprintf("inScope=%d; results=%s", len(inScope), strings.Join(limitStrings(endpoints, 20), ", ")),
		Recommendation: "Review exposed services for unintended exposure (admin panels, databases, staging hosts) and probe in-scope candidates.",
		Sources:        []string{"uncover"},
		Confidence:     0.8,
	}}
}

// runLinkFinder executes LinkFinder to extract endpoints/paths embedded in the
// target's JavaScript. LinkFinder fetches the page/JS and regex-parses it; it
// never injects payloads, so it is treated as passive/non-destructive.
func (s *Service) runLinkFinder(ctx context.Context, target string, scanScope model.ScanScope, state *integrationState) []model.Finding {
	if !s.cfg.EnableLinkFinder {
		return []model.Finding{{
			ID:             "linkfinder-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "LinkFinder integration requested but disabled",
			Description:    "The job requested LinkFinder but ENABLE_LINKFINDER_INTEGRATION is false.",
			Evidence:       "ENABLE_LINKFINDER_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.LinkFinderBinary); err != nil {
		return []model.Finding{{
			ID:             "linkfinder-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "LinkFinder binary not found",
			Description:    "LinkFinder integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install LinkFinder or set LINKFINDER_BINARY to the binary path.",
		}}
	}
	if !scope.IsURLInScope(target, scanScope) {
		return []model.Finding{{
			ID:             "linkfinder-out-of-scope",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "LinkFinder target out of scope",
			Description:    "The target URL is not in scope for endpoint discovery.",
			Evidence:       "target=" + target,
			Recommendation: "Adjust the scan scope to include the target before running LinkFinder.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.LinkFinderBinary, "-i", target, "-o", "cli")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if err := cmd.Run(); err != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "linkfinder-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "LinkFinder timed out",
			Description:    "LinkFinder did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	endpoints := parseLinkFinderEndpoints(outb.String(), target, scanScope)
	state.addEndpoints(endpoints...)
	if len(endpoints) == 0 {
		return []model.Finding{{
			ID:             "linkfinder-no-endpoints",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "LinkFinder found no endpoints",
			Description:    "LinkFinder completed but did not extract any in-scope endpoints from the target's JavaScript.",
			Evidence:       "target=" + target,
			Recommendation: "Try additional JS bundles or combine with active crawling (katana) for coverage.",
		}}
	}
	return []model.Finding{{
		ID:             "linkfinder-endpoint-discovery",
		Category:       "discovery",
		Severity:       model.SeverityInfo,
		Title:          "LinkFinder discovered endpoints in JavaScript",
		Description:    "LinkFinder extracted endpoints/paths referenced from the target's client-side JavaScript. These frequently expose API routes and functionality not linked from the rendered UI.",
		Evidence:       fmt.Sprintf("count=%d; %s", len(endpoints), strings.Join(limitStrings(endpoints, 20), ", ")),
		Recommendation: "Review the discovered endpoints for forgotten APIs and undocumented functionality, then probe in-scope candidates for access-control and injection flaws.",
		Sources:        []string{"linkfinder"},
		Confidence:     0.75,
	}}
}

// parseLinkFinderEndpoints parses LinkFinder's CLI output (one endpoint per
// line), resolves relative endpoints against the target, keeps only in-scope
// http(s) URLs, and returns a sorted, de-duplicated list.
func parseLinkFinderEndpoints(rawOutput, target string, scanScope model.ScanScope) []string {
	base, err := url.Parse(target)
	if err != nil {
		base = nil
	}
	endpoints := make([]string, 0)
	seen := map[string]struct{}{}
	for _, line := range strings.Split(rawOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// LinkFinder prints raw endpoint strings; skip obvious non-endpoints.
		if !strings.Contains(line, "/") && !strings.HasPrefix(line, "http") {
			continue
		}
		var abs string
		switch {
		case strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://"):
			abs = line
		case base != nil:
			ref, perr := url.Parse(line)
			if perr != nil {
				continue
			}
			abs = base.ResolveReference(ref).String()
		default:
			continue
		}
		if !strings.HasPrefix(abs, "http://") && !strings.HasPrefix(abs, "https://") {
			continue
		}
		if !scope.IsURLInScope(abs, scanScope) {
			continue
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		endpoints = append(endpoints, abs)
	}
	sort.Strings(endpoints)
	return endpoints
}

// downloadInScopeScripts fetches the target's HTML, resolves the in-scope,
// SSRF-safe JavaScript bundles it references, and downloads each (subject to
// budgets) into a fresh directory under SHARED_TMP_DIR so the retire.js and
// trufflehog sidecars can scan them at the same path. The caller owns the
// returned directory and must remove it. Returns the directory and the number
// of scripts written.
func (s *Service) downloadInScopeScripts(ctx context.Context, input RunInput) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
	if err != nil {
		return "", 0, err
	}
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return "", 0, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, jsDownloadMaxBytes))
	_ = resp.Body.Close()

	scriptURLs := extractScriptURLs(input.Target, string(body), input.Scope)
	if len(scriptURLs) == 0 {
		return "", 0, nil
	}
	if len(scriptURLs) > jsDownloadMaxScripts {
		scriptURLs = scriptURLs[:jsDownloadMaxScripts]
	}

	base := os.Getenv("SHARED_TMP_DIR")
	if base != "" {
		if err := os.MkdirAll(base, 0o755); err != nil {
			return "", 0, err
		}
	}
	dir, err := os.MkdirTemp(base, "auto-bughunter-js-*")
	if err != nil {
		return "", 0, err
	}

	count := 0
	for i, scriptURL := range scriptURLs {
		// extractScriptURLs already validated scope + SSRF safety.
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(r, input.AuthProfile)
		rp, err := s.doRequestWithRetry(ctx, r, input.Options)
		if err != nil || rp == nil {
			continue
		}
		content, _ := io.ReadAll(io.LimitReader(rp.Body, jsDownloadMaxBytes))
		_ = rp.Body.Close()
		if len(content) == 0 {
			continue
		}
		fp := filepath.Join(dir, fmt.Sprintf("script-%d.js", i))
		if err := os.WriteFile(fp, content, 0o644); err != nil {
			continue
		}
		count++
	}
	return dir, count, nil
}

// runRetireJS downloads the target's in-scope JavaScript bundles and runs
// retire.js against them to detect JavaScript libraries with publicly known
// vulnerabilities. It is passive/non-destructive: it only reads resources the
// application already serves.
func (s *Service) runRetireJS(ctx context.Context, input RunInput) []model.Finding {
	if !s.cfg.EnableRetireJS {
		return []model.Finding{{
			ID:             "retirejs-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "retire.js integration requested but disabled",
			Description:    "The job requested retire.js but ENABLE_RETIREJS_INTEGRATION is false.",
			Evidence:       "ENABLE_RETIREJS_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.RetireJSBinary); err != nil {
		return []model.Finding{{
			ID:             "retirejs-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "retire.js binary not found",
			Description:    "retire.js integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install retire.js (npm i -g retire) or set RETIREJS_BINARY to the binary path.",
		}}
	}

	dir, count, err := s.downloadInScopeScripts(ctx, input)
	if dir != "" {
		defer os.RemoveAll(dir)
	}
	if err != nil {
		return []model.Finding{{
			ID:             "retirejs-fetch-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "retire.js could not prepare JavaScript bundles",
			Description:    "Fetching or storing the target's JavaScript bundles for retire.js failed.",
			Evidence:       err.Error(),
			Recommendation: "Ensure SHARED_TMP_DIR is writable and the target is reachable, then retry.",
		}}
	}
	if count == 0 {
		return []model.Finding{{
			ID:             "retirejs-no-scripts",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "retire.js found no JavaScript to scan",
			Description:    "No in-scope JavaScript bundles were discovered on the target, so retire.js had nothing to analyse.",
			Evidence:       "target=" + input.Target,
			Recommendation: "Combine with active crawling (katana) to discover additional script bundles.",
		}}
	}

	outFile, err := os.CreateTemp(dir, "retire-*.json")
	if err != nil {
		return []model.Finding{{
			ID:             "retirejs-output-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "retire.js output preparation failed",
			Description:    "Could not create a temporary output file for retire.js.",
			Evidence:       err.Error(),
			Recommendation: "Ensure SHARED_TMP_DIR is writable by the backend container.",
		}}
	}
	outPath := outFile.Name()
	outFile.Close()

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.RetireJSBinary,
		"--path", dir, "--outputformat", "json", "--outputpath", outPath, "--exitwith", "0")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if runErr := cmd.Run(); runErr != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "retirejs-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "retire.js timed out",
			Description:    "retire.js did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	data, _ := os.ReadFile(outPath)
	vulns := parseRetireJSVulns(data)
	if len(vulns) == 0 {
		return []model.Finding{{
			ID:             "retirejs-no-vulns",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "retire.js found no vulnerable libraries",
			Description:    fmt.Sprintf("retire.js scanned %d JavaScript bundle(s) but did not flag any libraries with known vulnerabilities.", count),
			Evidence:       "target=" + input.Target,
			Recommendation: "Re-scan periodically; new CVEs are published against client-side libraries regularly.",
		}}
	}
	highest := model.SeverityLow
	for _, v := range vulns {
		if severityRank(v.severity) > severityRank(highest) {
			highest = v.severity
		}
	}
	lines := make([]string, 0, len(vulns))
	for _, v := range vulns {
		entry := fmt.Sprintf("%s@%s (%s)", v.component, v.version, v.severity)
		if len(v.identifiers) > 0 {
			entry += " " + strings.Join(limitStrings(v.identifiers, 4), ",")
		}
		lines = append(lines, entry)
	}
	return []model.Finding{{
		ID:             "retirejs-vulnerable-libraries",
		Category:       "vulnerable-dependency",
		Severity:       highest,
		Title:          "retire.js detected vulnerable JavaScript libraries",
		Description:    "retire.js identified client-side JavaScript libraries with publicly known vulnerabilities. Outdated front-end libraries frequently expose XSS, prototype-pollution, and ReDoS issues that are exploitable in the browser.",
		Evidence:       fmt.Sprintf("vulnerable=%d; %s", len(vulns), strings.Join(limitStrings(lines, 12), "; ")),
		Recommendation: "Upgrade the flagged libraries to a patched version and add a CI check (retire.js / npm audit) to prevent regressions.",
		CWE:            "CWE-1104",
		OWASPCategory:  "A06:2021 - Vulnerable and Outdated Components",
		Sources:        []string{"retire.js"},
		Confidence:     0.8,
	}}
}

// retireVuln is a flattened view of one vulnerable component reported by
// retire.js.
type retireVuln struct {
	component   string
	version     string
	severity    model.Severity
	identifiers []string
}

// parseRetireJSVulns parses retire.js JSON output (--outputformat json),
// handling both the newer object form ({"data": [...]}) and the older
// top-level array form. Returns a flattened list of vulnerable components.
func parseRetireJSVulns(data []byte) []retireVuln {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	type identifiers struct {
		CVE     []string `json:"CVE"`
		Issue   string   `json:"issue"`
		Summary string   `json:"summary"`
	}
	type vulnerability struct {
		Severity    string      `json:"severity"`
		Identifiers identifiers `json:"identifiers"`
	}
	type result struct {
		Component       string          `json:"component"`
		Version         string          `json:"version"`
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	}
	type fileEntry struct {
		File    string   `json:"file"`
		Results []result `json:"results"`
	}

	var entries []fileEntry
	var wrapper struct {
		Data []fileEntry `json:"data"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Data) > 0 {
		entries = wrapper.Data
	} else if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}

	out := make([]retireVuln, 0)
	seen := map[string]struct{}{}
	for _, fe := range entries {
		for _, r := range fe.Results {
			if len(r.Vulnerabilities) == 0 {
				continue
			}
			key := r.Component + "@" + r.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			highest := model.SeverityLow
			ids := make([]string, 0)
			idSeen := map[string]struct{}{}
			for _, v := range r.Vulnerabilities {
				if sv := mapRetireSeverity(v.Severity); severityRank(sv) > severityRank(highest) {
					highest = sv
				}
				for _, cve := range v.Identifiers.CVE {
					cve = strings.TrimSpace(cve)
					if cve == "" {
						continue
					}
					if _, ok := idSeen[cve]; ok {
						continue
					}
					idSeen[cve] = struct{}{}
					ids = append(ids, cve)
				}
			}
			out = append(out, retireVuln{
				component:   r.Component,
				version:     r.Version,
				severity:    highest,
				identifiers: ids,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].component < out[j].component })
	return out
}

// mapRetireSeverity maps a retire.js severity string to a model.Severity.
func mapRetireSeverity(raw string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityLow
	}
}

// severityRank orders model.Severity values so the highest-impact finding can
// be selected when several vulnerabilities are reported for one component.
func severityRank(sev model.Severity) int {
	switch sev {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// runTruffleHog downloads the target's in-scope JavaScript bundles and runs
// TruffleHog against them to detect committed credentials/secrets. It is
// passive/non-destructive in that it only reads resources the application
// already serves (it may verify discovered secrets against their provider).
func (s *Service) runTruffleHog(ctx context.Context, input RunInput) []model.Finding {
	if !s.cfg.EnableTruffleHog {
		return []model.Finding{{
			ID:             "trufflehog-disabled",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "TruffleHog integration requested but disabled",
			Description:    "The job requested TruffleHog but ENABLE_TRUFFLEHOG_INTEGRATION is false.",
			Evidence:       "ENABLE_TRUFFLEHOG_INTEGRATION=false",
			Recommendation: "Enable the feature flag in backend environment if this integration is approved.",
		}}
	}
	if _, err := exec.LookPath(s.cfg.TruffleHogBinary); err != nil {
		return []model.Finding{{
			ID:             "trufflehog-binary-missing",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "TruffleHog binary not found",
			Description:    "TruffleHog integration is enabled but the binary is not available in PATH.",
			Evidence:       err.Error(),
			Recommendation: "Install TruffleHog or set TRUFFLEHOG_BINARY to the binary path.",
		}}
	}

	dir, count, err := s.downloadInScopeScripts(ctx, input)
	if dir != "" {
		defer os.RemoveAll(dir)
	}
	if err != nil {
		return []model.Finding{{
			ID:             "trufflehog-fetch-error",
			Category:       "integration",
			Severity:       model.SeverityLow,
			Title:          "TruffleHog could not prepare JavaScript bundles",
			Description:    "Fetching or storing the target's JavaScript bundles for TruffleHog failed.",
			Evidence:       err.Error(),
			Recommendation: "Ensure SHARED_TMP_DIR is writable and the target is reachable, then retry.",
		}}
	}
	if count == 0 {
		return []model.Finding{{
			ID:             "trufflehog-no-scripts",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "TruffleHog found no JavaScript to scan",
			Description:    "No in-scope JavaScript bundles were discovered on the target, so TruffleHog had nothing to analyse.",
			Evidence:       "target=" + input.Target,
			Recommendation: "Combine with active crawling (katana) to discover additional script bundles.",
		}}
	}

	ictx, cancel := context.WithTimeout(ctx, s.cfg.IntegrationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ictx, s.cfg.TruffleHogBinary, "filesystem", dir, "--json", "--no-update")
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	if runErr := cmd.Run(); runErr != nil && ictx.Err() == context.DeadlineExceeded {
		return []model.Finding{{
			ID:             "trufflehog-timeout",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "TruffleHog timed out",
			Description:    "TruffleHog did not complete before the integration timeout.",
			Evidence:       "timeout=" + s.cfg.IntegrationTimeout.String(),
			Recommendation: "Increase INTEGRATION_TIMEOUT_SECONDS or reduce scan scope.",
		}}
	}

	detectors, verified := parseTruffleHogSecrets(outb.String())
	if len(detectors) == 0 {
		return []model.Finding{{
			ID:             "trufflehog-no-secrets",
			Category:       "integration",
			Severity:       model.SeverityInfo,
			Title:          "TruffleHog found no secrets",
			Description:    fmt.Sprintf("TruffleHog scanned %d JavaScript bundle(s) but did not detect any credentials.", count),
			Evidence:       "target=" + input.Target,
			Recommendation: "Re-scan periodically and after deployments; client-side bundles occasionally leak rotated keys.",
		}}
	}
	severity := model.SeverityHigh
	if verified {
		severity = model.SeverityCritical
	}
	return []model.Finding{{
		ID:             "trufflehog-secrets-in-js",
		Category:       "information-disclosure",
		Severity:       severity,
		Title:          "TruffleHog detected secret(s) in client-side JavaScript",
		Description:    "TruffleHog matched credential patterns in JavaScript served to every visitor. Anything in a public bundle should be considered compromised; an attacker can extract and abuse it without any application access.",
		Evidence:       fmt.Sprintf("verified=%t; detectors=%s", verified, strings.Join(limitStrings(detectors, 12), ", ")),
		Recommendation: "Treat the matched values as compromised: rotate them immediately and move secrets server-side. Add a CI secret-scanning check (TruffleHog/gitleaks) to prevent regressions.",
		CWE:            "CWE-798",
		OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
		Sources:        []string{"trufflehog"},
		Confidence:     0.85,
	}}
}

// parseTruffleHogSecrets parses TruffleHog's line-delimited JSON output and
// returns the sorted, de-duplicated detector names that fired plus whether any
// detection was verified against its provider.
func parseTruffleHogSecrets(rawOutput string) ([]string, bool) {
	detectors := make([]string, 0)
	seen := map[string]struct{}{}
	verified := false
	for _, line := range strings.Split(rawOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			DetectorName string `json:"DetectorName"`
			Verified     bool   `json:"Verified"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		name := strings.TrimSpace(rec.DetectorName)
		if name == "" {
			continue
		}
		if rec.Verified {
			verified = true
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		detectors = append(detectors, name)
	}
	sort.Strings(detectors)
	return detectors, verified
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
