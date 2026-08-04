package scanner

import (
	"context"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// phase2_gap_requeue wires the "gap" control from PHASE2_AUDIT.md: it
// takes the SurfaceGap list produced by DetectSurfaceGaps at the end of
// the first probe pass, selects the highest-ROI candidates via
// SelectHighROIGaps/GapReQueueURLs, and re-invokes the injection/header
// probes that already consume input.Options.SeedRuntimeEndpoints for a
// bounded second pass — so endpoints discovered late (e.g. by the
// hidden-parameter miner or runtime-XHR extraction, both of which only
// populate the inventory partway through the first pass) still get
// fuzzed in the same scan instead of being silently dropped.
//
// gapReQueueBudget bounds how many high-ROI gaps are re-queued per scan
// so a large, mostly-unprobed inventory can't blow up scan duration.
const gapReQueueBudget = 15
const gapReQueueMinBudget = 10
const gapReQueueMaxBudget = 30

// runGapReQueuePass re-runs the Batch 1 + Batch 2 Phase 2 probes
// against the highest-ROI unprobed surface gaps. It is a no-op when
// PassiveOnly is set (matches every migrated probe's own passive gate)
// or when there are no gaps worth re-queuing.
func (s *Service) runGapReQueuePass(ctx context.Context, input RunInput, bodyText string, gaps []SurfaceGap) []model.Finding {
	if input.Options.PassiveOnly || len(gaps) == 0 {
		return nil
	}
	top := SelectHighROIGaps(gaps, adaptiveGapReQueueBudget(gaps))
	urls := GapReQueueURLs(top)
	if len(urls) == 0 {
		return nil
	}

	// Only re-queue URLs that were not already part of the seed list
	// probes saw during the first pass, so the second pass is strictly
	// additive coverage rather than duplicate work.
	already := map[string]struct{}{}
	for _, u := range input.Options.SeedRuntimeEndpoints {
		already[u] = struct{}{}
	}
	var newURLs []string
	for _, u := range urls {
		if _, ok := already[u]; ok {
			continue
		}
		newURLs = append(newURLs, u)
	}
	if len(newURLs) == 0 {
		return nil
	}

	gapInput := input
	gapInput.Options.SeedRuntimeEndpoints = append(append([]string{}, input.Options.SeedRuntimeEndpoints...), newURLs...)

	var findings []model.Finding
	findings = append(findings, s.runActiveCORSProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveGraphQLIntrospectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveLDAPInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveNoSQLiProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveOpenRedirectProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActivePathTraversalProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActivePromptInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActivePrototypePollutionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveSQLiProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveSSTIProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveXPathInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveXSSProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runActiveXXEProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.gapReQueueClickjackingProbe(ctx, gapInput, newURLs)...)
	findings = append(findings, s.gapReQueueCachePoisoningProbe(ctx, gapInput, newURLs)...)
	findings = append(findings, s.gapReQueueVhostProbe(ctx, gapInput, newURLs)...)
	findings = append(findings, s.runCommandInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runCSSInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runDanglingMarkupProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.RunDeserializationProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.runDOMClobberingProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.RunDOMXSSProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.runFileUploadProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runFormulaInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runHTTPMethodsProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.RunLoginProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.RunMagicLinkProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.RunMFAProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.RunOAuthProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.RunOAuthSessionProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.runPasswordResetProbe(ctx, gapInput)...)
	findings = append(findings, s.runRateLimitProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runReflectedFileDownloadProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.RunSAMLProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.RunSessionLifecycleProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.runSMTPInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runSSIInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runVerboseErrorProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runWebSocketProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runXSLTInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runXSSIJSONPProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runZipSlipProbe(ctx, gapInput, bodyText)...)

	for i := range findings {
		if !strings.Contains(strings.ToLower(findings[i].Description), "gap-requeue") {
			findings[i].Description = strings.TrimSpace(findings[i].Description + " (surfaced via Phase 2 gap-requeue pass)")
		}
	}
	return findings
}

func adaptiveGapReQueueBudget(gaps []SurfaceGap) int {
	if len(gaps) == 0 {
		return gapReQueueBudget
	}
	budget := gapReQueueBudget
	unprobed := 0
	authWeighted := 0
	for _, g := range gaps {
		if g.Reason == SurfaceGapUnprobed {
			unprobed++
		}
		if isHighRiskGap(g) {
			authWeighted++
		}
	}
	if unprobed > len(gaps)/2 {
		budget += 5
	}
	if authWeighted > 0 {
		// Raise budget in proportion to risky auth/state-changing surfaces,
		// capped so scans stay bounded.
		budget += minInt(10, authWeighted/2+1)
	}
	if budget < gapReQueueMinBudget {
		return gapReQueueMinBudget
	}
	if budget > gapReQueueMaxBudget {
		return gapReQueueMaxBudget
	}
	return budget
}

func isHighRiskGap(g SurfaceGap) bool {
	target := strings.ToLower(strings.TrimSpace(g.Entry.URL) + " " + strings.TrimSpace(g.MissingItem))
	if hasAnyGapKeyword(target, "auth", "oauth", "oidc", "token", "session", "login", "logout", "mfa", "password", "reset", "admin", "csrf", "redirect", "callback") {
		return true
	}
	for _, p := range g.Entry.Params {
		if hasAnyGapKeyword(strings.ToLower(strings.TrimSpace(p)), "token", "state", "code", "redirect", "return", "next", "password", "email", "session", "csrf", "auth") {
			return true
		}
	}
	return false
}

func hasAnyGapKeyword(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// gapReQueueClickjackingMax bounds how many re-queued gap URLs get a
// live fetch for the clickjacking check, since (unlike the injection
// probes above) runClickjackingProbe does not itself consume
// SeedRuntimeEndpoints — it only inspects the response header for a
// single, caller-fetched URL.
const gapReQueueClickjackingMax = 5

// gapReQueueClickjackingProbe fetches up to gapReQueueClickjackingMax of
// the re-queued gap URLs and runs the clickjacking header check against
// each, so pages discovered late in the first pass (e.g. via runtime-XHR
// extraction or the hidden-parameter miner) still get framing coverage.
func (s *Service) gapReQueueClickjackingProbe(ctx context.Context, input RunInput, urls []string) []model.Finding {
	var findings []model.Finding
	for i, u := range urls {
		if i >= gapReQueueClickjackingMax {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			continue
		}
		header := resp.Header.Clone()
		_ = resp.Body.Close()
		urlInput := input
		urlInput.Target = u
		findings = append(findings, s.runClickjackingProbe(urlInput, header)...)
	}
	return findings
}

// gapReQueueCachePoisoningMax bounds how many re-queued gap URLs receive a
// cache-poisoning header-injection check on the second pass.
const gapReQueueCachePoisoningMax = 5

// gapReQueueCachePoisoningProbe runs the cache-poisoning probe against each
// of the supplied gap URLs (up to gapReQueueCachePoisoningMax), mirroring the
// pattern used by gapReQueueClickjackingProbe. This ensures endpoints
// discovered late (via runtime-XHR extraction or the hidden-parameter miner)
// still receive unkeyed-header reflection checks within the same scan.
func (s *Service) gapReQueueCachePoisoningProbe(ctx context.Context, input RunInput, urls []string) []model.Finding {
	var findings []model.Finding
	for i, u := range urls {
		if i >= gapReQueueCachePoisoningMax {
			break
		}
		urlInput := input
		urlInput.Target = u
		findings = append(findings, s.runCachePoisoningProbe(ctx, urlInput, "")...)
	}
	return findings
}

// gapReQueueVhostMax bounds how many re-queued gap URLs receive a virtual-host
// discovery check on the second pass.
const gapReQueueVhostMax = 5

// gapReQueueVhostProbe runs the vhost-discovery probe against each of the
// supplied gap URLs (up to gapReQueueVhostMax). This ensures late-discovered
// endpoints also get Host-header rotation coverage, catching hidden virtual
// hosts that are only reachable via sub-paths not present at scan start.
func (s *Service) gapReQueueVhostProbe(ctx context.Context, input RunInput, urls []string) []model.Finding {
	var findings []model.Finding
	for i, u := range urls {
		if i >= gapReQueueVhostMax {
			break
		}
		urlInput := input
		urlInput.Target = u
		findings = append(findings, s.runVhostDiscoveryProbe(ctx, urlInput, "")...)
	}
	return findings
}
