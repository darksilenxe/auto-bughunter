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

// runGapReQueuePass re-runs the Batch 1 + Batch 2 Phase 2 probes
// against the highest-ROI unprobed surface gaps. It is a no-op when
// PassiveOnly is set (matches every migrated probe's own passive gate)
// or when there are no gaps worth re-queuing.
func (s *Service) runGapReQueuePass(ctx context.Context, input RunInput, bodyText string, gaps []SurfaceGap) []model.Finding {
	if input.Options.PassiveOnly || len(gaps) == 0 {
		return nil
	}
	top := SelectHighROIGaps(gaps, gapReQueueBudget)
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
	findings = append(findings, s.runCommandInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runDanglingMarkupProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.RunDeserializationProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
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
	findings = append(findings, s.RunSAMLProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.RunSessionLifecycleProbe(ctx, gapInput.Target, gapInput.Scope, gapInput.Options, gapInput.AuthProfile, gapInput.Emit)...)
	findings = append(findings, s.runSMTPInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runSSIInjectionProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runVerboseErrorProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runWebSocketProbe(ctx, gapInput, bodyText)...)
	findings = append(findings, s.runXSSIJSONPProbe(ctx, gapInput, bodyText)...)

	for i := range findings {
		if !strings.Contains(strings.ToLower(findings[i].Description), "gap-requeue") {
			findings[i].Description = strings.TrimSpace(findings[i].Description + " (surfaced via Phase 2 gap-requeue pass)")
		}
	}
	return findings
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
