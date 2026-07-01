package scanner

import (
	"sort"
	"strings"
)

// hidden_endpoint_probe is a small helper that walks the SurfaceGap
// list produced by DetectSurfaceGaps and returns the highest-ROI
// candidates for re-probing, bounded by a caller-supplied budget.
//
// It is intentionally *not* a request-issuer: bringing those
// endpoints back into the active probe pipeline is the caller's job
// (typically by appending to input.Options.SeedRuntimeEndpoints
// before the next probe run). This module's contribution is the ROI
// ordering, which is a pure function of the gap list.
//
// ROI heuristic (higher score first):
//
//  1. SurfaceGapUnprobed on a runtime-XHR / OpenAPI / GraphQL
//     source outranks SurfaceGapUnprobed on a static crawl link,
//     because API sources historically host more auth-bearing state.
//  2. SurfaceGapParamNotFuzzed with an interesting parameter name
//     ("id", "user", "token", "url", "file", ...) outranks a
//     generic name ("q", "sort").
//  3. SurfaceGapMethodNotTested for POST/PUT/DELETE outranks
//     SurfaceGapMethodNotTested for OPTIONS/HEAD.
//
// The scoring produces a stable order so the same gap list always
// yields the same re-queue plan, making the module test-friendly.

// interestingParamNames overlap with the built-in param_discovery
// wordlist plus a few common data-selection names. The intersection
// with an entry's Params bumps its ROI score.
var interestingParamNames = map[string]struct{}{
	"id": {}, "user": {}, "uid": {}, "userid": {}, "role": {},
	"token": {}, "apikey": {}, "url": {}, "next": {}, "redirect": {},
	"target": {}, "file": {}, "path": {}, "template": {},
	"debug": {}, "admin": {}, "impersonate": {},
}

// scoreGap returns the ROI score of a single gap. Higher is better.
func scoreGap(g SurfaceGap) int {
	score := 0
	// Reason weight.
	switch g.Reason {
	case SurfaceGapUnprobed:
		score += 40
	case SurfaceGapMethodNotTested:
		score += 20
	case SurfaceGapParamNotFuzzed:
		score += 10
	}
	// Source weight — API-shaped sources are typically higher value.
	for _, src := range g.Entry.Sources {
		switch src {
		case SurfaceSourceRuntimeXHR, SurfaceSourceOpenAPI, SurfaceSourceGraphQL:
			score += 15
		case SurfaceSourceProxyImport:
			score += 8
		case SurfaceSourceJSBundle:
			score += 5
		case SurfaceSourceSitemap, SurfaceSourceRobots, SurfaceSourceCrawl:
			score += 2
		}
	}
	// Method weight for method-not-tested.
	if g.Reason == SurfaceGapMethodNotTested {
		switch g.MissingItem {
		case "POST", "PUT", "DELETE", "PATCH":
			score += 10
		case "OPTIONS", "HEAD":
			score += 1
		}
	}
	// Parameter interest weight.
	if g.Reason == SurfaceGapParamNotFuzzed {
		if _, ok := interestingParamNames[strings.ToLower(g.MissingItem)]; ok {
			score += 8
		}
	}
	// Interesting params on the entry itself lift the base score.
	for _, p := range g.Entry.Params {
		if _, ok := interestingParamNames[p]; ok {
			score += 1
		}
	}
	return score
}

// SelectHighROIGaps returns the highest-scoring gaps, capped at
// budget. Ordering ties are broken by (reason, key) so the result is
// deterministic.
func SelectHighROIGaps(gaps []SurfaceGap, budget int) []SurfaceGap {
	if budget <= 0 || len(gaps) == 0 {
		return nil
	}
	type scored struct {
		g SurfaceGap
		s int
	}
	buf := make([]scored, 0, len(gaps))
	for _, g := range gaps {
		buf = append(buf, scored{g: g, s: scoreGap(g)})
	}
	sort.SliceStable(buf, func(i, j int) bool {
		if buf[i].s != buf[j].s {
			return buf[i].s > buf[j].s
		}
		if buf[i].g.Reason != buf[j].g.Reason {
			return string(buf[i].g.Reason) < string(buf[j].g.Reason)
		}
		return buf[i].g.Entry.Key() < buf[j].g.Entry.Key()
	})
	if len(buf) > budget {
		buf = buf[:budget]
	}
	out := make([]SurfaceGap, len(buf))
	for i, s := range buf {
		out[i] = s.g
	}
	return out
}

// GapReQueueURLs projects a gap list to the URLs the caller should
// re-queue into input.Options.SeedRuntimeEndpoints for the next probe
// run. Deduped, preserves selection order.
func GapReQueueURLs(gaps []SurfaceGap) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(gaps))
	for _, g := range gaps {
		u := strings.TrimSpace(g.Entry.URL)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}
