package scanner

import "strings"

// phase2_probe_params provides the shared Phase 2 param-discovery merge
// helper used by the migrated active_* probes (see PHASE2_AUDIT.md). It
// generalises the pattern first landed in active_sqli.go
// (sqliDynamicParams / sqliMergedProbeParams) so every migrated probe
// shares one implementation instead of re-deriving it per file.

// phase2DynamicParams returns the parameter names surfaced by the Phase 2
// hidden-parameter miner for the current session (see
// ScanSession.AllDiscoveredParams). Returns nil (never panics) when no
// session or miner data is available.
func phase2DynamicParams(sess *ScanSession) []string {
	if sess == nil {
		return nil
	}
	return sess.AllDiscoveredParams()
}

// phase2ProbeParams merges miner-discovered parameter names in front of a
// probe's built-in wordlist. Discovered names take priority (so hidden
// parameters get exercised within the probe's attempt budget first);
// duplicates against the built-in list are dropped. Matching is
// case-insensitive; the returned names are lower-cased.
func phase2ProbeParams(dynamic []string, builtin []string) []string {
	seen := make(map[string]struct{}, len(dynamic)+len(builtin))
	out := make([]string, 0, len(dynamic)+len(builtin))
	for _, p := range dynamic {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range builtin {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
