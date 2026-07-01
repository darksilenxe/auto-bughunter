package scanner

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"auto-bughunter/backend/internal/model"
)

// findings_cluster deduplicates candidate findings by
// (category, host, normalized-path, param, evidence-hash) so a single
// underlying weakness reflected across many crawl paths does not spam
// the report. The strongest representative is kept; siblings are
// folded into the survivor's EvidenceFields under "clusterSiblings"
// and every finding in the cluster receives a stable "clusterId".
//
// The module is intentionally decoupled from the aggregator: it exposes
// a pure ClusterFindings function that callers invoke immediately
// before writing to storage, plus a process-wide metrics counter that
// AutomationMetrics surfaces via GetClusterMetrics.

// ClusterMetrics captures cluster-ratio KPIs across the process.
type ClusterMetrics struct {
	// TotalIn is the total number of candidate findings observed
	// before clustering (across all scans in the process lifetime).
	TotalIn uint64 `json:"totalIn"`
	// TotalOut is the total number of surviving findings after
	// clustering.
	TotalOut uint64 `json:"totalOut"`
	// Clustered is the number of candidates folded into siblings
	// (TotalIn - TotalOut).
	Clustered uint64 `json:"clustered"`
	// Ratio is Clustered / TotalIn in [0, 1]. 0 when TotalIn == 0.
	Ratio float64 `json:"ratio"`
}

var (
	clusterTotalIn  atomic.Uint64
	clusterTotalOut atomic.Uint64
)

// GetClusterMetrics returns a snapshot of the process-wide clustering
// metrics for AutomationMetrics.Extra.
func GetClusterMetrics() ClusterMetrics {
	in := clusterTotalIn.Load()
	out := clusterTotalOut.Load()
	var ratio float64
	if in > 0 {
		ratio = float64(in-out) / float64(in)
	}
	return ClusterMetrics{
		TotalIn:   in,
		TotalOut:  out,
		Clustered: in - out,
		Ratio:     ratio,
	}
}

// ResetClusterMetrics resets the counters. Intended for tests.
func ResetClusterMetrics() {
	clusterTotalIn.Store(0)
	clusterTotalOut.Store(0)
}

// pathIDSegmentRE normalises numeric IDs, UUIDs and long hex tokens
// in URL paths so /users/42/posts/7 and /users/99/posts/12 cluster
// together.
var pathIDSegmentRE = regexp.MustCompile(`(?i)(^|/)(?:[0-9]+|[0-9a-f\-]{16,}|[a-z0-9_\-]{24,})(?:$|/)`)

// normalizePath collapses variable path segments to `{id}` and strips
// the query string. It preserves the leading slash and lowercases the
// path so `/Users/42` and `/users/99` cluster.
func normalizePath(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	p = strings.ToLower(p)
	// Repeatedly replace ID segments until stable — the regex is
	// anchored on `/` boundaries so overlapping matches need two
	// passes.
	for i := 0; i < 4; i++ {
		next := pathIDSegmentRE.ReplaceAllString(p, "$1{id}/")
		next = strings.TrimSuffix(next, "/")
		if next == "" {
			next = "/"
		}
		if next == p {
			break
		}
		p = next
	}
	return p
}

// hostOf extracts the lowercased host from a URL, or returns the raw
// string when parsing fails.
func hostOf(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return strings.ToLower(rawURL)
	}
	return strings.ToLower(u.Host)
}

// evidenceHash produces a stable 12-hex-char hash of the salient
// evidence bytes. It intentionally strips dynamic tokens (via the
// existing dynamicTokenPatterns / dynamicBodyStructurePatterns) so
// two findings differing only in per-request nonces cluster together.
func evidenceHash(f model.Finding) string {
	buf := strings.Builder{}
	buf.WriteString(strings.ToLower(strings.TrimSpace(f.Evidence)))
	// Include a canonicalised subset of evidence fields — sort keys
	// for determinism, drop fields known to be per-request-unique.
	if len(f.EvidenceFields) > 0 {
		keys := make([]string, 0, len(f.EvidenceFields))
		for k := range f.EvidenceFields {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "timestamp") || strings.Contains(lk, "requestid") ||
				strings.Contains(lk, "nonce") || strings.Contains(lk, "trace") ||
				strings.Contains(lk, "clustersiblings") || strings.Contains(lk, "clusterid") {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			buf.WriteByte('|')
			buf.WriteString(strings.ToLower(k))
			buf.WriteByte('=')
			buf.WriteString(f.EvidenceFields[k])
		}
	}
	stripped := buf.String()
	for _, p := range dynamicBodyStructurePatterns {
		stripped = p.pat.ReplaceAllString(stripped, p.repl)
	}
	for _, re := range dynamicTokenPatterns {
		stripped = re.ReplaceAllString(stripped, "<dyn>")
	}
	sum := sha1.Sum([]byte(stripped))
	return hex.EncodeToString(sum[:6])
}

// clusterKey is the 5-tuple identity used to fold duplicate findings.
type clusterKey struct {
	Category string
	Host     string
	Path     string
	Param    string
	Evidence string
}

func keyFor(f model.Finding) clusterKey {
	return clusterKey{
		Category: strings.ToLower(strings.TrimSpace(f.Category)),
		Host:     hostOf(f.AffectedURL),
		Path:     normalizePath(f.AffectedURL),
		Param:    strings.ToLower(strings.TrimSpace(f.AffectedParameter)),
		Evidence: evidenceHash(f),
	}
}

// clusterID renders the cluster key as a stable short identifier
// suitable for logs, dashboards, and evidence fields.
func (k clusterKey) clusterID() string {
	joined := strings.Join([]string{k.Category, k.Host, k.Path, k.Param, k.Evidence}, "|")
	sum := sha1.Sum([]byte(joined))
	return "cluster-" + hex.EncodeToString(sum[:8])
}

// stronger returns true if a should be preferred over b as the
// cluster survivor. Higher severity wins, then higher confidence,
// then more evidence fields, then longer evidence body, then stable
// ID ordering to keep results deterministic.
func stronger(a, b model.Finding) bool {
	if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
		return ra > rb
	}
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if la, lb := len(a.EvidenceFields), len(b.EvidenceFields); la != lb {
		return la > lb
	}
	if la, lb := len(a.Evidence), len(b.Evidence); la != lb {
		return la > lb
	}
	return a.ID < b.ID
}

// siblingSummary produces a compact human-readable representation of a
// folded sibling finding to attach to the survivor.
func siblingSummary(f model.Finding) string {
	parts := []string{}
	if f.ID != "" {
		parts = append(parts, f.ID)
	}
	if f.AffectedURL != "" {
		parts = append(parts, f.AffectedURL)
	}
	if f.AffectedParameter != "" {
		parts = append(parts, "param="+f.AffectedParameter)
	}
	if f.Severity != "" {
		parts = append(parts, string(f.Severity))
	}
	return strings.Join(parts, " ")
}

// ClusterFindings groups the input findings by their 5-tuple identity
// and returns one survivor per cluster. Folded siblings are attached
// to the survivor's EvidenceFields under:
//
//	clusterId        — stable cluster identifier
//	clusterSize      — total findings in the cluster (survivor + siblings)
//	clusterSiblings  — newline-separated compact summaries of siblings
//
// Process-wide cluster metrics are updated atomically so callers can
// surface KPIs via GetClusterMetrics.
//
// Ordering: the survivor list is returned in the deterministic order
// of first appearance in `in` to preserve the caller's existing
// ordering guarantees.
func ClusterFindings(in []model.Finding) []model.Finding {
	if len(in) == 0 {
		return in
	}
	// Track cluster survivors and any siblings folded in.
	type bucket struct {
		key      clusterKey
		survivor model.Finding
		siblings []model.Finding
		firstIdx int
	}
	buckets := map[clusterKey]*bucket{}
	order := []clusterKey{}
	for i, f := range in {
		k := keyFor(f)
		b, ok := buckets[k]
		if !ok {
			buckets[k] = &bucket{key: k, survivor: f, firstIdx: i}
			order = append(order, k)
			continue
		}
		if stronger(f, b.survivor) {
			b.siblings = append(b.siblings, b.survivor)
			b.survivor = f
		} else {
			b.siblings = append(b.siblings, f)
		}
	}
	out := make([]model.Finding, 0, len(buckets))
	sort.SliceStable(order, func(i, j int) bool {
		return buckets[order[i]].firstIdx < buckets[order[j]].firstIdx
	})
	for _, k := range order {
		b := buckets[k]
		s := b.survivor
		clusterID := k.clusterID()
		clusterSize := 1 + len(b.siblings)
		if s.EvidenceFields == nil {
			s.EvidenceFields = map[string]string{}
		}
		s.EvidenceFields["clusterId"] = clusterID
		s.EvidenceFields["clusterSize"] = fmt.Sprintf("%d", clusterSize)
		if len(b.siblings) > 0 {
			lines := make([]string, 0, len(b.siblings))
			for _, sib := range b.siblings {
				lines = append(lines, siblingSummary(sib))
			}
			s.EvidenceFields["clusterSiblings"] = strings.Join(lines, "\n")
		}
		out = append(out, s)
	}
	// Metrics.
	clusterTotalIn.Add(uint64(len(in)))
	clusterTotalOut.Add(uint64(len(out)))
	return out
}

// clusterMu guards ClusterFindingsAdmit which is not currently used
// but reserved for streaming callers.
var clusterMu sync.Mutex

// ClusterFindingsAdmit is a streaming variant retained for callers
// that build findings incrementally. It admits a single finding into
// an accumulator and returns the survivor for the finding's cluster
// so the caller can decide whether to append it. Not used by the
// default aggregator path (which prefers the batch ClusterFindings).
func ClusterFindingsAdmit(acc map[string]model.Finding, f model.Finding) model.Finding {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	if acc == nil {
		return f
	}
	k := keyFor(f)
	id := k.clusterID()
	existing, ok := acc[id]
	if !ok {
		if f.EvidenceFields == nil {
			f.EvidenceFields = map[string]string{}
		}
		f.EvidenceFields["clusterId"] = id
		f.EvidenceFields["clusterSize"] = "1"
		acc[id] = f
		clusterTotalIn.Add(1)
		clusterTotalOut.Add(1)
		return f
	}
	clusterTotalIn.Add(1)
	if stronger(f, existing) {
		// Promote f, fold existing.
		if f.EvidenceFields == nil {
			f.EvidenceFields = map[string]string{}
		}
		size := 2
		if v := existing.EvidenceFields["clusterSize"]; v != "" {
			// parse best-effort
			var n int
			_, _ = fmt.Sscanf(v, "%d", &n)
			if n > 0 {
				size = n + 1
			}
		}
		f.EvidenceFields["clusterId"] = id
		f.EvidenceFields["clusterSize"] = fmt.Sprintf("%d", size)
		sibs := existing.EvidenceFields["clusterSiblings"]
		if sibs != "" {
			sibs += "\n"
		}
		sibs += siblingSummary(existing)
		f.EvidenceFields["clusterSiblings"] = sibs
		acc[id] = f
		return f
	}
	// Fold f into existing.
	if existing.EvidenceFields == nil {
		existing.EvidenceFields = map[string]string{}
	}
	size := 2
	if v := existing.EvidenceFields["clusterSize"]; v != "" {
		var n int
		_, _ = fmt.Sscanf(v, "%d", &n)
		if n > 0 {
			size = n + 1
		}
	}
	existing.EvidenceFields["clusterSize"] = fmt.Sprintf("%d", size)
	sibs := existing.EvidenceFields["clusterSiblings"]
	if sibs != "" {
		sibs += "\n"
	}
	sibs += siblingSummary(f)
	existing.EvidenceFields["clusterSiblings"] = sibs
	acc[id] = existing
	return existing
}
