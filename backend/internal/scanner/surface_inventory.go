package scanner

import (
	"crypto/sha1"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// surface_inventory is the Phase 2 shared surface catalogue. Its job is to
// unify every source of "endpoints we know about" so that Phase 2 probes
// (and the surface-gap detector) can reason about probe coverage from a
// single canonical set instead of the per-probe ad-hoc extraction that
// Phase 1 relied on.
//
// Sources unioned by SurfaceInventory include, but are not limited to:
//
//   - crawl links (HTML anchors, forms)
//   - runtime XHR endpoints intercepted by the SPA harness (per memory,
//     already seeded via input.Options.SeedRuntimeEndpoints in scanner.go)
//   - sitemap.xml and robots.txt entries
//   - JS-parsed routes (regex extraction from JS bundles)
//   - OpenAPI / Swagger documents
//   - GraphQL introspection response paths
//   - Burp/ZAP export URLs supplied via the proxy import path
//
// Everything is deduped by NormalizeSurfaceKey so a single (method, host,
// normalized-path, param-set) is stored once even when observed from
// multiple sources.

// SurfaceSource labels where a surface entry was learned from. Useful for
// operator debugging and per-source coverage metrics.
type SurfaceSource string

const (
	SurfaceSourceCrawl        SurfaceSource = "crawl"
	SurfaceSourceRuntimeXHR   SurfaceSource = "runtime_xhr"
	SurfaceSourceSitemap      SurfaceSource = "sitemap"
	SurfaceSourceRobots       SurfaceSource = "robots"
	SurfaceSourceJSBundle     SurfaceSource = "js_bundle"
	SurfaceSourceOpenAPI      SurfaceSource = "openapi"
	SurfaceSourceGraphQL      SurfaceSource = "graphql_introspection"
	SurfaceSourceProxyImport  SurfaceSource = "proxy_import"
	SurfaceSourceParamDiscover SurfaceSource = "param_discovery"
	SurfaceSourceUnknown      SurfaceSource = "unknown"
)

// SurfaceEntry is a single method+URL+known-params triple in the
// canonical inventory. Params are the set of parameter names observed on
// this endpoint (union across sources), not per-observation values.
type SurfaceEntry struct {
	Method  string          // upper-case HTTP method
	URL     string          // raw URL as first observed (kept for probe replay)
	Host    string          // lower-case host
	Path    string          // normalized path (see normalizePath)
	Params  []string        // sorted, deduped, lower-case parameter names
	Sources []SurfaceSource // sources this entry has been seen from
}

// Key returns the canonical coverage key for this entry. It is computed
// on (method, host, normalized-path) only — parameters are tracked
// separately on the entry for gap detection so that observing a new
// parameter on an existing endpoint does not create a duplicate entry.
func (e SurfaceEntry) Key() string {
	return NormalizeSurfaceKey(e.Method, e.URL, nil)
}

// SurfaceInventory is the union of all discovered endpoints. It is safe
// for concurrent Add / Snapshot use.
type SurfaceInventory struct {
	mu      sync.RWMutex
	entries map[string]*SurfaceEntry
}

// NewSurfaceInventory returns an empty inventory.
func NewSurfaceInventory() *SurfaceInventory {
	return &SurfaceInventory{entries: map[string]*SurfaceEntry{}}
}

// Add records a new observation. Method defaults to GET when empty.
// Params are the parameter names observed on this URL (query keys, form
// fields, JSON body keys). Values are intentionally not stored — the
// inventory is a key-shape catalogue, not a request log.
//
// Add is idempotent: repeated observations of the same key union
// their sources and parameter sets.
func (s *SurfaceInventory) Add(method, rawURL string, params []string, source SurfaceSource) {
	if s == nil {
		return
	}
	m := normalizeMethod(method)
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return
	}
	// Compose a merged parameter set from both explicit params and any
	// query keys present on the URL itself.
	merged := mergeParamNames(params, queryParamsOf(rawURL))
	// Dedup key is (method, host, normalized-path) so that observing
	// the same URL with different parameter sets unions params on the
	// existing entry rather than creating a duplicate.
	key := NormalizeSurfaceKey(m, rawURL, nil)

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[key]; ok {
		existing.Params = mergeParamNames(existing.Params, merged)
		if source != "" && !containsSource(existing.Sources, source) {
			existing.Sources = append(existing.Sources, source)
		}
		return
	}
	if source == "" {
		source = SurfaceSourceUnknown
	}
	s.entries[key] = &SurfaceEntry{
		Method:  m,
		URL:     rawURL,
		Host:    hostOf(rawURL),
		Path:    normalizePath(rawURL),
		Params:  merged,
		Sources: []SurfaceSource{source},
	}
}

// AddMany is a convenience for adding a bulk list of GET URLs from a
// single source (crawl output, sitemap, etc.).
func (s *SurfaceInventory) AddMany(urls []string, source SurfaceSource) {
	for _, u := range urls {
		s.Add("GET", u, nil, source)
	}
}

// Snapshot returns a defensive copy of the current inventory. Ordering is
// stable (sorted by key) so callers can compare snapshots across runs.
func (s *SurfaceInventory) Snapshot() []SurfaceEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SurfaceEntry, 0, len(s.entries))
	keys := make([]string, 0, len(s.entries))
	for k := range s.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := s.entries[k]
		copyEntry := *e
		copyEntry.Params = append([]string(nil), e.Params...)
		copyEntry.Sources = append([]SurfaceSource(nil), e.Sources...)
		out = append(out, copyEntry)
	}
	return out
}

// Size returns the number of unique surface keys currently held.
func (s *SurfaceInventory) Size() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Keys returns just the canonical keys currently in the inventory.
// Ordering is deterministic (sorted).
func (s *SurfaceInventory) Keys() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.entries))
	for k := range s.entries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NormalizeSurfaceKey produces the canonical dedup key for a surface
// entry. It is deliberately compact so it can be used both as a map key
// and as an evidence-field value.
//
// The key incorporates:
//   - upper-case HTTP method
//   - lower-case host
//   - normalized path (via normalizePath, so IDs / UUIDs collapse to {id})
//   - sorted, deduped, lower-cased parameter names (pass nil when a
//     "coverage" key is wanted that ignores parameter names)
//
// For SurfaceInventory dedup and coverage accounting, callers pass
// params=nil so the same URL observed with different parameter sets
// collapses to a single entry; the entry's Params field then tracks
// the union of parameter names.
func NormalizeSurfaceKey(method, rawURL string, params []string) string {
	m := normalizeMethod(method)
	host := hostOf(rawURL)
	path := normalizePath(rawURL)
	p := mergeParamNames(nil, params)
	joined := strings.Join(p, ",")
	raw := m + "|" + host + "|" + path + "|" + joined
	sum := sha1.Sum([]byte(raw))
	return "sk-" + hex.EncodeToString(sum[:10])
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func normalizeMethod(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return "GET"
	}
	return m
}

func queryParamsOf(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	out := make([]string, 0, len(q))
	for k := range q {
		out = append(out, k)
	}
	return out
}

// mergeParamNames returns the sorted, deduped, lower-case union of the
// two input lists. Empty strings are dropped.
func mergeParamNames(a, b []string) []string {
	seen := map[string]struct{}{}
	for _, k := range a {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		seen[k] = struct{}{}
	}
	for _, k := range b {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsSource(list []SurfaceSource, s SurfaceSource) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
