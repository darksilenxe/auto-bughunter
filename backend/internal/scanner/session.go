package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
)

// TokenStore holds harvested bearer/CSRF tokens discovered during a scan.
// It is safe for concurrent use.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func newTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]string)}
}

// Set stores key → value in the token store.
func (t *TokenStore) Set(key, value string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens[key] = value
}

// Get retrieves a token by key. Returns "" if not found.
func (t *TokenStore) Get(key string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.tokens[key]
}

// All returns a copy of all stored tokens.
func (t *TokenStore) All() map[string]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]string, len(t.tokens))
	for k, v := range t.tokens {
		out[k] = v
	}
	return out
}

// DiscoveredEndpoint holds a network endpoint captured during SPA crawling.
type DiscoveredEndpoint struct {
	URL    string
	Method string
}

// ScanSession carries per-scan stateful HTTP context:
//   - A shared cookie jar so cookies obtained in one probe are automatically
//     sent in subsequent probes.
//   - A TokenStore for explicit CSRF/bearer values extracted from JSON bodies
//     and response headers.
//   - A list of API endpoints observed by the headless browser XHR interceptor.
//
// All exported methods are nil-safe and safe for concurrent use.
type ScanSession struct {
	client              *http.Client
	TokenStore          *TokenStore
	mu                  sync.Mutex
	discoveredEndpoints []DiscoveredEndpoint
	// discoveredParams maps "<host><normalized-path>" → parameter
	// names surfaced by the Phase 2 hidden-parameter miner. Probes
	// consult this map before falling back to their built-in param
	// wordlist so miner findings actually get exercised.
	discoveredParams map[string]map[string]struct{}
	// surfaceInventory is the per-scan Phase 2 SurfaceInventory. It is
	// populated by scanner.Run() from crawl links and runtime XHR
	// endpoints, and consulted by probes and by the end-of-scan gap
	// detector. May be nil for callers that create a session outside
	// scanner.Run(); every use site is nil-safe.
	surfaceInventory *SurfaceInventory
	// coverageMap is the structured attack-surface coverage map built by
	// scanner.Run() at scan end. It is nil-safe; callers that create a
	// session outside scanner.Run() will see a nil value.
	coverageMap *model.CoverageMap
}

// NewScanSession creates a ScanSession backed by a stdlib cookie jar.
// The returned client uses the default Go transport (direct connections).
func NewScanSession() *ScanSession {
	return NewScanSessionWithTransport(nil)
}

// NewScanSessionWithTransport is like NewScanSession but installs the given
// http.RoundTripper on the session's client. Pass nil to use the default
// transport. Used to route scanner traffic through an upstream proxy.
func NewScanSessionWithTransport(rt http.RoundTripper) *ScanSession {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
	}
	if rt != nil {
		c.Transport = rt
	}
	return &ScanSession{
		client:     c,
		TokenStore: newTokenStore(),
	}
}

// Client returns the shared *http.Client whose cookie jar persists cookies
// across all requests made during this scan. Returns nil when s is nil.
func (s *ScanSession) Client() *http.Client {
	if s == nil {
		return nil
	}
	return s.client
}

// SeedCookies writes name→value cookie pairs into the session jar for the
// given target URL so that subsequent requests automatically include them.
func (s *ScanSession) SeedCookies(targetURL string, cookies map[string]string) {
	if s == nil || len(cookies) == 0 {
		return
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return
	}
	hcookies := make([]*http.Cookie, 0, len(cookies))
	for name, value := range cookies {
		if strings.TrimSpace(name) == "" {
			continue
		}
		hcookies = append(hcookies, &http.Cookie{Name: name, Value: value})
	}
	if len(hcookies) > 0 && s.client.Jar != nil {
		s.client.Jar.SetCookies(u, hcookies)
	}
}

// HarvestFromResponse extracts authentication tokens from a response and its
// body and stores them in the session's TokenStore. The cookie jar already
// handles Set-Cookie headers automatically; this method focuses on explicit
// CSRF headers and JSON body tokens.
//
// bodyBytes may be nil when only header harvesting is desired.
func (s *ScanSession) HarvestFromResponse(resp *http.Response, bodyBytes []byte) {
	if s == nil || resp == nil {
		return
	}
	// Harvest CSRF token from response headers.
	for _, headerName := range []string{"X-CSRF-Token", "X-CSRFToken", "CSRF-Token"} {
		if v := resp.Header.Get(headerName); v != "" {
			s.TokenStore.Set("csrf", v)
			break
		}
	}
	// Harvest tokens from JSON response body.
	if len(bodyBytes) == 0 {
		return
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return
	}
	for _, key := range []string{
		"token", "csrf", "csrf_token", "csrfToken",
		"access_token", "accessToken",
		"jwt", "id_token", "idToken",
		"refresh_token", "refreshToken",
	} {
		val, ok := parsed[key]
		if !ok {
			continue
		}
		str, ok := val.(string)
		if !ok || str == "" {
			continue
		}
		s.TokenStore.Set(key, str)
		// Normalise to well-known slot names for easy retrieval.
		switch key {
		case "access_token", "accessToken", "jwt", "id_token", "idToken":
			s.TokenStore.Set("bearer", str)
		case "csrf", "csrf_token", "csrfToken":
			s.TokenStore.Set("csrf", str)
		case "refresh_token", "refreshToken":
			s.TokenStore.Set("refresh_token", str)
		}
	}
}

// InjectIntoRequest applies harvested CSRF/bearer tokens to an outgoing
// request as headers. The session cookie jar handles Cookie headers
// automatically when using the session's HTTP client.
func (s *ScanSession) InjectIntoRequest(req *http.Request) {
	if s == nil || req == nil {
		return
	}
	if bearer := s.TokenStore.Get("bearer"); bearer != "" {
		if req.Header.Get("Authorization") == "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
	}
	if csrf := s.TokenStore.Get("csrf"); csrf != "" {
		if req.Header.Get("X-CSRF-Token") == "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
	}
}

// AddDiscoveredEndpoint records a network endpoint observed by the SPA
// crawler. Duplicate URL+Method pairs are silently ignored.
func (s *ScanSession) AddDiscoveredEndpoint(ep DiscoveredEndpoint) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.discoveredEndpoints {
		if existing.URL == ep.URL && existing.Method == ep.Method {
			return
		}
	}
	s.discoveredEndpoints = append(s.discoveredEndpoints, ep)
}

// AddDiscoveredParams stores parameter names discovered by the Phase 2
// hidden-parameter miner for a given URL. Probes call
// DiscoveredParamsFor(url) to consult this list before falling back to
// their built-in wordlists.
func (s *ScanSession) AddDiscoveredParams(rawURL string, params []string) {
	if s == nil || rawURL == "" || len(params) == 0 {
		return
	}
	key := discoveredParamsKey(rawURL)
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.discoveredParams == nil {
		s.discoveredParams = map[string]map[string]struct{}{}
	}
	if s.discoveredParams[key] == nil {
		s.discoveredParams[key] = map[string]struct{}{}
	}
	for _, p := range params {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		s.discoveredParams[key][p] = struct{}{}
	}
}

// DiscoveredParamsFor returns the parameter names miners have surfaced
// for the given URL, deduped and in stable (alphabetical) order.
func (s *ScanSession) DiscoveredParamsFor(rawURL string) []string {
	if s == nil {
		return nil
	}
	key := discoveredParamsKey(rawURL)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.discoveredParams[key]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// AllDiscoveredParams returns every parameter name discovered by the
// hidden-parameter miner across all URLs in this session, deduped and
// in stable order. Useful for probes that want to try miner-surfaced
// names on arbitrary candidate endpoints.
func (s *ScanSession) AllDiscoveredParams() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]struct{}{}
	for _, set := range s.discoveredParams {
		for k := range set {
			seen[k] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// SetSurfaceInventory installs the Phase 2 SurfaceInventory on the
// session so probes and the end-of-scan gap detector share the same
// canonical inventory. Safe to call once per session.
func (s *ScanSession) SetSurfaceInventory(inv *SurfaceInventory) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.surfaceInventory = inv
}

// SurfaceInventory returns the per-session SurfaceInventory or nil if
// none has been installed.
func (s *ScanSession) SurfaceInventory() *SurfaceInventory {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.surfaceInventory
}

// SetCoverageMap stores the structured coverage map built at scan end.
func (s *ScanSession) SetCoverageMap(cm *model.CoverageMap) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.coverageMap = cm
}

// GetCoverageMap returns the coverage map stored by scanner.Run, or nil.
func (s *ScanSession) GetCoverageMap() *model.CoverageMap {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.coverageMap
}

func discoveredParamsKey(rawURL string) string {
	host := hostOf(rawURL)
	if host == "" {
		return ""
	}
	return host + normalizePath(rawURL)
}

// sortStrings is a tiny helper that avoids adding a sort import at
// every call site. It sorts in place, ascending.
func sortStrings(v []string) {
	// simple insertion sort — lists here are tiny (< a few dozen).
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j-1] > v[j]; j-- {
			v[j-1], v[j] = v[j], v[j-1]
		}
	}
}


// DiscoveredURLs returns unique URLs observed during XHR interception in
// the order they were discovered.
func (s *ScanSession) DiscoveredURLs() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]struct{}, len(s.discoveredEndpoints))
	out := make([]string, 0, len(s.discoveredEndpoints))
	for _, ep := range s.discoveredEndpoints {
		if _, ok := seen[ep.URL]; !ok {
			seen[ep.URL] = struct{}{}
			out = append(out, ep.URL)
		}
	}
	return out
}
