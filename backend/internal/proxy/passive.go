package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
)

// PassiveFinding wraps a model.Finding with metadata about where and when it
// was discovered by the passive proxy scanner.
type PassiveFinding struct {
	model.Finding
	DiscoveredAt time.Time `json:"discoveredAt"`
	AffectedURL  string    `json:"affectedUrl"`
}

// PassiveScanStore is a thread-safe, deduplicated store for findings
// discovered by passively analysing HTTP traffic that flows through the
// intercepting proxy.
//
// Deduplication key: host + ":" + findingID — the same missing-CSP finding is
// reported once per host, not once per request.
type PassiveScanStore struct {
	mu       sync.RWMutex
	items    map[string]PassiveFinding // key = host + ":" + findingID
	spaHosts map[string]*spaHostState
}

// NewPassiveScanStore constructs an empty PassiveScanStore.
func NewPassiveScanStore() *PassiveScanStore {
	return &PassiveScanStore{
		items:    map[string]PassiveFinding{},
		spaHosts: map[string]*spaHostState{},
	}
}

// Analyze runs passive checks against a captured proxy request and stores any
// new, deduplicated findings. It is safe to call concurrently and is a no-op
// on a nil receiver or a request with no response status.
func (ps *PassiveScanStore) Analyze(pr *model.ProxyRequest) {
	if ps == nil || pr == nil || pr.ResponseStatus == 0 {
		return
	}
	host := passiveHostFrom(pr.URL)
	findings := runPassiveChecks(pr)
	ps.mu.Lock()
	if spaFinding := ps.analyzeLikelySPALocked(host, pr); spaFinding != nil {
		findings = append(findings, *spaFinding)
	}
	if len(findings) == 0 {
		ps.mu.Unlock()
		return
	}
	defer ps.mu.Unlock()
	for _, f := range findings {
		key := host + ":" + f.ID
		if _, exists := ps.items[key]; !exists {
			ps.items[key] = PassiveFinding{
				Finding:      f,
				DiscoveredAt: time.Now().UTC(),
				AffectedURL:  pr.URL,
			}
		}
	}
}

type spaHostState struct {
	seenPaths  map[string]struct{}
	shellCount map[string]int
	markerHits int
	bundleHits int
	detected   bool
}

const (
	minSPASamplePaths = 3
	minSPAShellHits   = 3
)

var (
	rePassiveHTMLTag = regexp.MustCompile(`(?i)</?([a-z0-9-]+)[^>]*>`)
	reSPABundlePath  = regexp.MustCompile(`(?i)(?:/assets/|/static/|/_next/|/_nuxt/|chunk|bundle|runtime)[^"' >]+\.js`)
	spaHintTokens    = []string{
		`id="root"`,
		`id='root'`,
		`id="__next"`,
		`data-reactroot`,
		`__nuxt`,
		`data-v-app`,
		`__vite`,
		`single page app`,
		`/_next/`,
		`/_nuxt/`,
	}
)

func (ps *PassiveScanStore) analyzeLikelySPALocked(host string, pr *model.ProxyRequest) *model.Finding {
	if host == "" || pr == nil || pr.ResponseStatus < 200 || pr.ResponseStatus >= 300 {
		return nil
	}
	if !isLikelyHTMLDocument(pr.ResponseHeaders, pr.ResponseBody) {
		return nil
	}
	path := passivePathFrom(pr.URL)
	if !isLikelyDocumentRoute(path) {
		return nil
	}
	state := ps.spaHosts[host]
	if state == nil {
		state = &spaHostState{
			seenPaths:  map[string]struct{}{},
			shellCount: map[string]int{},
		}
		ps.spaHosts[host] = state
	}
	if state.detected {
		return nil
	}
	if _, exists := state.seenPaths[path]; exists {
		return nil
	}
	state.seenPaths[path] = struct{}{}
	fingerprint := spaShellFingerprint(pr.ResponseBody)
	state.shellCount[fingerprint]++
	bodyLower := strings.ToLower(pr.ResponseBody)
	if hasSPAHints(bodyLower) {
		state.markerHits++
	}
	if reSPABundlePath.MatchString(bodyLower) {
		state.bundleHits++
	}
	if len(state.seenPaths) < minSPASamplePaths || state.shellCount[fingerprint] < minSPAShellHits {
		return nil
	}
	if state.markerHits < 2 && state.bundleHits < 2 {
		return nil
	}
	state.detected = true
	confidence := 0.7
	if state.markerHits >= 3 || state.bundleHits >= 3 {
		confidence = 0.85
	}
	return &model.Finding{
		ID:             "proxy-site-likely-spa",
		Category:       "fingerprint",
		Severity:       model.SeverityInfo,
		Title:          "Likely single-page application detected",
		Description:    "Captured proxy responses suggest this host serves a repeated HTML app-shell across multiple routes, which is typical SPA behavior.",
		Evidence:       fmt.Sprintf("Host %s returned matching HTML shell fingerprints across %d distinct document routes (markers=%d, bundles=%d).", host, state.shellCount[fingerprint], state.markerHits, state.bundleHits),
		Recommendation: "Use intercepted API/XHR traffic and route-aware testing because many paths may return the same SPA shell rather than unique server-rendered pages.",
		AffectedURL:    pr.URL,
		Confidence:     confidence,
	}
}

func isLikelyHTMLDocument(headers map[string]string, body string) bool {
	contentType := strings.ToLower(strings.TrimSpace(headerValue(headers, "Content-Type")))
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml") {
		return true
	}
	bodyPrefix := strings.ToLower(strings.TrimSpace(body))
	return strings.HasPrefix(bodyPrefix, "<!doctype html") || strings.HasPrefix(bodyPrefix, "<html")
}

func headerValue(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(strings.TrimSpace(k), key) {
			return v
		}
	}
	return ""
}

func passivePathFrom(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "/"
	}
	p := strings.TrimSpace(u.EscapedPath())
	if p == "" {
		return "/"
	}
	return p
}

func isLikelyDocumentRoute(requestPath string) bool {
	if requestPath == "" || requestPath == "/" {
		return true
	}
	ext := strings.ToLower(pathpkg.Ext(requestPath))
	return ext == "" || ext == ".html" || ext == ".htm"
}

func spaShellFingerprint(body string) string {
	matches := rePassiveHTMLTag.FindAllStringSubmatch(strings.ToLower(body), 300)
	if len(matches) == 0 {
		return "no-tags"
	}
	var b strings.Builder
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		b.WriteString(m[1])
		b.WriteByte('|')
	}
	return b.String()
}

func hasSPAHints(lowerBody string) bool {
	for _, token := range spaHintTokens {
		if strings.Contains(lowerBody, token) {
			return true
		}
	}
	return false
}

// Clear removes all stored passive findings.
func (ps *PassiveScanStore) Clear() {
	if ps == nil {
		return
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.items = map[string]PassiveFinding{}
	ps.spaHosts = map[string]*spaHostState{}
}

// List returns all passive findings sorted newest-first. Returns a non-nil
// empty slice when there are no findings so JSON marshals as [].
func (ps *PassiveScanStore) List() []PassiveFinding {
	if ps == nil {
		return []PassiveFinding{}
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]PassiveFinding, 0, len(ps.items))
	for _, f := range ps.items {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].DiscoveredAt.After(out[j].DiscoveredAt)
	})
	return out
}


// runPassiveChecks runs all passive analysis routines against a captured
// request and returns any findings.
func runPassiveChecks(pr *model.ProxyRequest) []model.Finding {
	var findings []model.Finding
	findings = append(findings, AnalyzeHeaders(pr)...)
	findings = append(findings, passiveCheckHSTS(pr)...)
	findings = append(findings, passiveCheckCookies(pr)...)
	findings = append(findings, passiveCheckSecrets(pr)...)
	return findings
}

// passiveCheckHSTS flags HTTPS responses that are missing the
// Strict-Transport-Security header.
func passiveCheckHSTS(pr *model.ProxyRequest) []model.Finding {
	if !strings.HasPrefix(strings.ToLower(pr.URL), "https://") {
		return nil
	}
	if strings.TrimSpace(pr.ResponseHeaders[http.CanonicalHeaderKey("Strict-Transport-Security")]) != "" {
		return nil
	}
	return []model.Finding{{
		ID:          "proxy-no-hsts",
		Category:    "headers",
		Severity:    model.SeverityMedium,
		Title:       "Missing Strict-Transport-Security header",
		Description: "The HTTPS response does not include a Strict-Transport-Security (HSTS) header. Without HSTS, browsers may be downgraded to plain HTTP.",
		Evidence:    "Strict-Transport-Security absent from HTTPS response at " + pr.URL,
		Recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to all HTTPS responses.",
		AffectedURL: pr.URL,
	}}
}

// passiveCheckCookies inspects the Set-Cookie response header string for
// cookies missing HttpOnly or (on HTTPS) Secure attributes.
func passiveCheckCookies(pr *model.ProxyRequest) []model.Finding {
	raw := pr.ResponseHeaders[http.CanonicalHeaderKey("Set-Cookie")]
	if raw == "" || raw == "[redacted]" {
		return nil
	}
	lower := strings.ToLower(raw)
	var findings []model.Finding
	if !strings.Contains(lower, "httponly") {
		findings = append(findings, model.Finding{
			ID:          "proxy-cookie-no-httponly",
			Category:    "cookies",
			Severity:    model.SeverityMedium,
			Title:       "Cookie missing HttpOnly attribute",
			Description: "One or more Set-Cookie headers lack the HttpOnly attribute, making session cookies accessible to JavaScript and increasing XSS impact.",
			Evidence:    "Set-Cookie header without HttpOnly from " + pr.URL,
			Recommendation: "Add HttpOnly to all session and authentication cookies.",
			AffectedURL: pr.URL,
		})
	}
	if strings.HasPrefix(strings.ToLower(pr.URL), "https://") {
		// The Secure attribute appears as "; secure" or "; secure;" after any
		// cookie in the combined header value. A case-insensitive check on the
		// lower-cased string handles all standard representations.
		hasSecure := strings.Contains(lower, "; secure") ||
			strings.Contains(lower, ";secure") ||
			strings.HasPrefix(lower, "secure;") ||
			lower == "secure"
		if !hasSecure {
			findings = append(findings, model.Finding{
				ID:          "proxy-cookie-no-secure",
				Category:    "cookies",
				Severity:    model.SeverityMedium,
				Title:       "Cookie missing Secure flag on HTTPS endpoint",
				Description: "One or more Set-Cookie headers on this HTTPS endpoint lack the Secure attribute, allowing the cookie to be sent over plain HTTP.",
				Evidence:    "Set-Cookie header without Secure flag from " + pr.URL,
				Recommendation: "Add the Secure attribute to all cookies served over HTTPS.",
				AffectedURL: pr.URL,
			})
		}
	}
	return findings
}

var (
	rePassiveJWT     = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`)
	rePassiveAWSKey  = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	rePassiveGHToken = regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)
	rePassivePrivKey = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	rePassiveGenKey  = regexp.MustCompile(`(?i)["' ](api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_.\-]{20,})["']?`)
)

// passiveCheckSecrets scans the response body for common credential and
// secret patterns.
func passiveCheckSecrets(pr *model.ProxyRequest) []model.Finding {
	body := pr.ResponseBody
	if len(body) == 0 {
		return nil
	}
	var findings []model.Finding
	if rePassiveJWT.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:          "proxy-secret-jwt",
			Category:    "disclosure",
			Severity:    model.SeverityMedium,
			Title:       "JWT token found in response body",
			Description: "A JSON Web Token (JWT) was detected in the response body. Exposed JWTs can be replayed to impersonate users.",
			Evidence:    "JWT pattern detected in response from " + pr.URL,
			Recommendation: "Transmit JWTs only over secure channels; avoid embedding them in response bodies unnecessarily.",
			AffectedURL: pr.URL,
		})
	}
	if rePassiveAWSKey.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:          "proxy-secret-aws-key",
			Category:    "disclosure",
			Severity:    model.SeverityHigh,
			Title:       "AWS access key ID found in response body",
			Description: "An AWS access key ID (AKIA...) was detected in the response body, indicating a potential credential leak.",
			Evidence:    "AWS key pattern detected in response from " + pr.URL,
			Recommendation: "Rotate exposed AWS credentials immediately and audit IAM policies.",
			AffectedURL: pr.URL,
		})
	}
	if rePassiveGHToken.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:          "proxy-secret-github-token",
			Category:    "disclosure",
			Severity:    model.SeverityHigh,
			Title:       "GitHub personal access token found in response body",
			Description: "A GitHub personal access token (ghp_...) was detected in the response body.",
			Evidence:    "GitHub token pattern detected in response from " + pr.URL,
			Recommendation: "Revoke exposed GitHub tokens immediately and audit repository access.",
			AffectedURL: pr.URL,
		})
	}
	if rePassivePrivKey.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:          "proxy-secret-private-key",
			Category:    "disclosure",
			Severity:    model.SeverityCritical,
			Title:       "Private key material found in response body",
			Description: "A private key header (RSA, EC, or OpenSSH) was detected in the response body — a severe credential exposure.",
			Evidence:    "Private key header pattern detected in response from " + pr.URL,
			Recommendation: "Rotate the exposed key pair immediately and audit web server configuration to prevent key material from being served.",
			AffectedURL: pr.URL,
		})
	}
	if rePassiveGenKey.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:          "proxy-secret-generic-key",
			Category:    "disclosure",
			Severity:    model.SeverityMedium,
			Title:       "API key or access token pattern found in response body",
			Description: "A pattern consistent with an API key or access token was detected in the response body.",
			Evidence:    "API key/token pattern detected in response from " + pr.URL,
			Recommendation: "Avoid embedding API keys in responses. Rotate any exposed credentials and use a secrets manager.",
			AffectedURL: pr.URL,
		})
	}
	return findings
}

// passiveHostFrom extracts the hostname from a raw URL string, falling back
// to the raw string when parsing fails.
func passiveHostFrom(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}
