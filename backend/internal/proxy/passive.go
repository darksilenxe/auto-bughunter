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
	findings = append(findings, passiveCheckPrivacyHeaders(pr)...)
	findings = append(findings, passiveCheckDirectoryListing(pr)...)
	findings = append(findings, passiveCheckVerboseErrors(pr)...)
	findings = append(findings, passiveCheckInfoDisclosure(pr)...)
	findings = append(findings, passiveCheckMixedContent(pr)...)
	findings = append(findings, passiveCheckSensitiveURLParams(pr)...)
	findings = append(findings, passiveCheckAutocompletePassword(pr)...)
	findings = append(findings, passiveCheckCacheableSensitive(pr)...)
	findings = append(findings, passiveCheckReflectedOriginCORS(pr)...)
	findings = append(findings, passiveCheckAdditionalCSRF(pr)...)
	return findings
}

// csrfFieldNamePattern matches common anti-CSRF hidden-field/header naming
// conventions used across frameworks (Django, Rails, ASP.NET, Spring,
// generic "csrf_token", etc.).
var csrfFieldNamePattern = regexp.MustCompile(`(?i)(csrf[_-]?token|_csrf|_token|authenticity_token|csrfmiddlewaretoken|requestverificationtoken|xsrf[_-]?token)`)

// reHTMLFormOpenTag matches an opening <form ...> tag so its method
// attribute and body (up to the matching </form>) can be inspected for a
// CSRF token field.
var reHTMLFormOpenTag = regexp.MustCompile(`(?is)<form\b[^>]*>`)
var reFormMethodAttr = regexp.MustCompile(`(?is)\bmethod\s*=\s*["']?(get|post|put|patch|delete)["']?`)

// passiveCheckAdditionalCSRF implements a small set of additional CSRF
// checks beyond the existing SameSite cookie check ("Additional CSRF
// Checks", à la the Burp Suite extension of the same name):
//
//  1. HTML forms with a state-changing method (POST/PUT/PATCH/DELETE) that
//     contain no anti-CSRF hidden field, when the response also sets a
//     session cookie.
//  2. Cookie-authenticated (session-cookie-bearing) state-changing requests
//     (POST/PUT/PATCH/DELETE) whose body/headers carry no anti-CSRF token
//     at all — the request-side counterpart of check 1, useful for JSON
//     APIs where there is no HTML form to inspect.
func passiveCheckAdditionalCSRF(pr *model.ProxyRequest) []model.Finding {
	var findings []model.Finding

	// Check 1: HTML response containing state-changing forms without a
	// visible anti-CSRF field, on a page that establishes a session cookie.
	if hasSessionCookie(pr) && looksLikeHTML(pr.ResponseHeaders) {
		for _, form := range reHTMLFormOpenTag.FindAllStringIndex(pr.ResponseBody, -1) {
			openTag := pr.ResponseBody[form[0]:form[1]]
			methodMatch := reFormMethodAttr.FindStringSubmatch(openTag)
			if methodMatch == nil || strings.EqualFold(methodMatch[1], "get") {
				continue // default/explicit GET forms don't need a CSRF token
			}
			closeIdx := strings.Index(pr.ResponseBody[form[1]:], "</form>")
			var formBody string
			if closeIdx >= 0 {
				formBody = pr.ResponseBody[form[1] : form[1]+closeIdx]
			} else {
				formBody = pr.ResponseBody[form[1]:]
			}
			if !csrfFieldNamePattern.MatchString(formBody) {
				findings = append(findings, model.Finding{
					ID:             "proxy-csrf-form-missing-token",
					Category:       "csrf",
					Severity:       model.SeverityMedium,
					Title:          "State-changing HTML form missing anti-CSRF token",
					Description:    "A form using a state-changing HTTP method (POST/PUT/PATCH/DELETE) was found with no recognizable anti-CSRF hidden field, while the response also establishes a session cookie. This may allow a cross-site request forgery attack against the form's action.",
					Evidence:       fmt.Sprintf("Form tag %q on %s has no csrf_token/authenticity_token/__RequestVerificationToken-style hidden field.", strings.TrimSpace(openTag), pr.URL),
					Recommendation: "Include a unique, unpredictable, per-session (or per-request) anti-CSRF token as a hidden field in every state-changing form and validate it server-side.",
					AffectedURL:    pr.URL,
				})
				break // one finding per page is sufficient signal
			}
		}
	}

	// Check 2: cookie-authenticated JSON/form API requests with a
	// state-changing method and no CSRF token in body or headers.
	if isStateChangingMethod(pr.Method) && pr.RequestHeaders[http.CanonicalHeaderKey("Cookie")] != "" {
		hasTokenHeader := false
		for name := range pr.RequestHeaders {
			if csrfFieldNamePattern.MatchString(name) {
				hasTokenHeader = true
				break
			}
		}
		if !hasTokenHeader && !csrfFieldNamePattern.MatchString(pr.RequestBody) {
			findings = append(findings, model.Finding{
				ID:             "proxy-csrf-request-missing-token",
				Category:       "csrf",
				Severity:       model.SeverityLow,
				Title:          "Cookie-authenticated state-changing request has no anti-CSRF token",
				Description:    "A state-changing request (POST/PUT/PATCH/DELETE) is authenticated via a Cookie header but carries no recognizable anti-CSRF token in its body or headers (e.g. X-CSRF-Token). If the endpoint relies solely on the session cookie for authorization, it may be vulnerable to CSRF.",
				Evidence:       fmt.Sprintf("%s %s sent a Cookie header with no csrf_token/X-CSRF-Token-style value in the body or headers.", pr.Method, pr.URL),
				Recommendation: "Require a per-session anti-CSRF token (double-submit cookie or synchronizer token) validated server-side for every cookie-authenticated state-changing request, or use SameSite=Strict/Lax cookies plus custom-header checks for JSON APIs.",
				AffectedURL:    pr.URL,
			})
		}
	}

	return findings
}

func hasSessionCookie(pr *model.ProxyRequest) bool {
	raw := pr.ResponseHeaders[http.CanonicalHeaderKey("Set-Cookie")]
	return raw != "" && raw != "[redacted]"
}

func looksLikeHTML(headers map[string]string) bool {
	ct := strings.ToLower(headers[http.CanonicalHeaderKey("Content-Type")])
	return strings.Contains(ct, "html")
}

func isStateChangingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// passiveCheckPrivacyHeaders flags HTML responses missing Referrer-Policy
// and Permissions-Policy headers, both of which reduce data leakage and
// limit access to sensitive browser APIs.
func passiveCheckPrivacyHeaders(pr *model.ProxyRequest) []model.Finding {
	if !isLikelyHTMLDocument(pr.ResponseHeaders, pr.ResponseBody) {
		return nil
	}
	var findings []model.Finding
	if strings.TrimSpace(headerValue(pr.ResponseHeaders, "Referrer-Policy")) == "" {
		findings = append(findings, model.Finding{
			ID:             "proxy-no-referrer-policy",
			Category:       "headers",
			Severity:       model.SeverityLow,
			Title:          "No Referrer-Policy header",
			Description:    "The response has no Referrer-Policy header, so the full URL (including any sensitive query parameters) may leak to third parties via the Referer header on outbound requests.",
			Evidence:       "Referrer-Policy absent from response at " + pr.URL,
			Recommendation: "Add Referrer-Policy: strict-origin-when-cross-origin (or stricter) to all responses.",
			AffectedURL:    pr.URL,
		})
	}
	if strings.TrimSpace(headerValue(pr.ResponseHeaders, "Permissions-Policy")) == "" {
		findings = append(findings, model.Finding{
			ID:             "proxy-no-permissions-policy",
			Category:       "headers",
			Severity:       model.SeverityLow,
			Title:          "No Permissions-Policy header",
			Description:    "The response has no Permissions-Policy header, leaving powerful browser features (camera, microphone, geolocation, etc.) unrestricted for embedded/third-party content.",
			Evidence:       "Permissions-Policy absent from response at " + pr.URL,
			Recommendation: "Add a Permissions-Policy header that disables unused browser features.",
			AffectedURL:    pr.URL,
		})
	}
	return findings
}

var reDirectoryListingTitle = regexp.MustCompile(`(?i)<title>\s*index of `)

// passiveCheckDirectoryListing flags responses that look like an
// auto-generated directory listing page (e.g. Apache/nginx "Index of /").
func passiveCheckDirectoryListing(pr *model.ProxyRequest) []model.Finding {
	if pr.ResponseStatus < 200 || pr.ResponseStatus >= 300 {
		return nil
	}
	body := pr.ResponseBody
	if body == "" {
		return nil
	}
	if !reDirectoryListingTitle.MatchString(body) && !strings.Contains(body, "Index of /") {
		return nil
	}
	return []model.Finding{{
		ID:             "proxy-directory-listing",
		Category:       "disclosure",
		Severity:       model.SeverityMedium,
		Title:          "Directory listing exposed",
		Description:    "The server returned an auto-generated directory listing page, which can reveal file names, backups, or other unintended content.",
		Evidence:       "Directory listing markers detected in response from " + pr.URL,
		Recommendation: "Disable directory indexing in the web server configuration and remove any unintentionally exposed files.",
		AffectedURL:    pr.URL,
	}}
}

var passiveVerboseErrorPatterns = []struct {
	pattern *regexp.Regexp
	label   string
}{
	{regexp.MustCompile(`(?i)at\s+[\w.$]+\([\w.]+\.java:\d+\)`), "Java stack trace"},
	{regexp.MustCompile(`(?i)Traceback \(most recent call last\)`), "Python traceback"},
	{regexp.MustCompile(`(?i)Warning:\s+(mysql|pg_|mssql|oci_)\w*\(\)`), "PHP database warning"},
	{regexp.MustCompile(`(?i)Microsoft OLE DB Provider for (ODBC|SQL Server)`), "ASP/ADO database error"},
	{regexp.MustCompile(`(?i)System\.(NullReferenceException|Data\.SqlClient|Web\.HttpException)`), ".NET exception"},
	{regexp.MustCompile(`(?i)org\.(springframework|hibernate)\.\w+Exception`), "Java framework exception"},
	{regexp.MustCompile(`(?i)Fatal error:\s+Uncaught`), "PHP fatal error"},
	{regexp.MustCompile(`(?i)ORA-\d{5}`), "Oracle database error"},
	{regexp.MustCompile(`(?i)you have an error in your sql syntax`), "MySQL syntax error"},
}

// passiveCheckVerboseErrors flags response bodies that contain stack traces
// or verbose database/framework error messages, which can disclose internal
// implementation details useful to an attacker.
func passiveCheckVerboseErrors(pr *model.ProxyRequest) []model.Finding {
	body := pr.ResponseBody
	if body == "" {
		return nil
	}
	for _, p := range passiveVerboseErrorPatterns {
		if p.pattern.MatchString(body) {
			return []model.Finding{{
				ID:             "proxy-verbose-error",
				Category:       "disclosure",
				Severity:       model.SeverityMedium,
				Title:          "Verbose error/stack trace disclosed",
				Description:    fmt.Sprintf("The response body contains what looks like a %s, which can reveal internal file paths, framework versions, or query structure to an attacker.", p.label),
				Evidence:       fmt.Sprintf("%s pattern detected in response from %s", p.label, pr.URL),
				Recommendation: "Disable verbose/debug error output in production and return generic error pages instead.",
				AffectedURL:    pr.URL,
			}}
		}
	}
	return nil
}

var rePassiveInternalIP = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)

// passiveCheckInfoDisclosure flags response bodies containing internal
// (RFC 1918) IP addresses, which can aid network reconnaissance.
func passiveCheckInfoDisclosure(pr *model.ProxyRequest) []model.Finding {
	body := pr.ResponseBody
	if body == "" {
		return nil
	}
	if !rePassiveInternalIP.MatchString(body) {
		return nil
	}
	return []model.Finding{{
		ID:             "proxy-internal-ip-disclosure",
		Category:       "disclosure",
		Severity:       model.SeverityLow,
		Title:          "Internal IP address disclosed",
		Description:    "The response body contains a private (RFC 1918) IP address, which can help an attacker map internal network topology.",
		Evidence:       "Internal IP address pattern detected in response from " + pr.URL,
		Recommendation: "Avoid exposing internal network addresses in client-facing responses.",
		AffectedURL:    pr.URL,
	}}
}

// passiveCheckMixedContent flags HTTPS pages that reference plain-HTTP
// subresources, which browsers may block or downgrade and which expose
// those subresources to network tampering.
func passiveCheckMixedContent(pr *model.ProxyRequest) []model.Finding {
	if !strings.HasPrefix(strings.ToLower(pr.URL), "https://") {
		return nil
	}
	if !isLikelyHTMLDocument(pr.ResponseHeaders, pr.ResponseBody) {
		return nil
	}
	body := pr.ResponseBody
	if body == "" {
		return nil
	}
	if !reMixedContentRef.MatchString(body) {
		return nil
	}
	return []model.Finding{{
		ID:             "proxy-mixed-content",
		Category:       "transport",
		Severity:       model.SeverityLow,
		Title:          "Mixed content: HTTPS page loads HTTP subresources",
		Description:    "An HTTPS page references one or more subresources over plain HTTP (src/href=\"http://...\"), which can be intercepted or modified by a network attacker.",
		Evidence:       "http:// subresource reference detected in HTTPS response from " + pr.URL,
		Recommendation: "Serve all subresources over HTTPS, or use protocol-relative/relative URLs.",
		AffectedURL:    pr.URL,
	}}
}

var reMixedContentRef = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']http://[^"']+["']`)

var sensitiveURLParamNames = []string{
	"password", "passwd", "pwd", "token", "access_token", "accesstoken",
	"api_key", "apikey", "secret", "session_id", "sessionid", "sid",
	"auth", "jwt",
}

// passiveCheckSensitiveURLParams flags requests carrying apparently
// sensitive values (passwords, tokens, session IDs) in the URL query
// string, since URLs are commonly logged and cached by proxies, browsers,
// and servers.
func passiveCheckSensitiveURLParams(pr *model.ProxyRequest) []model.Finding {
	u, err := url.Parse(strings.TrimSpace(pr.URL))
	if err != nil || u.RawQuery == "" {
		return nil
	}
	query := u.Query()
	for name := range query {
		lower := strings.ToLower(name)
		for _, sensitive := range sensitiveURLParamNames {
			if strings.Contains(lower, sensitive) {
				return []model.Finding{{
					ID:             "proxy-sensitive-data-in-url",
					Category:       "disclosure",
					Severity:       model.SeverityMedium,
					Title:          "Sensitive data passed in URL query string",
					Description:    fmt.Sprintf("The request URL includes a query parameter (%q) whose name suggests it carries a sensitive value such as a password, token, or session identifier. Query strings are commonly logged in server/proxy access logs, browser history, and Referer headers.", name),
					Evidence:       fmt.Sprintf("Sensitive-looking parameter %q found in URL %s", name, pr.URL),
					Recommendation: "Send sensitive values in the request body or headers instead of the URL query string.",
					AffectedURL:    pr.URL,
				}}
			}
		}
	}
	return nil
}

var rePasswordInputNoAutocompleteOff = regexp.MustCompile(`(?i)<input\b[^>]*type\s*=\s*["']password["'][^>]*>`)

// passiveCheckAutocompletePassword flags HTML password input fields that do
// not explicitly disable autocomplete, which can leave credentials cached
// in the browser on shared machines.
func passiveCheckAutocompletePassword(pr *model.ProxyRequest) []model.Finding {
	if !isLikelyHTMLDocument(pr.ResponseHeaders, pr.ResponseBody) {
		return nil
	}
	body := pr.ResponseBody
	matches := rePasswordInputNoAutocompleteOff.FindAllString(body, -1)
	if len(matches) == 0 {
		return nil
	}
	for _, m := range matches {
		lower := strings.ToLower(m)
		if !strings.Contains(lower, `autocomplete="off"`) && !strings.Contains(lower, `autocomplete='off'`) &&
			!strings.Contains(lower, `autocomplete="new-password"`) && !strings.Contains(lower, `autocomplete='new-password'`) {
			return []model.Finding{{
				ID:             "proxy-password-autocomplete-enabled",
				Category:       "form",
				Severity:       model.SeverityLow,
				Title:          "Password field allows browser autocomplete",
				Description:    "A password <input> field does not set autocomplete=\"off\"/\"new-password\", allowing browsers to store and auto-fill the credential, which is risky on shared or public computers.",
				Evidence:       "Password input without autocomplete restriction detected in response from " + pr.URL,
				Recommendation: "Add autocomplete=\"new-password\" (or \"off\") to password input fields on sensitive forms.",
				AffectedURL:    pr.URL,
			}}
		}
	}
	return nil
}

// passiveCheckCacheableSensitive flags HTTPS responses that set a session
// cookie but do not forbid caching, meaning shared/intermediate caches or
// the local browser disk cache could retain a page containing session
// state.
func passiveCheckCacheableSensitive(pr *model.ProxyRequest) []model.Finding {
	setCookie := pr.ResponseHeaders[http.CanonicalHeaderKey("Set-Cookie")]
	if setCookie == "" || setCookie == "[redacted]" {
		return nil
	}
	cacheControl := strings.ToLower(headerValue(pr.ResponseHeaders, "Cache-Control"))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private") {
		return nil
	}
	return []model.Finding{{
		ID:             "proxy-cacheable-set-cookie-response",
		Category:       "headers",
		Severity:       model.SeverityLow,
		Title:          "Cacheable response sets a cookie",
		Description:    "The response sets a cookie but does not include Cache-Control: no-store or private, so shared caches or the browser disk cache could retain a response containing session-related data.",
		Evidence:       "Set-Cookie present without a restrictive Cache-Control directive on response from " + pr.URL,
		Recommendation: "Add Cache-Control: no-store (or at least private) to any response that sets or depends on session cookies.",
		AffectedURL:    pr.URL,
	}}
}

// passiveCheckReflectedOriginCORS flags responses where
// Access-Control-Allow-Origin reflects the request's Origin header (rather
// than a fixed allow-list) while Access-Control-Allow-Credentials is true,
// which effectively allows any origin to make credentialed requests.
func passiveCheckReflectedOriginCORS(pr *model.ProxyRequest) []model.Finding {
	acao := headerValue(pr.ResponseHeaders, "Access-Control-Allow-Origin")
	acac := headerValue(pr.ResponseHeaders, "Access-Control-Allow-Credentials")
	origin := strings.TrimSpace(headerValue(pr.RequestHeaders, "Origin"))
	if acao == "" || origin == "" || acao == "*" {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(acac), "true") {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(acao), origin) {
		return nil
	}
	return []model.Finding{{
		ID:             "proxy-cors-reflected-origin-creds",
		Category:       "cors",
		Severity:       model.SeverityHigh,
		Title:          "CORS reflects request Origin with credentials allowed",
		Description:    "Access-Control-Allow-Origin echoes back the request's Origin header verbatim and Access-Control-Allow-Credentials is true, effectively allowing any origin to make credentialed cross-site requests and read the response.",
		Evidence:       fmt.Sprintf("Request Origin %q reflected in Access-Control-Allow-Origin with credentials=true (from %s)", origin, pr.URL),
		Recommendation: "Validate the Origin header against an explicit allow-list before reflecting it, and avoid combining reflected origins with Access-Control-Allow-Credentials: true.",
		AffectedURL:    pr.URL,
	}}
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
		ID:             "proxy-no-hsts",
		Category:       "headers",
		Severity:       model.SeverityMedium,
		Title:          "Missing Strict-Transport-Security header",
		Description:    "The HTTPS response does not include a Strict-Transport-Security (HSTS) header. Without HSTS, browsers may be downgraded to plain HTTP.",
		Evidence:       "Strict-Transport-Security absent from HTTPS response at " + pr.URL,
		Recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to all HTTPS responses.",
		AffectedURL:    pr.URL,
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
			ID:             "proxy-cookie-no-httponly",
			Category:       "cookies",
			Severity:       model.SeverityMedium,
			Title:          "Cookie missing HttpOnly attribute",
			Description:    "One or more Set-Cookie headers lack the HttpOnly attribute, making session cookies accessible to JavaScript and increasing XSS impact.",
			Evidence:       "Set-Cookie header without HttpOnly from " + pr.URL,
			Recommendation: "Add HttpOnly to all session and authentication cookies.",
			AffectedURL:    pr.URL,
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
				ID:             "proxy-cookie-no-secure",
				Category:       "cookies",
				Severity:       model.SeverityMedium,
				Title:          "Cookie missing Secure flag on HTTPS endpoint",
				Description:    "One or more Set-Cookie headers on this HTTPS endpoint lack the Secure attribute, allowing the cookie to be sent over plain HTTP.",
				Evidence:       "Set-Cookie header without Secure flag from " + pr.URL,
				Recommendation: "Add the Secure attribute to all cookies served over HTTPS.",
				AffectedURL:    pr.URL,
			})
		}
	}
	if !strings.Contains(lower, "samesite") {
		findings = append(findings, model.Finding{
			ID:             "proxy-cookie-no-samesite",
			Category:       "cookies",
			Severity:       model.SeverityLow,
			Title:          "Cookie missing SameSite attribute",
			Description:    "One or more Set-Cookie headers lack the SameSite attribute, leaving the cookie sent with cross-site requests by default in older browsers and increasing CSRF exposure.",
			Evidence:       "Set-Cookie header without SameSite from " + pr.URL,
			Recommendation: "Add SameSite=Lax (or Strict, where appropriate) to all cookies.",
			AffectedURL:    pr.URL,
		})
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
			ID:             "proxy-secret-jwt",
			Category:       "disclosure",
			Severity:       model.SeverityMedium,
			Title:          "JWT token found in response body",
			Description:    "A JSON Web Token (JWT) was detected in the response body. Exposed JWTs can be replayed to impersonate users.",
			Evidence:       "JWT pattern detected in response from " + pr.URL,
			Recommendation: "Transmit JWTs only over secure channels; avoid embedding them in response bodies unnecessarily.",
			AffectedURL:    pr.URL,
		})
	}
	if rePassiveAWSKey.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:             "proxy-secret-aws-key",
			Category:       "disclosure",
			Severity:       model.SeverityHigh,
			Title:          "AWS access key ID found in response body",
			Description:    "An AWS access key ID (AKIA...) was detected in the response body, indicating a potential credential leak.",
			Evidence:       "AWS key pattern detected in response from " + pr.URL,
			Recommendation: "Rotate exposed AWS credentials immediately and audit IAM policies.",
			AffectedURL:    pr.URL,
		})
	}
	if rePassiveGHToken.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:             "proxy-secret-github-token",
			Category:       "disclosure",
			Severity:       model.SeverityHigh,
			Title:          "GitHub personal access token found in response body",
			Description:    "A GitHub personal access token (ghp_...) was detected in the response body.",
			Evidence:       "GitHub token pattern detected in response from " + pr.URL,
			Recommendation: "Revoke exposed GitHub tokens immediately and audit repository access.",
			AffectedURL:    pr.URL,
		})
	}
	if rePassivePrivKey.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:             "proxy-secret-private-key",
			Category:       "disclosure",
			Severity:       model.SeverityCritical,
			Title:          "Private key material found in response body",
			Description:    "A private key header (RSA, EC, or OpenSSH) was detected in the response body — a severe credential exposure.",
			Evidence:       "Private key header pattern detected in response from " + pr.URL,
			Recommendation: "Rotate the exposed key pair immediately and audit web server configuration to prevent key material from being served.",
			AffectedURL:    pr.URL,
		})
	}
	if rePassiveGenKey.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:             "proxy-secret-generic-key",
			Category:       "disclosure",
			Severity:       model.SeverityMedium,
			Title:          "API key or access token pattern found in response body",
			Description:    "A pattern consistent with an API key or access token was detected in the response body.",
			Evidence:       "API key/token pattern detected in response from " + pr.URL,
			Recommendation: "Avoid embedding API keys in responses. Rotate any exposed credentials and use a secrets manager.",
			AffectedURL:    pr.URL,
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
