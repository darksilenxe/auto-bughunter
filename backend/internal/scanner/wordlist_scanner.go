package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
	"auto-bughunter/backend/internal/wordlist"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var (
	pathStateWhitespaceRe = regexp.MustCompile(`\s+`)
	pathStateTokenRe      = regexp.MustCompile(`\b[0-9a-f]{8,}\b|\b\d{4,}\b`)
	pathStateTitleRe      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spaResponseHints      = []string{"id=\"root\"", "id='root'", "id=\"__next\"", "data-reactroot", "__nuxt", "data-v-app", "__vite", "single page app", "/_next/", "/_nuxt/"}
	loginWallHints        = []string{"sign in", "log in", "login", "password", "remember me", "name=\"password\"", "name='password'"}
	apiErrorEnvelopeHints = []string{"\"error\"", "\"message\"", "\"status\"", "\"path\"", "\"timestamp\"", "\"errors\""}
	notFoundResponseHints = []string{"not found", "404", "cannot get /", "page could not be found", "whitelabel error page", "does not exist", "the page you requested could not be found"}
)

type WordlistScanner struct {
	httpClient      *http.Client
	maxConcurrency  int
	timeoutPerCheck time.Duration
}

type wordlistScanKind string

const (
	wordlistScanKindDirectory wordlistScanKind = "directory"
	wordlistScanKindAPI       wordlistScanKind = "api"
)

type responseClass string

const (
	responseClassUnknown          responseClass = "unknown"
	responseClassSoft404          responseClass = "soft-404"
	responseClassSPAFallback      responseClass = "spa-fallback"
	responseClassAuthWall         responseClass = "auth-wall"
	responseClassAPIErrorEnvelope responseClass = "api-error-envelope"
	responseClassStaticAsset      responseClass = "static-asset"
	responseClassTrueContent      responseClass = "true-content-difference"
	responseClassRouteRedirect    responseClass = "route-redirect"
)

type frameworkCatalogEntry struct {
	Key               string
	TechnologyAliases []string
	HeaderHints       []string
	BodyHints         []string
	CookieHints       []string
	PrioritizedDirs   []string
	PrioritizedAPIs   []string
}

type frameworkProfile struct {
	Name                    string
	Technologies            []string
	Hints                   []string
	PrioritizedDirectories  []string
	PrioritizedAPIEndpoints []string
}

type pathStateFingerprint struct {
	status        int
	contentType   string
	bodySample    string
	bodyText      string
	title         string
	location      string
	accessible    bool
	hasSPAMarkers bool
	hasLoginWall  bool
	hasAPIError   bool
	notFoundHint  bool
	headers       http.Header
}

type wordlistProbeResult struct {
	Path          string
	URL           string
	Status        int
	Score         int
	ResponseClass responseClass
	Reason        string
}

type wordlistProbeSummary struct {
	Profile         frameworkProfile
	SuppressedCount int
	Suppressed      []string
}

var frameworkCatalog = []frameworkCatalogEntry{
	{
		Key:               "nextjs",
		TechnologyAliases: []string{"next.js", "nextjs"},
		BodyHints:         []string{"__next", "/_next/"},
		PrioritizedDirs:   []string{"/_next/static", "/api", "/dashboard", "/login"},
		PrioritizedAPIs:   []string{"/api", "/api/auth", "/_next/data", "/graphql"},
	},
	{
		Key:               "react-spa",
		TechnologyAliases: []string{"react", "vite"},
		BodyHints:         []string{"data-reactroot", "id=\"root\"", "__vite"},
		PrioritizedDirs:   []string{"/dashboard", "/settings", "/profile", "/assets"},
		PrioritizedAPIs:   []string{"/api", "/api/v1", "/graphql"},
	},
	{
		Key:               "nuxt",
		TechnologyAliases: []string{"nuxt", "nuxt.js"},
		BodyHints:         []string{"__nuxt", "/_nuxt/"},
		PrioritizedDirs:   []string{"/_nuxt", "/api", "/dashboard", "/login"},
		PrioritizedAPIs:   []string{"/api", "/graphql", "/api/_content/query"},
	},
	{
		Key:               "vue-spa",
		TechnologyAliases: []string{"vue", "vue.js"},
		BodyHints:         []string{"data-v-app", "id=\"app\"", "router-view"},
		PrioritizedDirs:   []string{"/dashboard", "/settings", "/profile", "/assets"},
		PrioritizedAPIs:   []string{"/api", "/api/v1", "/graphql"},
	},
	{
		Key:               "laravel",
		TechnologyAliases: []string{"laravel"},
		HeaderHints:       []string{"x-powered-by:php"},
		CookieHints:       []string{"laravel_session", "xsrf-token"},
		BodyHints:         []string{"csrf-token", "laravel"},
		PrioritizedDirs:   []string{"/login", "/register", "/storage", "/horizon"},
		PrioritizedAPIs:   []string{"/api", "/api/user", "/sanctum/csrf-cookie"},
	},
	{
		Key:               "django",
		TechnologyAliases: []string{"django"},
		CookieHints:       []string{"csrftoken", "sessionid"},
		BodyHints:         []string{"csrfmiddlewaretoken", "django"},
		PrioritizedDirs:   []string{"/admin", "/accounts/login", "/static"},
		PrioritizedAPIs:   []string{"/api", "/api-auth", "/graphql"},
	},
	{
		Key:               "rails",
		TechnologyAliases: []string{"ruby on rails", "rails"},
		CookieHints:       []string{"_session"},
		BodyHints:         []string{"csrf-param", "csrf-token", "rails"},
		PrioritizedDirs:   []string{"/users/sign_in", "/rails/info/routes", "/assets"},
		PrioritizedAPIs:   []string{"/api", "/rails/active_storage", "/graphql"},
	},
	{
		Key:               "express",
		TechnologyAliases: []string{"express", "node.js"},
		HeaderHints:       []string{"x-powered-by:express"},
		PrioritizedDirs:   []string{"/api", "/auth", "/login", "/health"},
		PrioritizedAPIs:   []string{"/api", "/api/v1", "/auth/login", "/graphql"},
	},
	{
		Key:               "aspnet",
		TechnologyAliases: []string{"asp.net", "iis"},
		HeaderHints:       []string{"x-powered-by:asp.net", "server:microsoft-iis"},
		CookieHints:       []string{".aspnetcore", "asp.net_sessionid"},
		BodyHints:         []string{"__viewstate", "asp.net"},
		PrioritizedDirs:   []string{"/Account/Login", "/swagger", "/hangfire", "/api"},
		PrioritizedAPIs:   []string{"/api", "/swagger", "/swagger/v1/swagger.json", "/graphql"},
	},
	{
		Key:               "spring",
		TechnologyAliases: []string{"spring", "spring boot"},
		CookieHints:       []string{"jsessionid"},
		BodyHints:         []string{"whitelabel error page", "spring"},
		PrioritizedDirs:   []string{"/actuator", "/swagger-ui", "/login", "/api"},
		PrioritizedAPIs:   []string{"/actuator", "/actuator/health", "/v3/api-docs", "/graphql"},
	},
	{
		Key:               "wordpress",
		TechnologyAliases: []string{"wordpress"},
		CookieHints:       []string{"wordpress_", "wp-settings"},
		BodyHints:         []string{"/wp-content/", "/wp-json", "wp-includes"},
		PrioritizedDirs:   []string{"/wp-admin", "/wp-login.php", "/wp-content", "/wp-json"},
		PrioritizedAPIs:   []string{"/wp-json", "/wp-json/wp/v2", "/xmlrpc.php"},
	},
}

func NewWordlistScanner(maxConcurrency int, timeoutPerCheck time.Duration) *WordlistScanner {
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}
	if timeoutPerCheck <= 0 {
		timeoutPerCheck = 3 * time.Second
	}
	return &WordlistScanner{
		httpClient:      &http.Client{Timeout: timeoutPerCheck},
		maxConcurrency:  maxConcurrency,
		timeoutPerCheck: timeoutPerCheck,
	}
}

func (ws *WordlistScanner) ScanDirectories(ctx context.Context, target string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) []model.Finding {
	profile, _, baseline := ws.captureEnumerationContext(ctx, target, authProfile, scanScope)
	dirs := wordlist.GetCommonDirectoriesPrioritized(ctx, []string{profile.Name})
	discovered, summary := ws.probeMultiple(ctx, target, dirs, authProfile, scanScope, wordlistScanKindDirectory, profile, baseline)
	return buildWordlistFindings("wordlist-directories", "directory", discovered, summary, target,
		"Review discovered paths and restrict access to sensitive endpoints.",
		"Test prioritized routes for auth coverage, information disclosure, and unintended exposure.")
}

func (ws *WordlistScanner) ScanSubdomains(ctx context.Context, target string, scanScope model.ScanScope) []model.Finding {
	findings := make([]model.Finding, 0)
	host := extractHostFromURL(target)
	if host == "" {
		return findings
	}

	subs := wordlist.GetCommonSubdomainsWithExternal(ctx)
	discovered := make([]string, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, ws.maxConcurrency*4) // Subdomains are just DNS, can be higher concurrency

	for _, sub := range subs {
		select {
		case <-ctx.Done():
			goto wait
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()

			testHost := s + "." + host
			if !scope.IsHostInScope(testHost, scanScope) {
				return
			}
			// Use a shorter timeout for individual DNS lookups to avoid hanging the scan
			dnsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			ips, err := net.DefaultResolver.LookupIP(dnsCtx, "ip", testHost)
			cancel()
			if err == nil && len(ips) > 0 {
				mu.Lock()
				discovered = append(discovered, testHost)
				mu.Unlock()
			}
		}(sub)
	}

wait:
	wg.Wait()

	if len(discovered) > 0 {
		sort.Strings(discovered)
		evidence := strings.Join(discovered, ", ")
		findings = append(findings, model.Finding{
			ID:             "wordlist-subdomains",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Discovered %d accessible subdomains", len(discovered)),
			Description:    "Wordlist-based subdomain enumeration resolved common subdomains.",
			Evidence:       evidence,
			Recommendation: "Expand assessment scope to include discovered subdomains.",
		})
	}

	return findings
}

func (ws *WordlistScanner) ScanAPIEndpoints(ctx context.Context, target string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) []model.Finding {
	profile, _, baseline := ws.captureEnumerationContext(ctx, target, authProfile, scanScope)
	endpoints := wordlist.GetCommonAPIEndpointsPrioritized(ctx, []string{profile.Name})
	discovered, summary := ws.probeMultiple(ctx, target, endpoints, authProfile, scanScope, wordlistScanKindAPI, profile, baseline)
	return buildWordlistFindings("wordlist-api-endpoints", "API endpoint", discovered, summary, target,
		"Test discovered API endpoints for authentication, authorization, and injection vulnerabilities.",
		"Prioritize JSON and framework-specific API routes for auth, validation, and schema checks.")
}

// ScanSeedRoutes probes a caller-supplied list of route paths (for example,
// endpoints recovered from JavaScript by the SAST pass) instead of brute-forcing
// the full wordlist. Because these routes were observed directly in the
// application's own code they are high-signal and few in number, so this pass
// is substantially faster than a blind wordlist sweep while confirming which of
// the code-referenced routes are actually reachable.
//
// Returns nil when no routes are supplied so callers can fall back to the
// standard enumeration.
func (ws *WordlistScanner) ScanSeedRoutes(ctx context.Context, target string, routes []string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) []model.Finding {
	paths := make([]string, 0, len(routes))
	seen := map[string]struct{}{}
	for _, r := range routes {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !strings.HasPrefix(r, "/") {
			r = "/" + r
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		paths = append(paths, r)
	}
	if len(paths) == 0 {
		return nil
	}

	profile, _, baseline := ws.captureEnumerationContext(ctx, target, authProfile, scanScope)
	discovered, summary := ws.probeMultiple(ctx, target, paths, authProfile, scanScope, wordlistScanKindDirectory, profile, baseline)
	return buildWordlistFindings("wordlist-code-discovered-routes", "code-discovered route", discovered, summary, target,
		"Validate these code-referenced routes for authentication, authorization, and input-handling weaknesses.",
		"Code-referenced routes were probed directly; prioritize any that resolve for deeper manual testing.")
}

func (ws *WordlistScanner) captureEnumerationContext(ctx context.Context, target string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) (frameworkProfile, pathStateFingerprint, pathStateFingerprint) {
	root := ws.captureURLState(ctx, target, authProfile, scanScope)
	baseline := ws.capturePathState(ctx, target, fmt.Sprintf("/__auto-bughunter-state-probe-%d__", time.Now().UnixNano()), authProfile, scanScope)
	profile := inferFrameworkProfile(root)
	if baseline.contentType == "" && baseline.bodySample == "" {
		baseline = root
	}
	return profile, root, baseline
}

func (ws *WordlistScanner) probeMultiple(ctx context.Context, target string, paths []string, authProfile model.ScanAuthProfile, scanScope model.ScanScope, kind wordlistScanKind, profile frameworkProfile, baseline pathStateFingerprint) ([]wordlistProbeResult, wordlistProbeSummary) {
	discovered := make([]wordlistProbeResult, 0)
	suppressed := make([]string, 0)
	sem := make(chan struct{}, ws.maxConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, path := range paths {
		select {
		case <-ctx.Done():
			// Stop scheduling new probes, but still wait for in-flight
			// workers below so they cannot race with the sort/return.
			goto wait
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(candidate string) {
			defer wg.Done()
			defer func() { <-sem }()

			state := ws.capturePathState(ctx, target, candidate, authProfile, scanScope)
			if state.status == 0 {
				return
			}
			result, ok := classifyWordlistResponse(kind, target, candidate, baseline, state, profile)
			mu.Lock()
			defer mu.Unlock()
			if ok {
				discovered = append(discovered, result)
				return
			}
			if result.Reason != "" {
				suppressed = append(suppressed, fmt.Sprintf("%s[%s]", candidate, result.Reason))
			}
		}(path)
	}

wait:
	wg.Wait()

	sort.Slice(discovered, func(i, j int) bool {
		if discovered[i].Score == discovered[j].Score {
			return discovered[i].Path < discovered[j].Path
		}
		return discovered[i].Score > discovered[j].Score
	})
	sort.Strings(suppressed)
	return discovered, wordlistProbeSummary{
		Profile:         profile,
		SuppressedCount: len(suppressed),
		Suppressed:      limitStrings(suppressed, 6),
	}
}

func filterStateChangingPaths(ctx context.Context, client *http.Client, target string, paths []string, authProfile model.ScanAuthProfile, scanScope model.ScanScope, maxConcurrency int, timeoutPerCheck time.Duration) []string {
	if len(paths) == 0 {
		return nil
	}
	if client == nil {
		return append([]string(nil), paths...)
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}
	if timeoutPerCheck <= 0 {
		timeoutPerCheck = 3 * time.Second
	}

	baseline := capturePathStateWithClient(ctx, client, target, fmt.Sprintf("/__auto-bughunter-state-probe-%d__", time.Now().UnixNano()), authProfile, scanScope, timeoutPerCheck)
	profile := inferFrameworkProfile(captureURLStateWithClient(ctx, client, target, authProfile, scanScope, timeoutPerCheck))
	discovered := make([]string, 0, len(paths))
	sem := make(chan struct{}, maxConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(candidate string) {
			defer wg.Done()
			defer func() { <-sem }()
			state := capturePathStateWithClient(ctx, client, target, candidate, authProfile, scanScope, timeoutPerCheck)
			result, ok := classifyWordlistResponse(wordlistScanKindDirectory, target, candidate, baseline, state, profile)
			if !ok || result.Path == "" {
				return
			}
			mu.Lock()
			discovered = append(discovered, candidate)
			mu.Unlock()
		}(path)
	}
	wg.Wait()
	sort.Strings(discovered)
	return discovered
}

func buildWordlistFindings(id, label string, discovered []wordlistProbeResult, summary wordlistProbeSummary, target, recommendation, fallbackRecommendation string) []model.Finding {
	if len(discovered) == 0 && summary.SuppressedCount == 0 {
		return nil
	}

	acceptedEvidence := make([]string, 0, len(discovered))
	seedEndpoints := make([]string, 0, len(discovered))
	classes := make([]string, 0, len(discovered))
	for _, hit := range discovered {
		acceptedEvidence = append(acceptedEvidence, fmt.Sprintf("%s [status=%d class=%s score=%d reason=%s]", hit.Path, hit.Status, hit.ResponseClass, hit.Score, hit.Reason))
		classes = append(classes, string(hit.ResponseClass))
		if hit.URL != "" && hit.Path != "/" {
			seedEndpoints = append(seedEndpoints, hit.URL)
		}
	}
	if len(acceptedEvidence) == 0 {
		acceptedEvidence = append(acceptedEvidence, "none")
	}
	profile := strings.TrimSpace(summary.Profile.Name)
	desc := fmt.Sprintf("Framework-aware wordlist %s enumeration classified responses before promotion. Accepted=%d suppressed=%d.", label, len(discovered), summary.SuppressedCount)
	if profile != "" {
		desc += " Likely framework profile: " + profile + "."
	}
	titleLabel := label + "s"
	if label == "directory" {
		titleLabel = "directories"
	}
	title := fmt.Sprintf("Discovered %d %s", len(discovered), titleLabel)
	if len(discovered) == 0 {
		title = fmt.Sprintf("Framework-aware %s enumeration suppressed fallback responses", label)
	}
	reco := recommendation
	if len(discovered) == 0 {
		reco = fallbackRecommendation
	}

	finding := model.Finding{
		ID:             id,
		Category:       "discovery",
		Severity:       model.SeverityInfo,
		Title:          title,
		Description:    desc,
		Evidence:       strings.Join(limitStrings(acceptedEvidence, 8), "; "),
		Recommendation: reco,
		EvidenceFields: map[string]string{
			"validationType":        "safe-observation",
			"frameworkProfile":      profile,
			"frameworkTechnologies": strings.Join(summary.Profile.Technologies, ","),
			"acceptedCount":         strconv.Itoa(len(discovered)),
			"suppressedCount":       strconv.Itoa(summary.SuppressedCount),
			"suppressedSamples":     strings.Join(summary.Suppressed, "; "),
			"responseClasses":       strings.Join(limitStrings(classes, 8), ","),
			"target":                target,
		},
	}
	if len(seedEndpoints) > 0 {
		finding.EvidenceFields["seedRuntimeEndpoints"] = strings.Join(uniqueStrings(seedEndpoints), ",")
	}
	return []model.Finding{finding}
}

func inferFrameworkProfile(root pathStateFingerprint) frameworkProfile {
	if root.status == 0 {
		return frameworkProfile{}
	}
	technologies := detectFrameworkTechnologies(root)
	matched := frameworkProfile{}
	bestScore := 0
	bodyText := strings.ToLower(root.bodyText)
	headerHints := []string{
		"server:" + strings.ToLower(root.headers.Get("Server")),
		"x-powered-by:" + strings.ToLower(root.headers.Get("X-Powered-By")),
		"x-generator:" + strings.ToLower(root.headers.Get("X-Generator")),
	}
	cookies := strings.ToLower(strings.Join(root.headers.Values("Set-Cookie"), ";"))
	for _, entry := range frameworkCatalog {
		score := 0
		for _, tech := range technologies {
			for _, alias := range entry.TechnologyAliases {
				if strings.Contains(strings.ToLower(tech), strings.ToLower(alias)) {
					score += 3
				}
			}
		}
		for _, hint := range entry.HeaderHints {
			for _, value := range headerHints {
				if strings.Contains(value, strings.ToLower(hint)) {
					score += 2
				}
			}
		}
		for _, hint := range entry.BodyHints {
			if strings.Contains(bodyText, strings.ToLower(hint)) {
				score += 2
			}
		}
		for _, hint := range entry.CookieHints {
			if strings.Contains(cookies, strings.ToLower(hint)) {
				score += 2
			}
		}
		if score > bestScore {
			bestScore = score
			matched = frameworkProfile{
				Name:                    entry.Key,
				Technologies:            technologies,
				Hints:                   []string{entry.Key},
				PrioritizedDirectories:  append([]string(nil), entry.PrioritizedDirs...),
				PrioritizedAPIEndpoints: append([]string(nil), entry.PrioritizedAPIs...),
			}
		}
	}
	if matched.Name == "" {
		matched.Technologies = technologies
		if root.hasSPAMarkers {
			matched.Name = "react-spa"
			matched.Hints = []string{"react-spa"}
		} else if root.hasAPIError || strings.Contains(root.contentType, "json") {
			matched.Name = "express"
			matched.Hints = []string{"express"}
		}
	}
	if len(matched.Hints) == 0 && matched.Name != "" {
		matched.Hints = []string{matched.Name}
	}
	return matched
}

func detectFrameworkTechnologies(root pathStateFingerprint) []string {
	client, err := wappalyzer.New()
	if err != nil {
		return nil
	}
	fingerprints := client.Fingerprint(root.headers, []byte(root.bodyText))
	technologies := make([]string, 0, len(fingerprints))
	for tech := range fingerprints {
		technologies = append(technologies, tech)
	}
	server := strings.TrimSpace(root.headers.Get("Server"))
	if server != "" {
		technologies = append(technologies, server)
	}
	xPoweredBy := strings.TrimSpace(root.headers.Get("X-Powered-By"))
	if xPoweredBy != "" {
		technologies = append(technologies, xPoweredBy)
	}
	xGenerator := strings.TrimSpace(root.headers.Get("X-Generator"))
	if xGenerator != "" {
		technologies = append(technologies, xGenerator)
	}
	sort.Strings(technologies)
	return uniqueStrings(technologies)
}

func classifyWordlistResponse(kind wordlistScanKind, target, path string, baseline, candidate pathStateFingerprint, profile frameworkProfile) (wordlistProbeResult, bool) {
	result := wordlistProbeResult{
		Path:   path,
		URL:    buildWordlistURL(target, path),
		Status: candidate.status,
	}
	if candidate.status == 0 {
		return result, false
	}
	if candidate.status == http.StatusNotFound || candidate.notFoundHint {
		result.ResponseClass = responseClassSoft404
		result.Reason = "404-like response"
		return result, false
	}
	if isSPAFallbackResponse(candidate, baseline, profile) {
		result.ResponseClass = responseClassSPAFallback
		result.Reason = "matches SPA shell fallback"
		return result, false
	}
	if samePathState(baseline, candidate) {
		result.ResponseClass = responseClassSoft404
		result.Reason = "matches baseline fallback"
		return result, false
	}
	if candidate.hasAPIError && looksLikeAPIPath(kind, path, profile) {
		result.ResponseClass = responseClassAPIErrorEnvelope
		result.Score = 4
		result.Reason = "JSON error envelope indicates routable endpoint"
		if candidate.status >= 200 && candidate.status < 300 {
			result.ResponseClass = responseClassTrueContent
			result.Score = 5
			result.Reason = "JSON endpoint returned distinct content"
		}
		return result, true
	}
	if isLoginRedirect(candidate.location) || candidate.status == http.StatusUnauthorized || candidate.status == http.StatusForbidden || candidate.hasLoginWall {
		result.ResponseClass = responseClassAuthWall
		result.Score = 3
		result.Reason = "auth wall indicates route exists"
		if isSensitiveWordlistPath(kind, path, profile) {
			result.Score = 5
		}
		return result, true
	}
	if isStaticAssetResponse(path, candidate) {
		result.ResponseClass = responseClassStaticAsset
		result.Score = 2
		result.Reason = "static asset handler responded"
		return result, true
	}
	if candidate.status >= 300 && candidate.status < 400 {
		result.ResponseClass = responseClassRouteRedirect
		result.Score = 3
		result.Reason = "route-specific redirect differs from baseline"
		return result, true
	}
	if candidate.status >= 200 && candidate.status < 300 {
		result.ResponseClass = responseClassTrueContent
		result.Score = 5
		result.Reason = "content differs from framework baseline"
		return result, true
	}
	result.ResponseClass = responseClassUnknown
	result.Reason = fmt.Sprintf("status=%d not promoted", candidate.status)
	return result, false
}

func isSensitiveWordlistPath(kind wordlistScanKind, path string, profile frameworkProfile) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if looksLikeAPIPath(kind, path, profile) {
		return true
	}
	return strings.Contains(lower, "admin") || strings.Contains(lower, "login") || strings.Contains(lower, "auth") || strings.Contains(lower, "dashboard") || strings.Contains(lower, "actuator") || strings.Contains(lower, "wp-")
}

func looksLikeAPIPath(kind wordlistScanKind, path string, profile frameworkProfile) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if kind == wordlistScanKindAPI {
		return true
	}
	if strings.Contains(lower, "/api") || strings.Contains(lower, "graphql") || strings.Contains(lower, "swagger") || strings.Contains(lower, "openapi") || strings.Contains(lower, "actuator") || strings.Contains(lower, "wp-json") {
		return true
	}
	for _, prioritized := range profile.PrioritizedAPIEndpoints {
		if strings.EqualFold(strings.TrimSpace(prioritized), strings.TrimSpace(path)) {
			return true
		}
	}
	return false
}

func isSPAFallbackResponse(candidate, baseline pathStateFingerprint, profile frameworkProfile) bool {
	if !candidate.hasSPAMarkers {
		return false
	}
	if samePathState(candidate, baseline) {
		return true
	}
	lowerProfile := strings.ToLower(strings.TrimSpace(profile.Name))
	if lowerProfile == "react-spa" || lowerProfile == "nextjs" || lowerProfile == "vue-spa" || lowerProfile == "nuxt" {
		return candidate.title != "" && candidate.title == baseline.title && candidate.contentType == baseline.contentType
	}
	return false
}

func isStaticAssetResponse(path string, candidate pathStateFingerprint) bool {
	lowerPath := strings.ToLower(strings.TrimSpace(path))
	if !(strings.HasSuffix(lowerPath, ".js") || strings.HasSuffix(lowerPath, ".css") || strings.HasSuffix(lowerPath, ".png") || strings.HasSuffix(lowerPath, ".jpg") || strings.HasSuffix(lowerPath, ".svg")) {
		return false
	}
	return candidate.status >= 200 && candidate.status < 300 && !strings.Contains(candidate.contentType, "html")
}

func isLoginRedirect(location string) bool {
	lower := strings.ToLower(strings.TrimSpace(location))
	return strings.Contains(lower, "/login") || strings.Contains(lower, "/signin") || strings.Contains(lower, "auth")
}

func samePathState(left, right pathStateFingerprint) bool {
	return left.status == right.status &&
		left.contentType == right.contentType &&
		left.bodySample == right.bodySample &&
		left.title == right.title &&
		left.location == right.location
}

func (ws *WordlistScanner) capturePathState(ctx context.Context, target, path string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) pathStateFingerprint {
	return capturePathStateWithClient(ctx, ws.httpClient, target, path, authProfile, scanScope, ws.timeoutPerCheck)
}

func (ws *WordlistScanner) captureURLState(ctx context.Context, rawURL string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) pathStateFingerprint {
	return captureURLStateWithClient(ctx, ws.httpClient, rawURL, authProfile, scanScope, ws.timeoutPerCheck)
}

func capturePathStateWithClient(ctx context.Context, client *http.Client, target, path string, authProfile model.ScanAuthProfile, scanScope model.ScanScope, timeoutPerCheck time.Duration) pathStateFingerprint {
	fullURL := buildWordlistURL(target, path)
	if !scope.IsURLInScope(fullURL, scanScope) {
		return pathStateFingerprint{}
	}
	return captureURLStateWithClient(ctx, client, fullURL, authProfile, scanScope, timeoutPerCheck)
}

func captureURLStateWithClient(ctx context.Context, client *http.Client, rawURL string, authProfile model.ScanAuthProfile, scanScope model.ScanScope, timeoutPerCheck time.Duration) pathStateFingerprint {
	if timeoutPerCheck <= 0 {
		timeoutPerCheck = 3 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: timeoutPerCheck}
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return pathStateFingerprint{}
	}
	// Rebuild the request URL from explicit parsed fields instead of reusing the
	// original raw string. This keeps the sink constrained to the already-parsed
	// scheme/host/path/query components and makes that safety property visible to
	// static taint analysis.
	safeURL := &url.URL{
		Scheme:   strings.ToLower(parsed.Scheme),
		User:     parsed.User,
		Host:     parsed.Host,
		Path:     parsed.Path,
		RawPath:  parsed.RawPath,
		RawQuery: parsed.RawQuery,
	}
	safeRawURL := safeURL.String()
	if !scope.IsURLInScope(safeRawURL, scanScope) {
		return pathStateFingerprint{}
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeoutPerCheck)
	defer cancel()

	req := (&http.Request{
		Method: http.MethodGet,
		URL:    safeURL,
		Header: make(http.Header),
	}).WithContext(checkCtx)
	if req == nil {
		return pathStateFingerprint{}
	}
	ApplyAuthProfile(req, authProfile)

	resp, err := client.Do(req)
	if err != nil {
		return pathStateFingerprint{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyText := string(bodyBytes)
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	title := extractHTMLTitle(bodyText)
	location := strings.TrimSpace(resp.Header.Get("Location"))
	return pathStateFingerprint{
		status:        resp.StatusCode,
		contentType:   normalizePathStateText(contentType),
		bodySample:    normalizePathStateText(bodyText),
		bodyText:      bodyText,
		title:         normalizePathStateText(title),
		location:      normalizePathStateText(location),
		accessible:    resp.StatusCode >= 200 && resp.StatusCode < 400,
		hasSPAMarkers: hasSPAMarkers(bodyText),
		hasLoginWall:  hasLoginWall(bodyText),
		hasAPIError:   hasAPIErrorEnvelope(contentType, bodyText),
		notFoundHint:  hasNotFoundMarkers(bodyText),
		headers:       resp.Header.Clone(),
	}
}

func stateMeaningfullyChanged(baseline, candidate pathStateFingerprint) bool {
	return !samePathState(baseline, candidate)
}

func normalizePathStateText(text string) string {
	text = strings.ToLower(strings.TrimSpace(text))
	text = pathStateWhitespaceRe.ReplaceAllString(text, " ")
	text = pathStateTokenRe.ReplaceAllString(text, "#")
	if len(text) > 256 {
		text = text[:256]
	}
	return text
}

func extractHTMLTitle(body string) string {
	matches := pathStateTitleRe.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return pathStateWhitespaceRe.ReplaceAllString(strings.TrimSpace(matches[1]), " ")
}

func hasSPAMarkers(body string) bool {
	lower := strings.ToLower(body)
	for _, hint := range spaResponseHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func hasLoginWall(body string) bool {
	lower := strings.ToLower(body)
	for _, hint := range loginWallHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func hasAPIErrorEnvelope(contentType, body string) bool {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return false
	}
	lower := strings.ToLower(body)
	matches := 0
	for _, hint := range apiErrorEnvelopeHints {
		if strings.Contains(lower, hint) {
			matches++
		}
	}
	return matches >= 2
}

func hasNotFoundMarkers(body string) bool {
	lower := strings.ToLower(body)
	for _, hint := range notFoundResponseHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func buildWordlistURL(target, path string) string {
	baseURL := target
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return baseURL + strings.TrimPrefix(path, "/")
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func extractHostFromURL(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
