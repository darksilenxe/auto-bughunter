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
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
	"auto-bughunter/backend/internal/wordlist"
)

var (
	pathStateWhitespaceRe = regexp.MustCompile(`\s+`)
	pathStateTokenRe      = regexp.MustCompile(`\b[0-9a-f]{8,}\b|\b\d{4,}\b`)
)

type WordlistScanner struct {
	httpClient      *http.Client
	maxConcurrency  int
	timeoutPerCheck time.Duration
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
	findings := make([]model.Finding, 0)

	dirs := wordlist.GetCommonDirectoriesWithExternal(ctx)
	discovered := ws.checkMultiple(ctx, target, dirs, authProfile, scanScope)
	discovered = filterStateChangingPaths(ctx, ws.httpClient, target, discovered, authProfile, scanScope, ws.maxConcurrency, ws.timeoutPerCheck)

	if len(discovered) > 0 {
		evidence := strings.Join(discovered, ", ")
		findings = append(findings, model.Finding{
			ID:             "wordlist-directories",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Discovered %d accessible directories", len(discovered)),
			Description:    "Wordlist-based directory scanning discovered accessible paths.",
			Evidence:       evidence,
			Recommendation: "Review discovered paths and restrict access to sensitive endpoints.",
		})
	}

	return findings
}

func (ws *WordlistScanner) ScanSubdomains(ctx context.Context, target string, scanScope model.ScanScope) []model.Finding {
	findings := make([]model.Finding, 0)
	host := extractHostFromURL(target)
	if host == "" {
		return findings
	}

	subs := wordlist.GetCommonSubdomainsWithExternal(ctx)
	discovered := make([]string, 0)

	for _, sub := range subs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testHost := sub + "." + host
		if !scope.IsHostInScope(testHost, scanScope) {
			continue
		}
		ips, err := net.LookupIP(testHost)
		if err == nil && len(ips) > 0 {
			discovered = append(discovered, testHost)
		}
	}

	if len(discovered) > 0 {
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
	findings := make([]model.Finding, 0)

	endpoints := wordlist.GetCommonAPIEndpointsWithExternal(ctx)
	discovered := ws.checkMultiple(ctx, target, endpoints, authProfile, scanScope)

	if len(discovered) > 0 {
		evidence := strings.Join(discovered, ", ")
		findings = append(findings, model.Finding{
			ID:             "wordlist-api-endpoints",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Discovered %d API endpoints", len(discovered)),
			Description:    "Wordlist-based API scanning discovered accessible endpoints.",
			Evidence:       evidence,
			Recommendation: "Test discovered API endpoints for authentication, authorization, and injection vulnerabilities.",
		})
	}

	return findings
}

func (ws *WordlistScanner) checkMultiple(ctx context.Context, target string, paths []string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) []string {
	discovered := make([]string, 0)
	sem := make(chan struct{}, ws.maxConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, path := range paths {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			checkCtx, cancel := context.WithTimeout(ctx, ws.timeoutPerCheck)
			defer cancel()

			if ws.isAccessible(checkCtx, target, p, authProfile, scanScope) {
				mu.Lock()
				discovered = append(discovered, p)
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()

done:
	return discovered
}

type pathStateFingerprint struct {
	status      int
	finalURL    string
	contentType string
	bodySample  string
	accessible  bool
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

	baseline, ok := capturePathState(ctx, client, target, fmt.Sprintf("/__auto-bughunter-state-probe-%d__", time.Now().UnixNano()), authProfile, scanScope, timeoutPerCheck)
	if !ok {
		out := append([]string(nil), paths...)
		sort.Strings(out)
		return out
	}

	out := make([]string, 0, len(paths))
	sem := make(chan struct{}, maxConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, path := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(candidate string) {
			defer wg.Done()
			defer func() { <-sem }()

			state, ok := capturePathState(ctx, client, target, candidate, authProfile, scanScope, timeoutPerCheck)
			if !ok || !state.accessible {
				return
			}
			if !stateMeaningfullyChanged(baseline, state) {
				return
			}
			mu.Lock()
			out = append(out, candidate)
			mu.Unlock()
		}(path)
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

func capturePathState(ctx context.Context, client *http.Client, target, path string, authProfile model.ScanAuthProfile, scanScope model.ScanScope, timeoutPerCheck time.Duration) (pathStateFingerprint, bool) {
	fullURL := buildWordlistURL(target, path)
	if !scope.IsURLInScope(fullURL, scanScope) {
		return pathStateFingerprint{}, false
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeoutPerCheck)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, fullURL, nil)
	if err != nil {
		return pathStateFingerprint{}, false
	}
	ApplyAuthProfile(req, authProfile)

	resp, err := client.Do(req)
	if err != nil {
		return pathStateFingerprint{}, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return pathStateFingerprint{
		status:      resp.StatusCode,
		finalURL:    normalizePathStateText(resp.Request.URL.String()),
		contentType: normalizePathStateText(resp.Header.Get("Content-Type")),
		bodySample:  normalizePathStateText(string(bodyBytes)),
		accessible:  resp.StatusCode >= 200 && resp.StatusCode < 400,
	}, true
}

func stateMeaningfullyChanged(baseline, candidate pathStateFingerprint) bool {
	return baseline.status != candidate.status ||
		baseline.finalURL != candidate.finalURL ||
		baseline.contentType != candidate.contentType ||
		baseline.bodySample != candidate.bodySample
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

func buildWordlistURL(target, path string) string {
	baseURL := target
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return baseURL + strings.TrimPrefix(path, "/")
}

func (ws *WordlistScanner) isAccessible(ctx context.Context, target string, path string, authProfile model.ScanAuthProfile, scanScope model.ScanScope) bool {
	fullURL := buildWordlistURL(target, path)
	if !scope.IsURLInScope(fullURL, scanScope) {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, fullURL, nil)
	if err != nil {
		return false
	}
	ApplyAuthProfile(req, authProfile)

	resp, err := ws.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func extractHostFromURL(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
