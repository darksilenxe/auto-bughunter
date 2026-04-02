package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/wordlist"
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

func (ws *WordlistScanner) ScanDirectories(ctx context.Context, target string, authProfile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	dirs := wordlist.GetCommonDirectoriesWithExternal(ctx)
	discovered := ws.checkMultiple(ctx, target, dirs, authProfile)

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

func (ws *WordlistScanner) ScanSubdomains(ctx context.Context, target string) []model.Finding {
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

func (ws *WordlistScanner) ScanAPIEndpoints(ctx context.Context, target string, authProfile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	endpoints := wordlist.GetCommonAPIEndpointsWithExternal(ctx)
	discovered := ws.checkMultiple(ctx, target, endpoints, authProfile)

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

func (ws *WordlistScanner) checkMultiple(ctx context.Context, target string, paths []string, authProfile model.ScanAuthProfile) []string {
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

			if ws.isAccessible(checkCtx, target, p, authProfile) {
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

func (ws *WordlistScanner) isAccessible(ctx context.Context, target string, path string, authProfile model.ScanAuthProfile) bool {
	baseURL := target
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	trimmedPath := strings.TrimPrefix(path, "/")
	fullURL := baseURL + trimmedPath

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
