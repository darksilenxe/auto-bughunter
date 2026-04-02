package wordlist

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ExternalLoader struct {
	cacheDir           string
	enableSecLists     bool
	enableKiterunner   bool
	timeout            time.Duration
	maxCacheAge        time.Duration
	httpClient         *http.Client
	mu                 sync.RWMutex
	cachedDirectories  []string
	cachedSubdomains   []string
	cachedAPIEndpoints []string
}

func NewExternalLoader(cacheDir string, enableSecLists, enableKiterunner bool) *ExternalLoader {
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "auto-bughunter-wordlists")
	}
	return &ExternalLoader{
		cacheDir:           cacheDir,
		enableSecLists:     enableSecLists,
		enableKiterunner:   enableKiterunner,
		timeout:            10 * time.Second,
		maxCacheAge:        24 * time.Hour,
		httpClient:         &http.Client{Timeout: 15 * time.Second},
		cachedDirectories:  make([]string, 0),
		cachedSubdomains:   make([]string, 0),
		cachedAPIEndpoints: make([]string, 0),
	}
}

func (el *ExternalLoader) LoadDirectories(ctx context.Context) []string {
	el.mu.RLock()
	if len(el.cachedDirectories) > 0 {
		defer el.mu.RUnlock()
		return append([]string{}, el.cachedDirectories...)
	}
	el.mu.RUnlock()

	result := append([]string{}, CommonDirectories...)

	if el.enableSecLists {
		seclists := el.loadSecListsDirectories(ctx)
		result = append(result, seclists...)
	}

	if el.enableKiterunner {
		kr := el.loadKiterunnerAPIPaths(ctx)
		result = append(result, filterByPathPrefix(kr, "/")...)
	}

	result = dedup(result)

	el.mu.Lock()
	el.cachedDirectories = result
	el.mu.Unlock()

	return append([]string{}, result...)
}

func (el *ExternalLoader) LoadSubdomains(ctx context.Context) []string {
	el.mu.RLock()
	if len(el.cachedSubdomains) > 0 {
		defer el.mu.RUnlock()
		return append([]string{}, el.cachedSubdomains...)
	}
	el.mu.RUnlock()

	result := append([]string{}, CommonSubdomains...)

	if el.enableSecLists {
		seclists := el.loadSecListsSubdomains(ctx)
		result = append(result, seclists...)
	}

	result = dedup(result)

	el.mu.Lock()
	el.cachedSubdomains = result
	el.mu.Unlock()

	return append([]string{}, result...)
}

func (el *ExternalLoader) LoadAPIEndpoints(ctx context.Context) []string {
	el.mu.RLock()
	if len(el.cachedAPIEndpoints) > 0 {
		defer el.mu.RUnlock()
		return append([]string{}, el.cachedAPIEndpoints...)
	}
	el.mu.RUnlock()

	result := append([]string{}, CommonAPIEndpoints...)

	if el.enableKiterunner {
		kr := el.loadKiterunnerAPIPaths(ctx)
		result = append(result, kr...)
	}

	if el.enableSecLists {
		seclists := el.loadSecListsAPIPaths(ctx)
		result = append(result, seclists...)
	}

	result = dedup(result)

	el.mu.Lock()
	el.cachedAPIEndpoints = result
	el.mu.Unlock()

	return append([]string{}, result...)
}

func (el *ExternalLoader) loadSecListsDirectories(ctx context.Context) []string {
	urls := []string{
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
	}
	return el.loadFromURLs(ctx, "seclists-dirs", urls)
}

func (el *ExternalLoader) loadSecListsSubdomains(ctx context.Context) []string {
	urls := []string{
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
	}
	return el.loadFromURLs(ctx, "seclists-subs", urls)
}

func (el *ExternalLoader) loadSecListsAPIPaths(ctx context.Context) []string {
	urls := []string{
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/common.txt",
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt",
	}
	return el.loadFromURLs(ctx, "seclists-api", urls)
}

func (el *ExternalLoader) loadKiterunnerAPIPaths(ctx context.Context) []string {
	urls := []string{
		"https://raw.githubusercontent.com/assetnote/kiterunner/main/wordlists/data/endpoints.jsonl",
		"https://raw.githubusercontent.com/assetnote/kiterunner/main/wordlists/data/swagger-wordlist.jsonl",
	}

	result := el.loadFromURLs(ctx, "kiterunner-api", urls)
	return extractJSONLPaths(result)
}

func (el *ExternalLoader) loadFromURLs(ctx context.Context, cacheKey string, urls []string) []string {
	cacheFile := filepath.Join(el.cacheDir, cacheKey+".txt")

	if isCacheValid(cacheFile, el.maxCacheAge) {
		cached, err := readCachedFile(cacheFile)
		if err == nil && len(cached) > 0 {
			return cached
		}
	}

	all := make([]string, 0)
	for _, url := range urls {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		lines := el.downloadLines(ctx, url)
		all = append(all, lines...)
	}

done:
	if len(all) > 0 {
		_ = cacheLines(cacheFile, all)
	}

	return all
}

func (el *ExternalLoader) downloadLines(ctx context.Context, url string) []string {
	result := make([]string, 0)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result
	}

	resp, err := el.httpClient.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return result
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}

	return result
}

func isCacheValid(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < maxAge
}

func readCachedFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result = append(result, line)
		}
	}
	return result, scanner.Err()
}

func cacheLines(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func extractJSONLPaths(lines []string) []string {
	result := make([]string, 0)
	for _, line := range lines {
		if strings.Contains(line, "\"endpoint\"") || strings.Contains(line, "\"path\"") {
			if idx := strings.Index(line, ":"); idx > 0 {
				if idx2 := strings.Index(line[idx:], "\""); idx2 > 0 {
					if start := idx + idx2 + 1; start < len(line) {
						if end := strings.Index(line[start:], "\""); end > 0 {
							path := line[start : start+end]
							if path != "" && (strings.HasPrefix(path, "/") || strings.HasPrefix(path, "http")) {
								result = append(result, path)
							}
						}
					}
				}
			}
		}
	}
	return result
}

func filterByPathPrefix(paths []string, prefix string) []string {
	result := make([]string, 0)
	for _, p := range paths {
		if strings.HasPrefix(p, prefix) {
			result = append(result, p)
		}
	}
	return result
}

func dedup(items []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(strings.ToLower(item))
		if item != "" {
			if _, ok := seen[item]; !ok {
				seen[item] = struct{}{}
				result = append(result, item)
			}
		}
	}
	return result
}
