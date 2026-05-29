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

// Profile selects how much external wordlist coverage to load. The "small"
// profile keeps scans fast with the most common lists; "full" opts into the
// large/comprehensive SecLists and PayloadsAllTheThings sets.
const (
	ProfileSmall = "small"
	ProfileFull  = "full"
)

// Raw source bases. SecLists relative paths are resolved against the vendored
// checkout first (when present) and otherwise fetched from GitHub.
const (
	secListsRawBase = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
	pattRawBase     = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/"
)

// NormalizeProfile coerces an arbitrary string into a supported profile,
// defaulting to ProfileSmall.
func NormalizeProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case ProfileFull, "large", "comprehensive", "all":
		return ProfileFull
	default:
		return ProfileSmall
	}
}

type ExternalLoader struct {
	cacheDir         string
	enableSecLists   bool
	enableKiterunner bool
	profile          string
	// secListsDir is an optional path to a vendored/mounted SecLists checkout.
	// When a requested list exists locally it is read from disk instead of
	// being fetched over the network.
	secListsDir string
	timeout     time.Duration
	maxCacheAge time.Duration
	httpClient  *http.Client

	mu                 sync.RWMutex
	cachedDirectories  []string
	cachedSubdomains   []string
	cachedAPIEndpoints []string
	cachedFuzzPayloads []string
}

// LoaderConfig configures an ExternalLoader.
type LoaderConfig struct {
	CacheDir         string
	EnableSecLists   bool
	EnableKiterunner bool
	// Profile is "small" (default) or "full".
	Profile string
	// SecListsDir is an optional vendored/mounted SecLists checkout root.
	SecListsDir string
}

// NewExternalLoaderWithConfig builds a loader from an explicit config.
func NewExternalLoaderWithConfig(cfg LoaderConfig) *ExternalLoader {
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "auto-bughunter-wordlists")
	}
	secListsDir := strings.TrimSpace(cfg.SecListsDir)
	if secListsDir == "" {
		// Probe a couple of conventional locations for a vendored checkout.
		for _, candidate := range []string{"/usr/share/seclists", "/wordlists/seclists"} {
			if dirExists(candidate) {
				secListsDir = candidate
				break
			}
		}
	}
	return &ExternalLoader{
		cacheDir:           cacheDir,
		enableSecLists:     cfg.EnableSecLists,
		enableKiterunner:   cfg.EnableKiterunner,
		profile:            NormalizeProfile(cfg.Profile),
		secListsDir:        secListsDir,
		timeout:            10 * time.Second,
		maxCacheAge:        24 * time.Hour,
		httpClient:         &http.Client{Timeout: 15 * time.Second},
		cachedDirectories:  make([]string, 0),
		cachedSubdomains:   make([]string, 0),
		cachedAPIEndpoints: make([]string, 0),
		cachedFuzzPayloads: make([]string, 0),
	}
}

// NewExternalLoader preserves the original constructor signature for callers
// that only toggle the SecLists/Kiterunner integrations. It uses the default
// (small) profile and auto-detects a vendored SecLists checkout.
func NewExternalLoader(cacheDir string, enableSecLists, enableKiterunner bool) *ExternalLoader {
	return NewExternalLoaderWithConfig(LoaderConfig{
		CacheDir:         cacheDir,
		EnableSecLists:   enableSecLists,
		EnableKiterunner: enableKiterunner,
		Profile:          ProfileSmall,
	})
}

// SecListsDir returns the resolved vendored SecLists checkout path (empty when
// none was configured or detected).
func (el *ExternalLoader) SecListsDir() string {
	return el.secListsDir
}

// Profile returns the active loading profile.
func (el *ExternalLoader) Profile() string {
	return el.profile
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

// LoadFuzzingPayloads returns active-fuzzing payload strings sourced from
// SecLists Fuzzing/ and PayloadsAllTheThings. These are NOT path/endpoint
// candidates — they are injection payloads used to seed active probes. Returns
// the built-in CommonFuzzPayloads when external loading is disabled.
func (el *ExternalLoader) LoadFuzzingPayloads(ctx context.Context) []string {
	el.mu.RLock()
	if len(el.cachedFuzzPayloads) > 0 {
		defer el.mu.RUnlock()
		return append([]string{}, el.cachedFuzzPayloads...)
	}
	el.mu.RUnlock()

	result := append([]string{}, CommonFuzzPayloads...)

	if el.enableSecLists {
		result = append(result, el.loadFuzzingPayloads(ctx)...)
	}

	// PayloadsAllTheThings payload index (MIT-licensed). Loaded whenever
	// SecLists fuzzing is enabled because the curated payload files are small
	// and high-signal.
	if el.enableSecLists {
		result = append(result, el.loadPayloadsAllTheThings(ctx)...)
	}

	result = dedupPreserveCase(result)

	el.mu.Lock()
	el.cachedFuzzPayloads = result
	el.mu.Unlock()

	return append([]string{}, result...)
}

func (el *ExternalLoader) loadSecListsDirectories(ctx context.Context) []string {
	rels := []string{
		"Discovery/Web-Content/common.txt",
		"Discovery/Web-Content/big.txt",
	}
	if el.profile == ProfileFull {
		rels = append(rels,
			"Discovery/Web-Content/directory-list-2.3-medium.txt",
			"Discovery/Web-Content/raft-large-directories.txt",
			"Discovery/Web-Content/raft-large-files.txt",
			"Discovery/Web-Content/dirsearch.txt",
		)
	}
	return el.loadSecListsRel(ctx, "seclists-dirs", rels)
}

func (el *ExternalLoader) loadSecListsSubdomains(ctx context.Context) []string {
	rels := []string{
		"Discovery/DNS/subdomains-top1million-5000.txt",
		"Discovery/DNS/subdomains-top1million-110000.txt",
	}
	if el.profile == ProfileFull {
		rels = append(rels,
			"Discovery/DNS/bitquark-subdomains-top100000.txt",
		)
	}
	return el.loadSecListsRel(ctx, "seclists-subs", rels)
}

func (el *ExternalLoader) loadSecListsAPIPaths(ctx context.Context) []string {
	rels := []string{
		"Discovery/Web-Content/api/common.txt",
		"Discovery/Web-Content/api/objects.txt",
	}
	if el.profile == ProfileFull {
		rels = append(rels,
			"Discovery/Web-Content/api/api-endpoints.txt",
			"Discovery/Web-Content/api/actions.txt",
			"Discovery/Web-Content/graphql.txt",
		)
	}
	return el.loadSecListsRel(ctx, "seclists-api", rels)
}

func (el *ExternalLoader) loadFuzzingPayloads(ctx context.Context) []string {
	rels := []string{
		"Fuzzing/special-chars.txt",
		"Fuzzing/SQLi/Generic-SQLi.txt",
		"Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
		"Fuzzing/LFI/LFI-Jhaddix.txt",
	}
	if el.profile == ProfileFull {
		rels = append(rels,
			"Fuzzing/XSS/XSS-Jhaddix.txt",
			"Fuzzing/SQLi/quick-SQLi.txt",
			"Fuzzing/command-injection-commix.txt",
			"Fuzzing/template-engines-expression.txt",
		)
	}
	return el.loadSecListsRel(ctx, "seclists-fuzz", rels)
}

func (el *ExternalLoader) loadPayloadsAllTheThings(ctx context.Context) []string {
	// Curated, high-signal payload files from PayloadsAllTheThings (MIT).
	rels := []string{
		"XSS%20Injection/Intruders/XSS_Polyglots.txt",
		"SQL%20Injection/Intruder/Generic_SQLI.txt",
		"Directory%20Traversal/Intruder/directory_traversal.txt",
		"Command%20Injection/Intruder/command_exec.txt",
	}
	if el.profile == ProfileFull {
		rels = append(rels,
			"SQL%20Injection/Intruder/Auth_Bypass.txt",
			"Server%20Side%20Template%20Injection/Intruder/ssti.txt",
		)
	}
	urls := make([]string, 0, len(rels))
	for _, rel := range rels {
		urls = append(urls, pattRawBase+rel)
	}
	return el.loadFromURLsPreserveCase(ctx, "patt-payloads", urls)
}

func (el *ExternalLoader) loadKiterunnerAPIPaths(ctx context.Context) []string {
	urls := []string{
		"https://raw.githubusercontent.com/assetnote/kiterunner/main/wordlists/data/endpoints.jsonl",
		"https://raw.githubusercontent.com/assetnote/kiterunner/main/wordlists/data/swagger-wordlist.jsonl",
	}

	result := el.loadFromURLs(ctx, "kiterunner-api", urls)
	return extractJSONLPaths(result)
}

// loadSecListsRel resolves a set of SecLists-relative paths, reading each from
// the vendored checkout when available and falling back to the GitHub raw URL
// otherwise. Results are cached on disk under cacheKey.
func (el *ExternalLoader) loadSecListsRel(ctx context.Context, cacheKey string, rels []string) []string {
	all := make([]string, 0)
	remoteURLs := make([]string, 0, len(rels))
	for _, rel := range rels {
		if local := el.readVendoredSecList(rel); local != nil {
			all = append(all, local...)
			continue
		}
		remoteURLs = append(remoteURLs, secListsRawBase+rel)
	}
	if len(remoteURLs) > 0 {
		all = append(all, el.loadFromURLs(ctx, cacheKey, remoteURLs)...)
	}
	return all
}

// readVendoredSecList reads a SecLists-relative file from the vendored checkout
// if it exists. rel is always a hard-coded constant (never user input), so the
// joined path cannot escape the checkout root. Returns nil when unavailable.
func (el *ExternalLoader) readVendoredSecList(rel string) []string {
	if el.secListsDir == "" {
		return nil
	}
	p := filepath.Join(el.secListsDir, filepath.FromSlash(rel))
	lines, err := readCachedFile(p)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
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

		lines := el.downloadLines(ctx, url, true)
		all = append(all, lines...)
	}

done:
	if len(all) > 0 {
		_ = cacheLines(cacheFile, all)
	}

	return all
}

// loadFromURLsPreserveCase is like loadFromURLs but does not lowercase results,
// which matters for injection payloads (filter-bypass variants rely on casing).
func (el *ExternalLoader) loadFromURLsPreserveCase(ctx context.Context, cacheKey string, urls []string) []string {
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

		lines := el.downloadLines(ctx, url, false)
		all = append(all, lines...)
	}

done:
	if len(all) > 0 {
		_ = cacheLines(cacheFile, all)
	}

	return all
}

func (el *ExternalLoader) downloadLines(ctx context.Context, url string, _ bool) []string {
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
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func readCachedFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make([]string, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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

// dedupPreserveCase deduplicates while preserving original casing, which matters
// for injection payloads (e.g. <sCrIpT> filter-bypass variants).
func dedupPreserveCase(items []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
