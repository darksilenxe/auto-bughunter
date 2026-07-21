package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// chromedpContext returns a chromedp context. When CHROME_REMOTE_URL is set
// (e.g. http://chromium:9222 in Docker Compose), it attaches to that
// long-running headless-shell sidecar via the DevTools protocol instead of
// trying to launch a local Chromium binary inside the slim backend image.
func chromedpContext(parent context.Context) (context.Context, context.CancelFunc) {
	remote := strings.TrimSpace(os.Getenv("CHROME_REMOTE_URL"))
	if remote == "" {
		return chromedp.NewContext(parent)
	}
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(parent, remote)
	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	cancel := func() {
		cancelCtx()
		cancelAlloc()
	}
	return ctx, cancel
}
func headlessChecks(parent context.Context, target string, profile model.ScanAuthProfile, options model.ScanOptions, scanScope model.ScanScope, emit func(model.ScanEvent), liveQueue *LiveScanQueue) ([]model.Finding, []DiscoveredEndpoint, error) {
	// headlessChecks performs multi-page crawling and screenshot capture with graceful degradation.
	// Key improvements for screenshot reliability:
	//   - Individual 5-second timeout for initial screenshot (separate from page navigation)
	//   - Per-page screenshots with individual 3-second timeouts
	//   - Graceful error recovery: screenshot failures don't abort the scan
	//   - Context cancellation checks before emitting to prevent partial screenshots
	//   - Detailed logging of screenshot capture failures for debugging
	//   - Continues with findings even if screenshots fail (e.g. forms, links still collected)
	// This design ensures the browser crawl completes with maximum useful data regardless of
	// screenshot timeouts or network issues with the Chromium sidecar.
	ctx, cancel := chromedpContext(parent)
	defer cancel()

	ctx, timeoutCancel := context.WithTimeout(ctx, 35*time.Second)
	defer timeoutCancel()
	var formCount int
	var csrfLikeCount int
	var title string
	var links []string
	var currentURL string
	var screenshotBuf []byte
	u, _ := url.Parse(target)
	host := ""
	if u != nil {
		host = u.Hostname()
	}

	// Intercept XHR/Fetch network requests to discover real SPA API surface.
	var xhrMu sync.Mutex
	var xhrEndpoints []DiscoveredEndpoint
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			rt := e.Type
			if rt != network.ResourceTypeXHR && rt != network.ResourceTypeFetch {
				return
			}
			rawURL := e.Request.URL
			if rawURL == "" {
				return
			}
			if !scope.IsURLInScope(rawURL, scanScope) {
				return
			}
			method := strings.ToUpper(strings.TrimSpace(e.Request.Method))
			if method == "" {
				method = "GET"
			}
			xhrMu.Lock()
			xhrEndpoints = append(xhrEndpoints, DiscoveredEndpoint{URL: rawURL, Method: method})
			xhrMu.Unlock()
			// Immediately enqueue for live scanning so probing starts
			// concurrently with continued crawling.
			ct := ""
			if ctVal, ok := e.Request.Headers["Content-Type"]; ok {
				ct = fmt.Sprintf("%v", ctVal)
			}
			liveQueue.TryEnqueue(method, rawURL, "", ct, nil)
		}
	})

	extraHeaders := make(network.Headers)
	for key, value := range profile.Headers {
		if strings.TrimSpace(key) != "" {
			extraHeaders[key] = value
		}
	}
	if profile.UserAgent != "" {
		extraHeaders["User-Agent"] = profile.UserAgent
	}

	tasks := make(chromedp.Tasks, 0, 10)
	tasks = append(tasks,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if len(extraHeaders) > 0 {
				if err := network.SetExtraHTTPHeaders(extraHeaders).Do(ctx); err != nil {
					return err
				}
			}
			if host == "" {
				return nil
			}
			return seedBrowserCookies(ctx, target, profile.Cookies)
		}),
	)

	tasks = append(tasks,
		chromedp.Navigate(target),
		chromedp.Title(&title),
		chromedp.Location(&currentURL),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 100)`, &links),
		chromedp.Evaluate(`document.querySelectorAll('form').length`, &formCount),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('form')).filter(f => {
			const html = f.innerHTML.toLowerCase();
			return html.includes('csrf') || html.includes('_token') || html.includes('xsrf');
		}).length`, &csrfLikeCount),
	)

	// Capture initial screenshot with individual timeout and error recovery.
	// Use a shorter 5-second timeout for the screenshot to avoid blocking
	// if the page is slow to render or if network is unreliable.
	tasks = append(tasks, chromedp.ActionFunc(func(taskCtx context.Context) error {
		screenshotCtx, cancelScreenshot := context.WithTimeout(taskCtx, 5*time.Second)
		defer cancelScreenshot()
		if err := chromedp.CaptureScreenshot(&screenshotBuf).Do(screenshotCtx); err != nil {
			// Log the screenshot error but don't fail the entire scan.
			// The scan can continue without the initial screenshot.
			if emit != nil {
				emit(model.ScanEvent{
					Type:      model.ScanEventInfo,
					AgentName: "scanner",
					Message:   fmt.Sprintf("Initial screenshot capture failed: %v (will continue without it)", err),
				})
			}
			return nil // Don't propagate error - graceful degradation
		}
		return nil
	}))

	err := chromedp.Run(ctx, tasks...)
	if err != nil {
		// Log navigation/extraction errors but attempt to continue if we have some data
		if emit != nil {
			emit(model.ScanEvent{
				Type:      model.ScanEventInfo,
				AgentName: "scanner",
				Message:   fmt.Sprintf("Headless checks encountered error: %v (partial results may still be available)", err),
			})
		}
		// Continue with what we have rather than failing completely
		// This allows at least XHR endpoint discovery to complete
	}

	// Emit screenshot of initial page load if captured successfully.
	if len(screenshotBuf) > 0 {
		if emit != nil {
			// Check if context is still valid before emitting
			select {
			case <-parent.Done():
				// Parent context cancelled - skip emission
				break
			default:
				emit(model.ScanEvent{
					Type:       model.ScanEventScreenshot,
					AgentName:  "scanner",
					Message:    fmt.Sprintf("Screenshot: %s (title=%q)", currentURL, title),
					Screenshot: base64.StdEncoding.EncodeToString(screenshotBuf),
				})
			}
		}
	} else if emit != nil {
		// Log when initial screenshot is missing
		emit(model.ScanEvent{
			Type:      model.ScanEventInfo,
			AgentName: "scanner",
			Message:   fmt.Sprintf("No initial screenshot captured for %s", target),
		})
	}

	maxPages := 6
	if options.CrawlMaxPages > 0 {
		maxPages = options.CrawlMaxPages
	}
	if maxPages > 15 {
		maxPages = 15
	}
	if maxPages < 2 {
		maxPages = 2
	}

	internalLinks := collectInternalLinks(target, links, scanScope, maxPages)
	totalForms := formCount
	totalCSRFLike := csrfLikeCount
	visitedPages := 1
	loginRedirects := 0
	runtimeRefs := map[string]struct{}{}
	for _, l := range internalLinks {
		runtimeRefs[l] = struct{}{}
	}
	// Enqueue the initial page for live scanning immediately.
	liveQueue.TryEnqueue("GET", currentURL, "", "", nil)
	if isLikelyLoginURL(currentURL) {
		loginRedirects++
	}
	for _, next := range internalLinks {
		// Enqueue each crawled page for live scanning before navigating to it
		// so probing can begin as soon as the URL is known.
		liveQueue.TryEnqueue("GET", next, "", "", nil)
		var pageForms int
		var pageCsrfLike int
		var pageLinks []string
		var pageURL string
		var pageShot []byte

		// Capture screenshot with individual timeout and graceful error handling.
		// Use separate timeout for screenshot operation (3 seconds) to allow
		// the page to render even if other operations complete quickly.
		pageTasks := chromedp.Tasks{
			chromedp.Navigate(next),
			chromedp.Location(&pageURL),
			chromedp.Evaluate(`document.querySelectorAll('form').length`, &pageForms),
			chromedp.Evaluate(`Array.from(document.querySelectorAll('form')).filter(f => {
				const html = f.innerHTML.toLowerCase();
				return html.includes('csrf') || html.includes('_token') || html.includes('xsrf');
			}).length`, &pageCsrfLike),
			chromedp.Evaluate(`Array.from(document.querySelectorAll('a[href],script[src],form[action]')).map(el => el.href || el.src || el.action).filter(Boolean).slice(0,100)`, &pageLinks),
		}

		// Add screenshot capture with isolated error handling
		pageTasks = append(pageTasks, chromedp.ActionFunc(func(taskCtx context.Context) error {
			screenshotCtx, cancelScreenshot := context.WithTimeout(taskCtx, 3*time.Second)
			defer cancelScreenshot()
			if err := chromedp.CaptureScreenshot(&pageShot).Do(screenshotCtx); err != nil {
				// Log screenshot failure for this page but continue
				// Other page data (forms, links) will still be collected
				return nil // Don't fail - screenshot is optional for per-page crawl
			}
			return nil
		}))

		if err := chromedp.Run(ctx, pageTasks...); err != nil {
			// Check if context deadline exceeded to avoid spam logging
			if err == context.DeadlineExceeded {
				if emit != nil {
					emit(model.ScanEvent{
						Type:      model.ScanEventInfo,
						AgentName: "scanner",
						Message:   fmt.Sprintf("Crawl timeout on page: %s (skipping to next page)", next),
					})
				}
			}
			continue
		}

		visitedPages++
		totalForms += pageForms
		totalCSRFLike += pageCsrfLike
		if isLikelyLoginURL(pageURL) {
			loginRedirects++
		}
		for _, ref := range pageLinks {
			if strings.TrimSpace(ref) == "" {
				continue
			}
			runtimeRefs[ref] = struct{}{}
		}

		// Emit per-page screenshot only if captured successfully.
		if len(pageShot) > 0 {
			if emit != nil {
				// Check if context is still valid before emitting
				select {
				case <-parent.Done():
					// Parent context cancelled - skip emission
					break
				default:
					emit(model.ScanEvent{
						Type:       model.ScanEventScreenshot,
						AgentName:  "scanner",
						Message:    fmt.Sprintf("Screenshot: %s", pageURL),
						Screenshot: base64.StdEncoding.EncodeToString(pageShot),
					})
				}
			}
		}
	}

	findings := []model.Finding{
		{
			ID:             "browser-page-fingerprint",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          "Headless crawl completed",
			Description:    "Basic client-side reconnaissance data was collected for remediation planning.",
			Evidence:       fmt.Sprintf("title=%q links=%d forms=%d pagesVisited=%d", title, len(links), totalForms, visitedPages),
			Recommendation: "Review exposed routes and forms; reduce unnecessary attack surface.",
		},
	}

	if totalForms > 0 && totalCSRFLike == 0 {
		findings = append(findings, model.Finding{
			ID:             "browser-form-csrf-indicator",
			Category:       "csrf",
			Severity:       model.SeverityMedium,
			Title:          "Forms detected without visible CSRF indicator",
			Description:    "No obvious CSRF token markers were observed in form markup during static DOM inspection.",
			Evidence:       fmt.Sprintf("forms=%d csrfLike=%d pagesVisited=%d", totalForms, totalCSRFLike, visitedPages),
			Recommendation: "Implement verified anti-CSRF controls server-side and validate on submission.",
		})
	}

	if len(links) > 0 {
		external := 0
		for _, l := range links {
			if !strings.Contains(l, hostFromURL(target)) {
				external++
			}
		}
		if external > 0 {
			findings = append(findings, model.Finding{
				ID:             "browser-external-links",
				Category:       "surface",
				Severity:       model.SeverityLow,
				Title:          "External links found",
				Description:    "The app references external domains that may affect data flow and trust boundaries.",
				Evidence:       fmt.Sprintf("externalLinks=%d", external),
				Recommendation: "Review third-party integrations and enforce strict content/security policies.",
			})
		}
	}
	if loginRedirects >= 2 && (len(profile.Cookies) > 0 || len(profile.Headers) > 0 || profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "") {
		findings = append(findings, model.Finding{
			ID:             "browser-auth-session-instability",
			Category:       "coverage",
			Severity:       model.SeverityMedium,
			Title:          "Authenticated crawl appears to redirect to login repeatedly",
			Description:    "Multiple crawled pages resolved to login-like routes, which can indicate session expiry/token-refresh issues and reduced authenticated coverage.",
			Evidence:       fmt.Sprintf("loginRedirects=%d pagesVisited=%d", loginRedirects, visitedPages),
			Recommendation: "Refresh auth material and ensure token/cookie renewal is stable across multi-step crawling flows.",
		})
	}
	if refs := normalizeRefs(runtimeRefs, target, scanScope, 10); len(refs) > 0 {
		findings = append(findings, model.Finding{
			ID:             "browser-runtime-references",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          "Runtime crawl discovered additional endpoint references",
			Description:    "Multi-page authenticated crawl collected additional in-scope endpoint references from links/scripts/forms.",
			Evidence:       strings.Join(refs, ", "),
			Recommendation: "Expand targeted testing to these discovered runtime references.",
		})
	}

	return findings, xhrEndpoints, nil
}

func collectInternalLinks(target string, links []string, scanScope model.ScanScope, max int) []string {
	candidates := map[string]struct{}{}
	for _, l := range links {
		parsed, err := url.Parse(strings.TrimSpace(l))
		if err != nil {
			continue
		}
		ref := parsed
		if parsed.Scheme == "" || parsed.Host == "" {
			base, err := url.Parse(target)
			if err != nil {
				continue
			}
			ref = base.ResolveReference(parsed)
		}
		if ref.Scheme == "" || ref.Host == "" {
			continue
		}
		if !scope.IsURLInScope(ref.String(), scanScope) {
			continue
		}
		if strings.Contains(strings.ToLower(ref.Path), ".css") || strings.Contains(strings.ToLower(ref.Path), ".png") || strings.Contains(strings.ToLower(ref.Path), ".jpg") {
			continue
		}
		candidates[ref.String()] = struct{}{}
	}
	out := make([]string, 0, len(candidates))
	for c := range candidates {
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func isLikelyLoginURL(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(lower, "/login") || strings.Contains(lower, "/signin") || strings.Contains(lower, "auth")
}

func normalizeRefs(refs map[string]struct{}, target string, scanScope model.ScanScope, max int) []string {
	base, err := url.Parse(target)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(refs))
	for raw := range refs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		resolved := parsed
		if parsed.Scheme == "" || parsed.Host == "" {
			resolved = base.ResolveReference(parsed)
		}
		if resolved.Scheme == "" || resolved.Host == "" {
			continue
		}
		if !scope.IsURLInScope(resolved.String(), scanScope) {
			continue
		}
		out = append(out, resolved.String())
	}
	sort.Strings(out)
	if len(out) > max {
		return out[:max]
	}
	return out
}
