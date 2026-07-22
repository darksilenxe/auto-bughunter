package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// browserValidationTimeout is the total deadline for a single browser
// validation session (before + after snapshots).
const browserValidationTimeout = 30 * time.Second

// browserValidationSettleMs is the wait in milliseconds after applying the
// probe payload so JavaScript frameworks have time to re-render.
const browserValidationSettleMs = 1500

// browserSnapshotTimeout is the per-screenshot timeout used inside a
// validation session. Shorter than the overall timeout so one slow render
// does not consume the entire budget.
const browserSnapshotTimeout = 5 * time.Second

// ValidateFindingWithBrowser opens a headless browser, captures a "before"
// DOM snapshot of the finding's affected URL with authentication applied,
// then replays the finding's PoC (or navigates to the probe URL derived from
// AffectedURL + AffectedParameter + payload), and captures an "after"
// snapshot. The two snapshots are diffed to produce a StateChangeDelta.
//
// Before and after screenshots are emitted as ScanEventScreenshot events for
// human inspection.  The function is safe to call from a probe closure passed
// to SubmitVerifiedFinding as BrowserValidationFunc; it never panics on
// browser unavailability — it returns a nil result instead.
func ValidateFindingWithBrowser(
	ctx context.Context,
	finding model.Finding,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) (*model.BrowserValidationResult, error) {
	targetURL := strings.TrimSpace(finding.AffectedURL)
	if targetURL == "" {
		return nil, nil
	}

	// Derive the "after" URL: if the finding has an affected parameter and a
	// PoC that looks like a query value, append the parameter. Otherwise use
	// the PoC string directly when it is a full URL, falling back to the
	// AffectedURL unchanged.
	afterURL := deriveProbeURL(finding)

	browserCtx, cancelBrowser := chromedpContext(ctx)
	defer cancelBrowser()

	browserCtx, cancelTimeout := context.WithTimeout(browserCtx, browserValidationTimeout)
	defer cancelTimeout()

	// Inject authentication into the browser session in the same way that
	// headlessChecks does: set extra HTTP headers and seed cookies.
	extraHeaders := make(network.Headers)
	for k, v := range auth.Headers {
		if strings.TrimSpace(k) != "" {
			extraHeaders[k] = v
		}
	}
	if auth.UserAgent != "" {
		extraHeaders["User-Agent"] = auth.UserAgent
	}

	setupTasks := chromedp.Tasks{
		network.Enable(),
		chromedp.ActionFunc(func(setupCtx context.Context) error {
			if len(extraHeaders) > 0 {
				if err := network.SetExtraHTTPHeaders(extraHeaders).Do(setupCtx); err != nil {
					return err
				}
			}
			return seedBrowserCookies(setupCtx, targetURL, auth.Cookies)
		}),
	}
	if err := chromedp.Run(browserCtx, setupTasks...); err != nil {
		// Browser unavailable — degrade gracefully.
		return nil, nil
	}

	// Capture the "before" snapshot.
	before, err := takeDOMPageSnapshot(browserCtx, targetURL, emit, "before")
	if err != nil {
		return nil, nil
	}

	// Navigate to the probe URL and wait for JS to settle.
	settleTasks := chromedp.Tasks{
		chromedp.Navigate(afterURL),
		chromedp.Sleep(browserValidationSettleMs * time.Millisecond),
	}
	if err := chromedp.Run(browserCtx, settleTasks...); err != nil {
		// Probe navigation failed; return partial result with empty delta.
		return &model.BrowserValidationResult{Before: before}, nil
	}

	// Capture the "after" snapshot.
	after, err := takeDOMPageSnapshot(browserCtx, afterURL, emit, "after")
	if err != nil {
		return &model.BrowserValidationResult{Before: before}, nil
	}

	delta := computeStateChangeDelta(before, after)

	return &model.BrowserValidationResult{
		Before: before,
		After:  after,
		Delta:  delta,
	}, nil
}

// takeDOMPageSnapshot collects a full DOM fingerprint and screenshot of the
// currently loaded page in browserCtx. It emits a ScanEventScreenshot event
// (labelled with prefix) when a screenshot is captured. Snapshot collection
// degrades gracefully: individual failures do not abort the snapshot.
func takeDOMPageSnapshot(
	browserCtx context.Context,
	pageURL string,
	emit func(model.ScanEvent),
	prefix string,
) (model.DOMPageSnapshot, error) {
	snap := model.DOMPageSnapshot{
		URL:            pageURL,
		JSBundleHashes: map[string]string{},
	}

	var outerHTML, visibleText, title, currentURL string
	var formCount, inputCount int
	var scriptSrcs []string
	var screenshotBuf []byte

	collectTasks := chromedp.Tasks{
		chromedp.Location(&currentURL),
		chromedp.Title(&title),
		chromedp.OuterHTML("html", &outerHTML, chromedp.ByQuery),
		chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &visibleText),
		chromedp.Evaluate(`document.querySelectorAll('form').length`, &formCount),
		chromedp.Evaluate(`document.querySelectorAll('input').length`, &inputCount),
		chromedp.Evaluate(
			`Array.from(document.querySelectorAll('script[src]')).map(s => s.src).filter(Boolean)`,
			&scriptSrcs,
		),
	}

	// Screenshot with its own short timeout so a slow render does not stall.
	collectTasks = append(collectTasks, chromedp.ActionFunc(func(taskCtx context.Context) error {
		ssCtx, cancelSS := context.WithTimeout(taskCtx, browserSnapshotTimeout)
		defer cancelSS()
		_ = chromedp.CaptureScreenshot(&screenshotBuf).Do(ssCtx)
		return nil
	}))

	if err := chromedp.Run(browserCtx, collectTasks...); err != nil {
		return snap, err
	}

	if currentURL != "" {
		snap.URL = currentURL
	}
	snap.Title = title
	snap.FormCount = formCount
	snap.InputCount = inputCount
	snap.OuterHTMLHash = sha256Hex(outerHTML)
	snap.VisibleTextHash = sha256Hex(visibleText)

	// Hash the text content of each inline/external script. For external
	// scripts we use the URL as a stable key and hash its src URL value
	// (the browser evaluation already fetched the script; we do not
	// re-fetch here to stay inside the session budget).
	for _, src := range scriptSrcs {
		if src == "" {
			continue
		}
		snap.JSBundleHashes[src] = sha256Hex(src)
	}

	if len(screenshotBuf) > 0 {
		snap.ScreenshotB64 = base64.StdEncoding.EncodeToString(screenshotBuf)
		if emit != nil {
			emit(model.ScanEvent{
				Type:       model.ScanEventScreenshot,
				AgentName:  "browser-validation",
				Message:    fmt.Sprintf("%s: %s (title=%q)", prefix, snap.URL, snap.Title),
				Screenshot: snap.ScreenshotB64,
			})
		}
	}

	return snap, nil
}

// computeStateChangeDelta compares two DOMPageSnapshots and returns a
// StateChangeDelta describing what (if anything) changed between them.
func computeStateChangeDelta(before, after model.DOMPageSnapshot) model.StateChangeDelta {
	delta := model.StateChangeDelta{
		FormCountDelta: after.FormCount - before.FormCount,
	}

	if before.OuterHTMLHash != "" && after.OuterHTMLHash != "" {
		delta.HTMLChanged = before.OuterHTMLHash != after.OuterHTMLHash
	}
	if before.VisibleTextHash != "" && after.VisibleTextHash != "" {
		delta.TextChanged = before.VisibleTextHash != after.VisibleTextHash
	}

	// Detect JS bundle changes: any bundle that is new or whose URL changed.
	for src := range after.JSBundleHashes {
		if _, ok := before.JSBundleHashes[src]; !ok {
			delta.JSBundleChanged = true
			delta.NewJSBundles = append(delta.NewJSBundles, src)
		}
	}
	// Also flag when existing bundles changed hash (not possible with
	// URL-keyed hashes, but kept for forward compatibility).
	for src, afterHash := range after.JSBundleHashes {
		if beforeHash, ok := before.JSBundleHashes[src]; ok && beforeHash != afterHash {
			delta.JSBundleChanged = true
		}
	}

	delta.IsStaticResponse = !delta.HTMLChanged && !delta.TextChanged && !delta.JSBundleChanged
	return delta
}

// attachBrowserValidationArtifacts appends before/after screenshots and a
// state-delta summary as ProofArtifacts on the finding. It also records the
// key delta flags in EvidenceFields for proof-policy evaluation.
func attachBrowserValidationArtifacts(
	f *model.Finding,
	before, after model.DOMPageSnapshot,
	delta model.StateChangeDelta,
) {
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["browserValidation.htmlChanged"] = fmt.Sprintf("%v", delta.HTMLChanged)
	f.EvidenceFields["browserValidation.textChanged"] = fmt.Sprintf("%v", delta.TextChanged)
	f.EvidenceFields["browserValidation.jsBundleChanged"] = fmt.Sprintf("%v", delta.JSBundleChanged)
	f.EvidenceFields["browserValidation.static"] = fmt.Sprintf("%v", delta.IsStaticResponse)

	if before.ScreenshotB64 != "" {
		f.ProofArtifacts = append(f.ProofArtifacts, model.ProofArtifact{
			Type:        "screenshot",
			Label:       "Browser validation \u2013 before",
			Description: fmt.Sprintf("Page state before probe payload was applied (%s)", before.URL),
			Value:       before.ScreenshotB64,
		})
	}
	if after.ScreenshotB64 != "" {
		f.ProofArtifacts = append(f.ProofArtifacts, model.ProofArtifact{
			Type:        "screenshot",
			Label:       "Browser validation \u2013 after",
			Description: fmt.Sprintf("Page state after probe payload was applied (%s)", after.URL),
			Value:       after.ScreenshotB64,
		})
	}

	// Attach a compact JSON summary of the delta for machine-readable
	// consumption by the proof-policy engine and the UI.
	deltaJSON, _ := json.Marshal(delta)
	f.ProofArtifacts = append(f.ProofArtifacts, model.ProofArtifact{
		Type:        "state-delta",
		Label:       "DOM state change",
		Description: "Computed difference between before/after DOM snapshots captured during browser validation.",
		Value:       string(deltaJSON),
	})
}

// deriveProbeURL constructs the URL that will be navigated to during the
// "after" phase of browser validation. Priority order:
//  1. If PoC is a valid absolute URL, use it directly.
//  2. If AffectedParameter is set, append it to AffectedURL with the PoC as
//     the parameter value.
//  3. Fall back to AffectedURL unchanged (the browser is already on it).
func deriveProbeURL(f model.Finding) string {
	poc := strings.TrimSpace(f.PoC)
	affectedURL := strings.TrimSpace(f.AffectedURL)

	// Case 1: PoC is an absolute URL.
	if poc != "" {
		if u, err := url.Parse(poc); err == nil && u.Scheme != "" && u.Host != "" {
			return poc
		}
	}

	// Case 2: Inject PoC value into the affected parameter.
	param := strings.TrimSpace(f.AffectedParameter)
	if param != "" && affectedURL != "" && poc != "" {
		if u, err := url.Parse(affectedURL); err == nil {
			q := u.Query()
			q.Set(param, poc)
			u.RawQuery = q.Encode()
			return u.String()
		}
	}

	// Case 3: Append PoC as a URL fragment (e.g. DOM XSS hash-based probes).
	if poc != "" && affectedURL != "" && !strings.Contains(poc, " ") {
		if !strings.HasPrefix(poc, "#") {
			return affectedURL + "#" + poc
		}
		return affectedURL + poc
	}

	return affectedURL
}

// sha256Hex returns the lowercase hex-encoded SHA-256 digest of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}
