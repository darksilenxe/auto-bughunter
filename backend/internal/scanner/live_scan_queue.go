package scanner

// live_scan_queue.go — Burp Suite-style "Live Audit from Proxy" for the
// headless-crawl and UI-simulation phases.
//
// Every unique endpoint discovered during crawling is immediately enqueued for
// active scanning so probing and crawling run concurrently — matching Burp
// Suite Pro's "Live Audit from Proxy" behaviour — rather than waiting until
// the crawl phase finishes.
//
// Architecture:
//   - LiveScanQueue wraps a bounded channel with a structural-dedup map so
//     that endpoints with the same URL shape (same path template + param names)
//     are only tested once.
//   - startLiveScanWorkers spins up a pool of goroutines that drain the queue
//     and run a targeted active-probe suite against each unique endpoint.
//   - runLiveScanItem calls the existing probe methods with a per-item RunInput
//     so all safety, scope, and session plumbing is reused without duplication.
//   - ExtractInsertionPoints returns the injectable locations (URL params, JSON
//     body fields, form fields, key headers) for a single queued item.

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// liveScanMaxItems is the maximum number of items the queue will hold. When the
// queue is full additional enqueues are silently dropped. This bounds memory and
// probe traffic for wide-coverage targets.
const liveScanMaxItems = 30

// liveScanItemTimeout is the per-item context deadline. Probes that take
// longer than this are cancelled so a single slow endpoint cannot block the
// queue.
const liveScanItemTimeout = 30 * time.Second

// liveScanDefaultConcurrency is the number of worker goroutines used when the
// operator has not configured a specific concurrency.
const liveScanDefaultConcurrency = 3

// InsertionPointKind classifies the location of an injectable value within an
// HTTP request. Mirrors the insertion-point taxonomy used by Burp Suite.
type InsertionPointKind string

const (
	// InsertionPointQueryParam is a URL query-string parameter.
	InsertionPointQueryParam InsertionPointKind = "query_param"
	// InsertionPointBodyField is a top-level field in a JSON or form body.
	InsertionPointBodyField InsertionPointKind = "body_field"
	// InsertionPointHeader is a request header whose value is considered
	// injectable (e.g. Referer, X-Forwarded-For, Origin).
	InsertionPointHeader InsertionPointKind = "header"
)

// InsertionPoint represents one injectable location in a queued HTTP request.
type InsertionPoint struct {
	Kind  InsertionPointKind
	Name  string // parameter / field / header name
	Value string // current (baseline) value, empty when not present
}

// QueuedScanItem is the unit of work consumed by live-scan workers. It carries
// the full HTTP context of one endpoint discovered during crawling or UI
// simulation.
type QueuedScanItem struct {
	// Fingerprint is the structural deduplication key computed by
	// structuralFingerprint. Items with the same fingerprint are not
	// enqueued twice.
	Fingerprint string

	// URL is the absolute endpoint URL (scheme://host/path?query).
	URL string
	// Method is the HTTP verb (GET, POST, etc.).
	Method string
	// Headers holds the request headers captured by the XHR listener.
	Headers map[string]string
	// Body is the request body (JSON/form-encoded), may be empty.
	Body string
	// ContentType is the value of the request Content-Type header, used to
	// choose the correct body parser in ExtractInsertionPoints.
	ContentType string

	// InsertionPoints are the injectable locations extracted from URL/body/headers.
	InsertionPoints []InsertionPoint
}

// LiveScanQueue is a bounded, thread-safe, deduplicated work queue for live
// scanning. It is nil-safe: all methods on a nil receiver are no-ops.
type LiveScanQueue struct {
	mu      sync.Mutex
	seen    map[string]struct{} // keyed by structural fingerprint
	items   chan QueuedScanItem
	closed  bool
	dropped int // count of items dropped because the queue was full or already seen
}

// NewLiveScanQueue constructs an empty LiveScanQueue with the given capacity.
func NewLiveScanQueue(capacity int) *LiveScanQueue {
	if capacity <= 0 {
		capacity = liveScanMaxItems
	}
	return &LiveScanQueue{
		seen:  make(map[string]struct{}),
		items: make(chan QueuedScanItem, capacity),
	}
}

// TryEnqueue computes the structural fingerprint for rawURL+method and
// enqueues the item if it has not been seen before and the queue is not full.
// Returns true when the item was accepted. Safe to call on a nil receiver
// (returns false).
func (q *LiveScanQueue) TryEnqueue(method, rawURL, body, contentType string, headers map[string]string) bool {
	if q == nil {
		return false
	}
	fp := structuralFingerprint(method, rawURL)
	if fp == "" {
		return false
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return false
	}
	if _, exists := q.seen[fp]; exists {
		return false
	}

	item := QueuedScanItem{
		Fingerprint:     fp,
		URL:             rawURL,
		Method:          strings.ToUpper(strings.TrimSpace(method)),
		Headers:         headers,
		Body:            body,
		ContentType:     contentType,
		InsertionPoints: ExtractInsertionPoints(method, rawURL, body, contentType, headers),
	}

	select {
	case q.items <- item:
		q.seen[fp] = struct{}{}
		return true
	default:
		// Channel full — drop.
		q.dropped++
		return false
	}
}

// Close signals that no more items will be enqueued. Workers draining the
// channel will exit after processing all buffered items. Idempotent.
func (q *LiveScanQueue) Close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.items)
	}
}

// Len returns the number of items currently buffered in the queue.
func (q *LiveScanQueue) Len() int {
	if q == nil {
		return 0
	}
	return len(q.items)
}

// Dropped returns the number of items that were rejected because the queue
// was at capacity.
func (q *LiveScanQueue) Dropped() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// reUUIDSegment matches UUID v4 path segments.
var reUUIDSegment = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// reNumericSegment matches purely numeric path segments (resource IDs).
var reNumericSegment = regexp.MustCompile(`^\d+$`)

// reHexSegment matches long hex strings (object IDs, hashes).
var reHexSegment = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)

// normalizePathSegment replaces dynamic path segments with typed placeholders
// so that /users/123 and /users/456 share the same structural fingerprint.
func normalizePathSegment(seg string) string {
	switch {
	case reUUIDSegment.MatchString(seg):
		return "{uuid}"
	case reNumericSegment.MatchString(seg):
		return "{id}"
	case reHexSegment.MatchString(seg):
		return "{hex}"
	default:
		return seg
	}
}

// structuralFingerprint returns a stable string key for a method + URL
// combination that treats dynamically varying path segments and ignores query
// parameter values (keeping only parameter names). The result is used to
// deduplicate equivalent endpoints discovered under different resource IDs.
func structuralFingerprint(method, rawURL string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}

	// Normalize path segments.
	segments := strings.Split(u.Path, "/")
	for i, seg := range segments {
		segments[i] = normalizePathSegment(seg)
	}
	normalizedPath := strings.Join(segments, "/")

	// Collect and sort query parameter names (not values).
	params := make([]string, 0)
	for name := range u.Query() {
		params = append(params, strings.ToLower(name))
	}
	sort.Strings(params)

	key := fmt.Sprintf("%s:%s://%s%s?[%s]",
		method,
		u.Scheme,
		strings.ToLower(u.Host),
		normalizedPath,
		strings.Join(params, ","),
	)
	h := md5.Sum([]byte(key))
	return fmt.Sprintf("%x", h)
}

// injectableHeaders is the list of headers considered injection-point
// candidates for live scanning. These are chosen because server-side
// components frequently trust them for URL construction, IP logging, or
// routing decisions.
var injectableHeaders = []string{
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"Origin",
	"X-Original-URL",
}

// ExtractInsertionPoints returns all injectable locations in the HTTP request
// described by (method, rawURL, body, contentType, headers). The returned
// slice is ordered: URL query params first, then body fields, then headers.
func ExtractInsertionPoints(method, rawURL, body, contentType string, headers map[string]string) []InsertionPoint {
	var points []InsertionPoint

	// 1. URL query parameters.
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil {
		for name, vals := range u.Query() {
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			points = append(points, InsertionPoint{
				Kind:  InsertionPointQueryParam,
				Name:  name,
				Value: val,
			})
		}
	}

	// 2. Body fields.
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(ct, "application/json") && body != "" {
		var m map[string]interface{}
		if json.Unmarshal([]byte(body), &m) == nil {
			for name, val := range m {
				points = append(points, InsertionPoint{
					Kind:  InsertionPointBodyField,
					Name:  name,
					Value: fmt.Sprintf("%v", val),
				})
			}
		}
	} else if (strings.Contains(ct, "application/x-www-form-urlencoded") ||
		strings.Contains(ct, "multipart/form-data")) && body != "" {
		vals, ferr := url.ParseQuery(body)
		if ferr == nil {
			for name, vs := range vals {
				val := ""
				if len(vs) > 0 {
					val = vs[0]
				}
				points = append(points, InsertionPoint{
					Kind:  InsertionPointBodyField,
					Name:  name,
					Value: val,
				})
			}
		}
	}

	// 3. Selected injectable headers.
	for _, h := range injectableHeaders {
		val := ""
		if headers != nil {
			val = headers[h]
		}
		points = append(points, InsertionPoint{
			Kind:  InsertionPointHeader,
			Name:  h,
			Value: val,
		})
	}

	return points
}

// startLiveScanWorkers starts a pool of concurrency goroutines that drain
// queue and run active probes against each dequeued item. It returns a channel
// that receives the aggregated findings from all workers once the queue has
// been closed and drained.
func (s *Service) startLiveScanWorkers(
	ctx context.Context,
	input RunInput,
	queue *LiveScanQueue,
	concurrency int,
) <-chan []model.Finding {
	done := make(chan []model.Finding, 1)

	go func() {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var allFindings []model.Finding

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for item := range queue.items {
					itemFindings := s.runLiveScanItem(ctx, input, item)
					if len(itemFindings) == 0 {
						continue
					}
					mu.Lock()
					allFindings = append(allFindings, itemFindings...)
					mu.Unlock()
					// Emit each finding immediately so results appear in
					// the live scan event stream rather than waiting for
					// the full scan to finish.
					for _, f := range itemFindings {
						f := f // copy for closure safety
						if input.Emit != nil {
							input.Emit(model.ScanEvent{
								Type:         model.ScanEventFinding,
								AgentName:    "live-scanner",
								Message:      fmt.Sprintf("[live-scan] %s: %s", f.Severity, f.Title),
								FindingTitle: f.Title,
								Severity:     string(f.Severity),
							})
						}
					}
				}
			}()
		}

		wg.Wait()
		done <- allFindings
	}()

	return done
}

// runLiveScanItem runs a targeted active-probe suite against a single queued
// endpoint. It reuses the existing probe methods by constructing a per-item
// RunInput with a short per-item context deadline so slow endpoints cannot
// block the queue.
//
// The probe subset mirrors Burp Suite's live-scan check list:
//   - shallow: XSS reflection, open redirect
//   - standard (default): + error-based SQLi, SSTI arithmetic
//
// Host-header injection and TRACE/XST checks are also included at standard
// depth because they are independent of insertion points and cheap to run.
func (s *Service) runLiveScanItem(ctx context.Context, input RunInput, item QueuedScanItem) []model.Finding {
	// Validate URL before doing anything.
	u, err := url.Parse(item.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !scope.IsURLInScope(item.URL, input.Scope) {
		return nil
	}

	// Apply per-item timeout.
	itemCtx, cancel := context.WithTimeout(ctx, liveScanItemTimeout)
	defer cancel()

	// Build a scoped RunInput targeting this URL. Use SeedRuntimeEndpoints to
	// ensure the existing probe methods pick up this URL as their candidate.
	// Empty body causes extractRuntimeEndpoints to return nothing, so the
	// probes fall back to []string{input.Target} = []string{item.URL}.
	itemInput := input
	itemInput.Target = item.URL
	itemInput.Options.SeedRuntimeEndpoints = []string{item.URL}
	// Suppress per-item emit commands so the live-scan stream isn't flooded
	// with verbose probe-start events for each individual item.
	itemInput.Emit = nil

	depth := strings.ToLower(strings.TrimSpace(input.Options.LiveScanDepth))
	if depth == "" {
		depth = "standard"
	}

	var findings []model.Finding

	// Shallow checks (always run).
	findings = append(findings, s.runActiveXSSProbe(itemCtx, itemInput, "")...)
	findings = append(findings, s.runActiveOpenRedirectProbe(itemCtx, itemInput, "")...)

	if depth != "shallow" {
		// Standard checks: add SQLi, SSTI, and host-header/TRACE probes.
		findings = append(findings, s.runActiveSQLiProbe(itemCtx, itemInput, "")...)
		findings = append(findings, s.runActiveSSTIProbe(itemCtx, itemInput, "")...)
		findings = append(findings, liveScanHostHeaderCheck(itemCtx, s, itemInput)...)
		findings = append(findings, liveScanTraceCheck(itemCtx, s, itemInput)...)
	}

	// Tag every finding with the live-scan source so the UI can distinguish
	// live-scan results from the main sequential probe sweep.
	for i := range findings {
		if findings[i].EvidenceFields == nil {
			findings[i].EvidenceFields = make(map[string]string)
		}
		findings[i].EvidenceFields["source"] = "live-scan"
		findings[i].EvidenceFields["liveQueueURL"] = item.URL
	}

	return findings
}

// liveScanHostHeaderCheck sends the queued URL with a spoofed Host header and
// flags a finding when the injected value is reflected in the response body.
// This is a lightweight inline implementation that does not require the full
// proxy active-scan infrastructure.
func liveScanHostHeaderCheck(ctx context.Context, s *Service, input RunInput) []model.Finding {
	canary := "live-scan-host-" + fmt.Sprintf("%x", md5.Sum([]byte(input.Target)))[:8] + ".invalid"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Host", canary)
	req.Header.Set("X-Forwarded-Host", canary)

	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return nil
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	_ = resp.Body.Close()
	body := string(bodyBytes)

	if !strings.Contains(body, canary) {
		return nil
	}
	return []model.Finding{{
		ID:             "live-scan-host-header-injection",
		Category:       "input-validation",
		Severity:       model.SeverityMedium,
		Title:          "Host header value reflected in response (live-scan)",
		Description:    "The application reflects an attacker-controlled Host/X-Forwarded-Host header into the response body, enabling password-reset poisoning, cache poisoning, or SSRF.",
		Evidence:       fmt.Sprintf("Host: %s reflected in response from %s", canary, input.Target),
		Recommendation: "Validate the Host header against an allow-list of expected values; never use it to construct absolute URLs.",
		AffectedURL:    input.Target,
	}}
}

// liveScanTraceCheck sends an HTTP TRACE request and flags a finding when the
// server echoes back the canary header (Cross-Site Tracing / XST).
func liveScanTraceCheck(ctx context.Context, s *Service, input RunInput) []model.Finding {
	canary := "live-scan-trace-" + fmt.Sprintf("%x", md5.Sum([]byte(input.Target+fmt.Sprint(time.Now().UnixNano()))))[:10]

	req, err := http.NewRequestWithContext(ctx, "TRACE", input.Target, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("X-LiveScan-Canary", canary)

	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return nil
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	body := string(bodyBytes)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	if !strings.Contains(body, canary) {
		return nil
	}
	return []model.Finding{{
		ID:             "live-scan-trace-enabled",
		Category:       "misconfiguration",
		Severity:       model.SeverityMedium,
		Title:          "HTTP TRACE method enabled (Cross-Site Tracing) (live-scan)",
		Description:    "The server accepts the TRACE method and echoes request headers back in the response body, enabling Cross-Site Tracing (XST) attacks that can bypass HttpOnly cookie protections.",
		Evidence:       fmt.Sprintf("TRACE %s returned %d and reflected canary header in response.", input.Target, resp.StatusCode),
		Recommendation: "Disable the TRACE (and TRACK) HTTP methods on the web server and load balancer.",
		AffectedURL:    input.Target,
	}}
}

// liveScanEffectiveConcurrency returns the worker concurrency to use for live
// scanning. It prefers the per-scan option, then the service config default,
// then the package constant.
func liveScanEffectiveConcurrency(cfg Config, opts model.ScanOptions) int {
	if opts.LiveScanConcurrency > 0 {
		return opts.LiveScanConcurrency
	}
	if cfg.LiveScanConcurrency > 0 {
		return cfg.LiveScanConcurrency
	}
	return liveScanDefaultConcurrency
}

// liveScanEnabled reports whether live scanning should be activated for this
// scan run.
func liveScanEnabled(cfg Config, opts model.ScanOptions) bool {
	return (cfg.EnableLiveScan || opts.UseLiveScan) && !opts.PassiveOnly
}
