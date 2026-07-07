package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/safety"
)

// BypassAttempt is one variation of a captured request tried by the 403 or
// 429 bypasser plugins (à la Burp Suite's "403 Bypasser"/"429 Bypasser"
// extensions), together with the upstream response summary.
type BypassAttempt struct {
	Technique    string            `json:"technique"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	Status       int               `json:"status"`
	LengthBytes  int               `json:"lengthBytes"`
	DurationMS   int64             `json:"durationMs"`
	Bypassed     bool              `json:"bypassed"`
	ResponseBody string            `json:"responseBody,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// BypassResult is the outcome of running a battery of bypass techniques
// against a single captured request.
type BypassResult struct {
	RequestID      string          `json:"requestId"`
	OriginalURL    string          `json:"originalUrl"`
	OriginalStatus int             `json:"originalStatus"`
	Attempts       []BypassAttempt `json:"attempts"`
	AnyBypassed    bool            `json:"anyBypassed"`
}

const maxBypassBodyPreview = 4 * 1024

// RunBypass403 replays a captured request that originally received a
// 401/403 response using a battery of well-known access-control bypass
// techniques: path manipulation (trailing/leading slashes, dot segments,
// encoding, case variation) and spoofed internal-origin headers
// (X-Original-URL, X-Forwarded-For, etc.). It reports, for each technique,
// whether the response status moved out of the 401/403 range.
func RunBypass403(ctx context.Context, srv *Server, requestID string) (*BypassResult, error) {
	if srv == nil {
		return nil, fmt.Errorf("proxy server is nil")
	}
	orig, err := srv.store.GetProxyRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get proxy request %s: %w", requestID, err)
	}

	parsed, err := url.Parse(orig.URL)
	if err != nil {
		return nil, fmt.Errorf("parse original URL: %w", err)
	}

	result := &BypassResult{
		RequestID:      requestID,
		OriginalURL:    orig.URL,
		OriginalStatus: orig.ResponseStatus,
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}
	lastSlash := strings.LastIndex(path, "/")
	lastSegment := path[lastSlash+1:]
	parent := path[:lastSlash+1]

	type variant struct {
		technique string
		path      string
		headers   map[string]string
	}
	variants := []variant{
		{"trailing slash", strings.TrimSuffix(path, "/") + "/", nil},
		{"double leading slash", "/" + strings.TrimPrefix(path, "/"), nil},
		{"path//" + lastSegment, parent + "/" + lastSegment, nil},
		{"dot segment prefix", parent + "./" + lastSegment, nil},
		{"trailing dot segment", strings.TrimSuffix(path, "/") + "/.", nil},
		{"url-encoded slash", parent + "%2e/" + lastSegment, nil},
		{"case randomized segment", parent + randomizeCase(lastSegment), nil},
		{"append ..;/", strings.TrimSuffix(path, "/") + "/..;/", nil},
		{"original path, X-Original-URL", path, map[string]string{"X-Original-URL": path}},
		{"original path, X-Rewrite-URL", path, map[string]string{"X-Rewrite-URL": path}},
		{"original path, X-Custom-IP-Authorization", path, map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{"original path, X-Forwarded-For localhost", path, map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{"original path, X-Forwarded-Host localhost", path, map[string]string{"X-Forwarded-Host": "localhost"}},
		{"original path, X-Host localhost", path, map[string]string{"X-Host": "localhost"}},
		{"original path, X-Forwarded localhost", path, map[string]string{"X-Forwarded": "for=127.0.0.1"}},
		{"original path, True-Client-IP localhost", path, map[string]string{"True-Client-IP": "127.0.0.1"}},
		{"original path, X-Client-IP localhost", path, map[string]string{"X-Client-IP": "127.0.0.1"}},
		{"original path, Referer same-origin", path, map[string]string{"Referer": parsed.Scheme + "://" + parsed.Host + "/"}},
	}

	for _, v := range variants {
		attemptURL := *parsed
		attemptURL.Path = v.path
		attempt := sendBypassAttempt(ctx, srv, v.technique, orig.Method, attemptURL.String(), orig.RequestHeaders, v.headers, orig.RequestBody)
		attempt.Bypassed = attempt.Error == "" && attempt.Status != 0 && attempt.Status != http.StatusUnauthorized && attempt.Status != http.StatusForbidden &&
			(orig.ResponseStatus == http.StatusUnauthorized || orig.ResponseStatus == http.StatusForbidden)
		if attempt.Bypassed {
			result.AnyBypassed = true
		}
		result.Attempts = append(result.Attempts, attempt)
	}

	return result, nil
}

// RunBypass429 replays a captured request that originally received a 429
// (Too Many Requests) response using a battery of common rate-limit bypass
// techniques based on spoofed client-identity headers, à la Burp Suite's
// "429 Bypasser" extension.
func RunBypass429(ctx context.Context, srv *Server, requestID string) (*BypassResult, error) {
	if srv == nil {
		return nil, fmt.Errorf("proxy server is nil")
	}
	orig, err := srv.store.GetProxyRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get proxy request %s: %w", requestID, err)
	}

	result := &BypassResult{
		RequestID:      requestID,
		OriginalURL:    orig.URL,
		OriginalStatus: orig.ResponseStatus,
	}

	variants := []struct {
		technique string
		headers   map[string]string
	}{
		{"X-Forwarded-For random IP", map[string]string{"X-Forwarded-For": randomIPv4()}},
		{"X-Real-IP random IP", map[string]string{"X-Real-IP": randomIPv4()}},
		{"X-Client-IP random IP", map[string]string{"X-Client-IP": randomIPv4()}},
		{"X-Originating-IP random IP", map[string]string{"X-Originating-IP": randomIPv4()}},
		{"True-Client-IP random IP", map[string]string{"True-Client-IP": randomIPv4()}},
		{"X-Forwarded-Host randomized", map[string]string{"X-Forwarded-Host": randomHostname()}},
		{"chained X-Forwarded-For", map[string]string{"X-Forwarded-For": randomIPv4() + ", " + randomIPv4()}},
		{"CF-Connecting-IP random IP", map[string]string{"CF-Connecting-IP": randomIPv4()}},
		{"X-Forwarded random IP", map[string]string{"X-Forwarded": "for=" + randomIPv4()}},
	}

	for _, v := range variants {
		attempt := sendBypassAttempt(ctx, srv, v.technique, orig.Method, orig.URL, orig.RequestHeaders, v.headers, orig.RequestBody)
		attempt.Bypassed = attempt.Error == "" && attempt.Status != 0 && attempt.Status != http.StatusTooManyRequests &&
			orig.ResponseStatus == http.StatusTooManyRequests
		if attempt.Bypassed {
			result.AnyBypassed = true
		}
		result.Attempts = append(result.Attempts, attempt)
	}

	return result, nil
}

// sendBypassAttempt builds and sends one bypass variation, applying the
// standard outbound safety policy, and returns a summary of the response.
func sendBypassAttempt(
	ctx context.Context,
	srv *Server,
	technique, method, rawURL string,
	baseHeaders, overrideHeaders map[string]string,
	body string,
) BypassAttempt {
	res := BypassAttempt{Technique: technique, Method: method, URL: rawURL, Headers: overrideHeaders}

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		res.Error = "invalid request URL"
		return res
	}
	if err := safety.ValidateOutboundURL(parsed.String()); err != nil {
		res.Error = "blocked by outbound safety policy"
		return res
	}

	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader([]byte(body)))
	if err != nil {
		res.Error = "build request: " + err.Error()
		return res
	}
	for k, v := range baseHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range overrideHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	start := time.Now()
	resp, err := srv.transport.RoundTrip(req)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = "transport error: " + err.Error()
		return res
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody))
	res.Status = resp.StatusCode
	res.LengthBytes = len(respBody)
	if len(respBody) > maxBypassBodyPreview {
		res.ResponseBody = string(respBody[:maxBypassBodyPreview])
	} else {
		res.ResponseBody = string(respBody)
	}
	return res
}

// randomizeCase returns s with alternating upper/lower case applied to its
// alphabetic characters, a common WAF/ACL bypass technique for
// case-sensitive path matching.
func randomizeCase(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		if i%2 == 0 {
			b.WriteString(strings.ToUpper(string(r)))
		} else {
			b.WriteString(strings.ToLower(string(r)))
		}
	}
	return b.String()
}

// randomIPv4 returns a pseudo-random, non-reserved-looking IPv4 address
// string used to spoof client-identity headers. It does not need to be
// cryptographically random — it only needs to differ from the operator's
// real address and from previous attempts.
func randomIPv4() string {
	n := time.Now().UnixNano()
	a := (n>>0)&0xFF | 1
	b := (n >> 8) & 0xFF
	c := (n >> 16) & 0xFF
	d := (n>>24)&0xFE + 1
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

// randomHostname returns a pseudo-random hostname-like string used to probe
// X-Forwarded-Host-driven rate limiting/routing logic.
func randomHostname() string {
	return fmt.Sprintf("bypass-%d.internal", time.Now().UnixNano()%1_000_000)
}
