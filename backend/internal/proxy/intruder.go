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

// IntruderResult is one row in an Intruder-style fuzz attack: a single
// payload substitution and the upstream response summary.
type IntruderResult struct {
	Payload      string `json:"payload"`
	Status       int    `json:"status"`
	LengthBytes  int    `json:"lengthBytes"`
	DurationMS   int64  `json:"durationMs"`
	ResponseBody string `json:"responseBody,omitempty"`
	Error        string `json:"error,omitempty"`
}

// RunIntruder fetches a previously-captured request, then for each payload
// substitutes the marker (e.g. "§") in the URL, header values, and body, sends
// the resulting request to the original destination, and returns a per-payload
// summary. Payloads that produce out-of-policy URLs are reported with an
// Error rather than being silently skipped so operators can audit results.
//
// The result body is truncated to maxIntruderBodyPreview to keep responses
// small; full bodies remain available via the standard capture history when
// captureToHistory is true (default in this package).
func RunIntruder(
	ctx context.Context,
	srv *Server,
	requestID string,
	marker string,
	payloads []string,
	overrideHeaders map[string]string,
	overrideBody string,
) ([]IntruderResult, error) {
	if srv == nil {
		return nil, fmt.Errorf("proxy server is nil")
	}
	orig, err := srv.store.GetProxyRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get proxy request %s: %w", requestID, err)
	}
	if marker == "" {
		marker = "§"
	}

	baselineBody := orig.RequestBody
	if overrideBody != "" {
		baselineBody = overrideBody
	}
	baselineHeaders := make(map[string]string, len(orig.RequestHeaders)+len(overrideHeaders))
	for k, v := range orig.RequestHeaders {
		baselineHeaders[k] = v
	}
	for k, v := range overrideHeaders {
		baselineHeaders[k] = v
	}

	results := make([]IntruderResult, 0, len(payloads))
	for _, payload := range payloads {
		results = append(results, runOneIntruder(ctx, srv, orig.Method, orig.URL, baselineHeaders, baselineBody, marker, payload))
	}
	return results, nil
}

const maxIntruderBodyPreview = 4 * 1024

func runOneIntruder(
	ctx context.Context,
	srv *Server,
	method, baseURL string,
	headers map[string]string,
	body, marker, payload string,
) IntruderResult {
	res := IntruderResult{Payload: payload}

	subURL := strings.ReplaceAll(baseURL, marker, payload)
	subBody := strings.ReplaceAll(body, marker, payload)
	subHeaders := make(http.Header, len(headers))
	for k, v := range headers {
		subHeaders.Set(k, strings.ReplaceAll(v, marker, payload))
	}

	// SSRF guard: payload-substituted URLs are user-controlled, so they
	// must pass the same outbound safety policy as every other proxy
	// request (blocks loopback, link-local, private, and metadata IPs,
	// and rejects non-http(s) schemes). Parse first so the validated
	// URL is what the transport actually dials.
	parsed, err := url.Parse(subURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		res.Error = "invalid request URL after payload substitution"
		return res
	}
	if err := safety.ValidateOutboundURL(parsed.String()); err != nil {
		res.Error = "blocked by outbound safety policy"
		return res
	}

	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader([]byte(subBody)))
	if err != nil {
		res.Error = "build request: " + err.Error()
		return res
	}
	req.Header = subHeaders
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
	if len(respBody) > maxIntruderBodyPreview {
		res.ResponseBody = string(respBody[:maxIntruderBodyPreview])
	} else {
		res.ResponseBody = string(respBody)
	}
	return res
}
