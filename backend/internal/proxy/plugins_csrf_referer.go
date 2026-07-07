package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/safety"
)

// AntiCSRFRefererResult is the outcome of the "Anti-CSRF Token From
// Referer" plugin: it fetches the page named by the captured request's
// Referer header, extracts a likely CSRF token from that page, injects it
// into a replay of the original request, and reports the result. This
// mirrors Burp Suite's "Anti-CSRF Token From Referer" extension, which lets
// operators keep CSRF-protected flows (e.g. Intruder/Repeater sessions)
// alive by refreshing the token from the page that would naturally have
// preceded the request.
type AntiCSRFRefererResult struct {
	RequestID         string `json:"requestId"`
	RefererURL        string `json:"refererUrl"`
	TokenFieldName    string `json:"tokenFieldName,omitempty"`
	TokenValue        string `json:"tokenValue,omitempty"`
	Injected          bool   `json:"injected"`
	InjectionLocation string `json:"injectionLocation,omitempty"` // "body", "header", or "query"
	ReplayStatus      int    `json:"replayStatus"`
	ReplayLengthBytes int    `json:"replayLengthBytes"`
	ReplayBody        string `json:"replayBody,omitempty"`
	Error             string `json:"error,omitempty"`
}

var (
	reHTMLInputTag  = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reHTMLMetaTag   = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	reAttrName      = regexp.MustCompile(`(?is)\bname\s*=\s*["']([^"']+)["']`)
	reAttrValue     = regexp.MustCompile(`(?is)\bvalue\s*=\s*["']([^"']*)["']`)
	reAttrContent   = regexp.MustCompile(`(?is)\bcontent\s*=\s*["']([^"']*)["']`)
	reCSRFFieldName = regexp.MustCompile(`(?i)^(csrf[_-]?token|_csrf|_token|authenticity_token|csrfmiddlewaretoken|__requestverificationtoken|xsrf[_-]?token)$`)
	reCSRFMetaName  = regexp.MustCompile(`(?i)^(csrf-token|csrf-param|_csrf|xsrf-token)$`)
)

// extractCSRFToken scans an HTML page for a hidden <input> field or <meta>
// tag whose name matches one of the well-known anti-CSRF token conventions
// (Django, Rails, ASP.NET, Spring, generic "csrf_token", etc.) and returns
// the field name and token value found, if any.
func extractCSRFToken(html string) (name, value string, found bool) {
	for _, tag := range reHTMLInputTag.FindAllString(html, -1) {
		nameMatch := reAttrName.FindStringSubmatch(tag)
		if nameMatch == nil || !reCSRFFieldName.MatchString(nameMatch[1]) {
			continue
		}
		valueMatch := reAttrValue.FindStringSubmatch(tag)
		val := ""
		if valueMatch != nil {
			val = valueMatch[1]
		}
		return nameMatch[1], val, true
	}
	for _, tag := range reHTMLMetaTag.FindAllString(html, -1) {
		nameMatch := reAttrName.FindStringSubmatch(tag)
		if nameMatch == nil || !reCSRFMetaName.MatchString(nameMatch[1]) {
			continue
		}
		contentMatch := reAttrContent.FindStringSubmatch(tag)
		val := ""
		if contentMatch != nil {
			val = contentMatch[1]
		}
		return nameMatch[1], val, true
	}
	return "", "", false
}

// RunAntiCSRFFromReferer fetches the page referenced by the captured
// request's Referer header, extracts a CSRF token from it, injects that
// token into the original request (replacing an existing form field/header
// of the same name, or appending it if the field isn't already present),
// and replays the request.
func RunAntiCSRFFromReferer(ctx context.Context, srv *Server, requestID string) (*AntiCSRFRefererResult, error) {
	if srv == nil {
		return nil, fmt.Errorf("proxy server is nil")
	}
	orig, err := srv.store.GetProxyRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get proxy request %s: %w", requestID, err)
	}

	refererURL := orig.RequestHeaders[http.CanonicalHeaderKey("Referer")]
	if refererURL == "" {
		refererURL = orig.RequestHeaders["Referer"]
	}
	refererURL = strings.TrimSpace(refererURL)
	if refererURL == "" {
		return nil, fmt.Errorf("captured request %s has no Referer header", requestID)
	}

	result := &AntiCSRFRefererResult{RequestID: requestID, RefererURL: refererURL}

	if err := safety.ValidateOutboundURL(refererURL); err != nil {
		result.Error = "referer URL blocked by outbound safety policy"
		return result, nil
	}
	refReq, err := http.NewRequestWithContext(ctx, http.MethodGet, refererURL, nil)
	if err != nil {
		result.Error = "build referer request: " + err.Error()
		return result, nil
	}
	refResp, err := srv.transport.RoundTrip(refReq)
	if err != nil {
		result.Error = "fetch referer page: " + err.Error()
		return result, nil
	}
	defer refResp.Body.Close()
	refBody, _ := io.ReadAll(io.LimitReader(refResp.Body, maxForwardBody))

	name, value, found := extractCSRFToken(string(refBody))
	if !found {
		result.Error = "no CSRF token found on referer page"
		return result, nil
	}
	result.TokenFieldName = name
	result.TokenValue = value

	// Inject the token into the original request: prefer replacing a
	// matching form field in the body, then a header of the same name,
	// falling back to appending it as a form field for POST/PUT/PATCH
	// requests with a form-encoded body.
	newBody := orig.RequestBody
	injected := false
	location := ""
	if strings.Contains(newBody, name+"=") {
		newBody = replaceFormFieldValue(newBody, name, value)
		injected = true
		location = "body"
	} else if _, hasHeader := orig.RequestHeaders[http.CanonicalHeaderKey(name)]; hasHeader {
		injected = true
		location = "header"
	} else if strings.EqualFold(orig.Method, http.MethodPost) || strings.EqualFold(orig.Method, http.MethodPut) || strings.EqualFold(orig.Method, http.MethodPatch) {
		if newBody != "" {
			newBody += "&"
		}
		newBody += url.QueryEscape(name) + "=" + url.QueryEscape(value)
		injected = true
		location = "body"
	}
	result.Injected = injected
	result.InjectionLocation = location

	headers := make(map[string]string, len(orig.RequestHeaders)+1)
	for k, v := range orig.RequestHeaders {
		headers[k] = v
	}
	if location == "header" {
		headers[http.CanonicalHeaderKey(name)] = value
	}

	if err := safety.ValidateOutboundURL(orig.URL); err != nil {
		result.Error = "original request URL blocked by outbound safety policy"
		return result, nil
	}
	outReq, err := http.NewRequestWithContext(ctx, orig.Method, orig.URL, bytes.NewReader([]byte(newBody)))
	if err != nil {
		result.Error = "build replay request: " + err.Error()
		return result, nil
	}
	for k, v := range headers {
		outReq.Header.Set(k, v)
	}
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := srv.transport.RoundTrip(outReq)
	if err != nil {
		result.Error = "replay transport error: " + err.Error()
		return result, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody))
	result.ReplayStatus = resp.StatusCode
	result.ReplayLengthBytes = len(respBody)
	if len(respBody) > maxBypassBodyPreview {
		result.ReplayBody = string(respBody[:maxBypassBodyPreview])
	} else {
		result.ReplayBody = string(respBody)
	}
	return result, nil
}

// reFormFieldValue matches a "name=value" pair up to the next "&" (or end of
// string) in an application/x-www-form-urlencoded body.
func replaceFormFieldValue(body, name, newValue string) string {
	re := regexp.MustCompile(`(^|&)` + regexp.QuoteMeta(name) + `=([^&]*)`)
	replacement := "${1}" + name + "=" + url.QueryEscape(newValue)
	return re.ReplaceAllString(body, replacement)
}
