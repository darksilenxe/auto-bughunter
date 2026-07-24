package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

type capturedAuthSession struct {
	Profile    model.ScanAuthProfile
	CapturedAt time.Time
}

func (s *Server) captureAuthFromRequest(rawURL string, headers http.Header) {
	if s == nil {
		return
	}
	key := authCaptureKey(rawURL)
	if key == "" {
		return
	}
	profile := authProfileFromHeaders(headers)
	// Also fold in any OAuth bearer token embedded as a URL query parameter
	// (e.g. GET /api/resource?access_token=eyJ…).
	if urlProfile := authProfileFromURLQueryParams(rawURL); !isEmptyAuthProfile(urlProfile) {
		profile = mergeAuthProfiles(profile, urlProfile)
	}
	if isEmptyAuthProfile(profile) {
		return
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	existing := s.authCaptures[key]
	s.authCaptures[key] = capturedAuthSession{
		Profile:    mergeAuthProfiles(existing.Profile, profile),
		CapturedAt: time.Now().UTC(),
	}
}

// captureAuthFromResponse extracts authentication material from an HTTP
// response and merges it into the per-host auth capture store. It handles
// two cases that the request-side capture misses:
//
//   - Set-Cookie headers: cookies set by the server after a successful OAuth
//     login or token-exchange are folded into the session cookie jar so that
//     subsequent scan requests carry the correct session identity.
//   - JSON token responses: when the token endpoint returns a body such as
//     {"access_token":"eyJ…","token_type":"Bearer"} (RFC 6749 §5.1 / OIDC),
//     the token is stored as an Authorization: ****** in the captured
//     profile so it can be replayed immediately without a separate login step.
func (s *Server) captureAuthFromResponse(rawURL string, respHeader http.Header, respBody []byte) {
	if s == nil {
		return
	}
	key := authCaptureKey(rawURL)
	if key == "" {
		return
	}
	profile := authProfileFromResponse(respHeader, respBody)
	if isEmptyAuthProfile(profile) {
		return
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	existing := s.authCaptures[key]
	s.authCaptures[key] = capturedAuthSession{
		Profile:    mergeAuthProfiles(existing.Profile, profile),
		CapturedAt: time.Now().UTC(),
	}
}

func (s *Server) LatestAuthProfileForTarget(target string, maxAge time.Duration) (model.ScanAuthProfile, bool) {
	if s == nil {
		return model.ScanAuthProfile{}, false
	}
	key := authCaptureKey(target)
	if key == "" {
		return model.ScanAuthProfile{}, false
	}
	s.authMu.RLock()
	session, ok := s.authCaptures[key]
	s.authMu.RUnlock()
	if !ok {
		return model.ScanAuthProfile{}, false
	}
	if maxAge > 0 && time.Since(session.CapturedAt) > maxAge {
		return model.ScanAuthProfile{}, false
	}
	return cloneAuthProfile(session.Profile), true
}

func authCaptureKey(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + strings.ToLower(parsed.Host)
}

func authProfileFromHeaders(headers http.Header) model.ScanAuthProfile {
	profile := model.ScanAuthProfile{}
	if userAgent := strings.TrimSpace(headers.Get("User-Agent")); userAgent != "" {
		profile.UserAgent = userAgent
	}
	for _, cookie := range (&http.Request{Header: headers}).Cookies() {
		name := strings.TrimSpace(cookie.Name)
		if name == "" {
			continue
		}
		if profile.Cookies == nil {
			profile.Cookies = map[string]string{}
		}
		profile.Cookies[name] = cookie.Value
	}
	for name, values := range headers {
		if !shouldCaptureAuthHeader(name) || len(values) == 0 {
			continue
		}
		value := strings.TrimSpace(values[0])
		if value == "" {
			continue
		}
		if profile.Headers == nil {
			profile.Headers = map[string]string{}
		}
		profile.Headers[http.CanonicalHeaderKey(name)] = value
	}
	return profile
}

func shouldCaptureAuthHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || lower == "cookie" || lower == "proxy-authorization" || lower == "user-agent" {
		return false
	}
	if lower == "authorization" {
		return true
	}
	if lower == "x-csrf-token" || lower == "x-csrftoken" || lower == "csrf-token" || lower == "x-xsrf-token" {
		return true
	}
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "api-key") ||
		strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "auth")
}

func mergeAuthProfiles(base, overlay model.ScanAuthProfile) model.ScanAuthProfile {
	merged := cloneAuthProfile(base)
	if merged.Headers == nil && len(overlay.Headers) > 0 {
		merged.Headers = map[string]string{}
	}
	for key, value := range overlay.Headers {
		merged.Headers[key] = value
	}
	if merged.Cookies == nil && len(overlay.Cookies) > 0 {
		merged.Cookies = map[string]string{}
	}
	for key, value := range overlay.Cookies {
		merged.Cookies[key] = value
	}
	if strings.TrimSpace(overlay.UserAgent) != "" {
		merged.UserAgent = overlay.UserAgent
	}
	if strings.TrimSpace(overlay.BasicAuthUsername) != "" {
		merged.BasicAuthUsername = overlay.BasicAuthUsername
	}
	if strings.TrimSpace(overlay.BasicAuthPassword) != "" {
		merged.BasicAuthPassword = overlay.BasicAuthPassword
	}
	if strings.TrimSpace(overlay.LoginURL) != "" {
		merged.LoginURL = overlay.LoginURL
	}
	if strings.TrimSpace(overlay.Username) != "" {
		merged.Username = overlay.Username
	}
	if strings.TrimSpace(overlay.Password) != "" {
		merged.Password = overlay.Password
	}
	if len(overlay.LoginSteps) > 0 {
		merged.LoginSteps = append([]model.ScanAuthLoginStep(nil), overlay.LoginSteps...)
	}
	return merged
}

func cloneAuthProfile(profile model.ScanAuthProfile) model.ScanAuthProfile {
	cloned := profile
	if len(profile.Headers) > 0 {
		cloned.Headers = make(map[string]string, len(profile.Headers))
		for key, value := range profile.Headers {
			cloned.Headers[key] = value
		}
	}
	if len(profile.Cookies) > 0 {
		cloned.Cookies = make(map[string]string, len(profile.Cookies))
		for key, value := range profile.Cookies {
			cloned.Cookies[key] = value
		}
	}
	if len(profile.LoginSteps) > 0 {
		cloned.LoginSteps = append([]model.ScanAuthLoginStep(nil), profile.LoginSteps...)
	}
	return cloned
}

func isEmptyAuthProfile(profile model.ScanAuthProfile) bool {
	return len(profile.Headers) == 0 &&
		len(profile.Cookies) == 0 &&
		strings.TrimSpace(profile.UserAgent) == "" &&
		strings.TrimSpace(profile.BasicAuthUsername) == "" &&
		strings.TrimSpace(profile.BasicAuthPassword) == "" &&
		strings.TrimSpace(profile.LoginURL) == "" &&
		strings.TrimSpace(profile.Username) == "" &&
		strings.TrimSpace(profile.Password) == "" &&
		len(profile.LoginSteps) == 0
}

// authProfileFromResponse builds a ScanAuthProfile from an HTTP response's
// headers and body. It captures:
//
//   - Cookies issued via Set-Cookie (e.g. session cookies set after a
//     successful OAuth callback).
//   - An OAuth bearer token found in the response JSON body under one of the
//     standard field names (access_token, id_token, token — RFC 6749 §5.1 /
//     OIDC). The token is stored as Authorization: ****** so it can
//     be replayed directly in subsequent probe requests.
func authProfileFromResponse(respHeader http.Header, respBody []byte) model.ScanAuthProfile {
	profile := model.ScanAuthProfile{}

	// Capture server-issued cookies from Set-Cookie response headers.
	for _, c := range (&http.Response{Header: respHeader}).Cookies() {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			continue
		}
		if profile.Cookies == nil {
			profile.Cookies = map[string]string{}
		}
		profile.Cookies[name] = c.Value
	}

	// Extract an OAuth bearer token from a JSON response body and synthesise
	// an Authorization header so authenticated replay works immediately.
	if token := extractOAuthTokenFromJSON(respBody); token != "" {
		if profile.Headers == nil {
			profile.Headers = map[string]string{}
		}
		profile.Headers["Authorization"] = "Bearer " + token
	}

	return profile
}

// oauthTokenJSONFields is the ordered list of JSON object keys we probe for an
// OAuth bearer token. access_token (RFC 6749) is tried first; id_token (OIDC)
// second; the generic "token" key used by many non-standard APIs last.
var oauthTokenJSONFields = []string{
	"access_token", "accessToken",
	"id_token", "idToken",
	"token",
	"auth_token", "authToken",
}

// extractOAuthTokenFromJSON parses body as a JSON object and returns the value
// of the first recognised OAuth token field. Returns "" when the body is not a
// JSON object or contains no recognised field.
func extractOAuthTokenFromJSON(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return ""
	}
	for _, field := range oauthTokenJSONFields {
		if v, ok := obj[field]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// oauthQueryParamNames is the ordered list of URL query parameter names used
// by OAuth and API-key "token-in-URL" patterns (non-recommended but common).
// We synthesise an Authorization: ****** from the first match so the
// captured profile covers this credential for authenticated replay.
var oauthQueryParamNames = []string{
	"access_token", "accesstoken",
	"id_token",
	"token",
	"auth_token", "authtoken",
}

// authProfileFromURLQueryParams extracts a bearer token embedded as a URL
// query parameter and returns it as an Authorization header in the auth
// profile. Returns an empty profile when no recognised parameter is present.
func authProfileFromURLQueryParams(rawURL string) model.ScanAuthProfile {
	profile := model.ScanAuthProfile{}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return profile
	}
	q := parsed.Query()
	for _, name := range oauthQueryParamNames {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			if profile.Headers == nil {
				profile.Headers = map[string]string{}
			}
			profile.Headers["Authorization"] = "Bearer " + v
			break
		}
	}
	return profile
}

// authProfileFromURLFragment extracts OAuth bearer tokens that appear in the
// URL fragment (hash portion), as used by the OAuth 2.0 implicit grant
// (RFC 6749 §4.2.2). Authorization servers encode the token response as a
// query-string inside the fragment, e.g.:
//
//	https://app.example.com/auth/redirection#access_token=TOKEN&token_type=bearer
//
// Browsers never send the fragment to the server, so the proxy can only see
// these tokens when they appear inside a redirect Location header issued by
// the OAuth provider. Returns an empty profile when no recognised field is
// found in the fragment.
func authProfileFromURLFragment(rawURL string) model.ScanAuthProfile {
	profile := model.ScanAuthProfile{}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Fragment == "" {
		return profile
	}
	q, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		return profile
	}
	for _, name := range oauthQueryParamNames {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			if profile.Headers == nil {
				profile.Headers = map[string]string{}
			}
			profile.Headers["Authorization"] = "Bearer " + v
			break
		}
	}
	return profile
}

// captureAuthFromRedirectLocation extracts OAuth material from the Location
// URL of a redirect response (HTTP 3xx) and stores it keyed to the redirect
// target host. This is the only opportunity to capture tokens delivered via
// the OAuth 2.0 implicit grant, where the authorization server issues a
// redirect such as:
//
//	HTTP/1.1 302 Found
//	Location: https://app.example.com/auth/redirection#access_token=TOKEN
//
// Browsers strip the fragment before making the follow-up GET, so the token
// never appears in any subsequent HTTP request — it must be captured here,
// from the OAuth provider's response, and stored under the application host
// (app.example.com) so it is available when the scanner probes that host.
func (s *Server) captureAuthFromRedirectLocation(locationURL string) {
	if s == nil || strings.TrimSpace(locationURL) == "" {
		return
	}
	key := authCaptureKey(locationURL)
	if key == "" {
		return
	}
	// Extract tokens from query params (some implicit-flow providers) and
	// from the URL fragment (standard implicit flow per RFC 6749 §4.2.2).
	profile := authProfileFromURLQueryParams(locationURL)
	if fragProfile := authProfileFromURLFragment(locationURL); !isEmptyAuthProfile(fragProfile) {
		profile = mergeAuthProfiles(profile, fragProfile)
	}
	if isEmptyAuthProfile(profile) {
		return
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	existing := s.authCaptures[key]
	s.authCaptures[key] = capturedAuthSession{
		Profile:    mergeAuthProfiles(existing.Profile, profile),
		CapturedAt: time.Now().UTC(),
	}
}
