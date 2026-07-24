package proxy

import (
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
	if s == nil || len(headers) == 0 {
		return
	}
	key := authCaptureKey(rawURL)
	if key == "" {
		return
	}
	profile := authProfileFromHeaders(headers)
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
