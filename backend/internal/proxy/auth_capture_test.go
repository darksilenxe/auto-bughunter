package proxy

import (
	"net/http"
	"testing"
	"time"
)

func TestLatestAuthProfileForTargetReturnsCapturedSession(t *testing.T) {
	srv := NewServer(NewMemStore())
	headers := http.Header{
		"Cookie":        []string{"session=abc123; csrftoken=xyz"},
		"Authorization": []string{"TestAuthValue"},
		"X-CSRF-Token":  []string{"xyz"},
		"User-Agent":    []string{"Mozilla/5.0"},
	}

	srv.captureAuthFromRequest("https://app.example.com/account", headers)

	profile, ok := srv.LatestAuthProfileForTarget("https://app.example.com/dashboard", time.Minute)
	if !ok {
		t.Fatal("expected captured auth profile")
	}
	if got := profile.Cookies["session"]; got != "abc123" {
		t.Fatalf("expected session cookie, got %q", got)
	}
	if got := profile.Headers["Authorization"]; got != "TestAuthValue" {
		t.Fatalf("expected authorization header, got %q", got)
	}
	if got := profile.Headers["X-Csrf-Token"]; got != "xyz" {
		t.Fatalf("expected csrf header, got %q", got)
	}
	if profile.UserAgent != "Mozilla/5.0" {
		t.Fatalf("expected user agent to be captured, got %q", profile.UserAgent)
	}
}

func TestLatestAuthProfileForTargetSkipsStaleCapture(t *testing.T) {
	srv := NewServer(NewMemStore())
	srv.authCaptures[authCaptureKey("https://app.example.com")] = capturedAuthSession{
		Profile:    authProfileFromHeaders(http.Header{"Cookie": []string{"session=abc123"}}),
		CapturedAt: time.Now().Add(-2 * time.Hour),
	}

	if _, ok := srv.LatestAuthProfileForTarget("https://app.example.com", time.Minute); ok {
		t.Fatal("expected stale capture to be ignored")
	}
}

func TestCaptureAuthFromResponseSetCookie(t *testing.T) {
	srv := NewServer(NewMemStore())
	respHeader := http.Header{
		"Set-Cookie": []string{"session=newtoken123; HttpOnly; Secure; SameSite=Strict"},
	}

	srv.captureAuthFromResponse("https://app.example.com/oauth/callback", respHeader, nil)

	profile, ok := srv.LatestAuthProfileForTarget("https://app.example.com", time.Minute)
	if !ok {
		t.Fatal("expected captured auth profile from Set-Cookie")
	}
	if got := profile.Cookies["session"]; got != "newtoken123" {
		t.Fatalf("expected session cookie from Set-Cookie, got %q", got)
	}
}

func TestCaptureAuthFromResponseJSONAccessToken(t *testing.T) {
	srv := NewServer(NewMemStore())
	const tok = "eyJtest123"
	body := []byte(`{"access_token":"` + tok + `","token_type":"Bearer","expires_in":3600}`)

	srv.captureAuthFromResponse("https://auth.example.com/oauth/token", nil, body)

	profile, ok := srv.LatestAuthProfileForTarget("https://auth.example.com", time.Minute)
	if !ok {
		t.Fatal("expected captured auth profile from JSON token response")
	}
	wantAuth := "Bearer " + tok
	if got := profile.Headers["Authorization"]; got != wantAuth {
		t.Fatalf("expected %q, got %q", wantAuth, got)
	}
}

func TestCaptureAuthFromResponseJSONIDToken(t *testing.T) {
	srv := NewServer(NewMemStore())
	// No access_token, only id_token -- should fall back to id_token.
	const tok = "eyJidtest"
	body := []byte(`{"id_token":"` + tok + `","token_type":"Bearer"}`)

	srv.captureAuthFromResponse("https://auth.example.com/oauth/token", nil, body)

	profile, ok := srv.LatestAuthProfileForTarget("https://auth.example.com", time.Minute)
	if !ok {
		t.Fatal("expected captured auth profile from id_token")
	}
	wantAuth := "Bearer " + tok
	if got := profile.Headers["Authorization"]; got != wantAuth {
		t.Fatalf("expected %q, got %q", wantAuth, got)
	}
}

func TestCaptureAuthFromResponseMergesWithExistingProfile(t *testing.T) {
	srv := NewServer(NewMemStore())
	// First, capture a session cookie from the request side.
	srv.captureAuthFromRequest("https://app.example.com/login", http.Header{
		"Cookie": []string{"csrftoken=csrf999"},
	})
	// Then the server responds with a new session cookie and an access token.
	respHeader := http.Header{
		"Set-Cookie": []string{"session=mergesession; HttpOnly"},
	}
	body := []byte(`{"access_token":"mergetoken"}`)
	srv.captureAuthFromResponse("https://app.example.com/login", respHeader, body)

	profile, ok := srv.LatestAuthProfileForTarget("https://app.example.com", time.Minute)
	if !ok {
		t.Fatal("expected merged auth profile")
	}
	if profile.Cookies["csrftoken"] != "csrf999" {
		t.Errorf("expected csrftoken from request side, got %q", profile.Cookies["csrftoken"])
	}
	if profile.Cookies["session"] != "mergesession" {
		t.Errorf("expected session from response Set-Cookie, got %q", profile.Cookies["session"])
	}
	wantAuth := "Bearer " + "mergetoken"
	if got := profile.Headers["Authorization"]; got != wantAuth {
		t.Errorf("expected %q from response JSON body, got %q", wantAuth, got)
	}
}

func TestCaptureAuthFromRequestURLQueryToken(t *testing.T) {
	srv := NewServer(NewMemStore())
	// No request headers, but access_token is in the query string.
	srv.captureAuthFromRequest("https://api.example.com/resource?access_token=qtok123&foo=bar", http.Header{})

	profile, ok := srv.LatestAuthProfileForTarget("https://api.example.com", time.Minute)
	if !ok {
		t.Fatal("expected captured auth profile from URL query token")
	}
	wantAuth := "Bearer " + "qtok123"
	if got := profile.Headers["Authorization"]; got != wantAuth {
		t.Fatalf("expected %q, got %q", wantAuth, got)
	}
}

func TestExtractOAuthTokenFromJSON(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{"access_token first", []byte(`{"access_token":"tok1","id_token":"tok2"}`), "tok1"},
		{"id_token fallback", []byte(`{"id_token":"tok2"}`), "tok2"},
		{"generic token", []byte(`{"token":"tok3"}`), "tok3"},
		{"auth_token", []byte(`{"auth_token":"tok4"}`), "tok4"},
		{"camelCase accessToken", []byte(`{"accessToken":"tok5"}`), "tok5"},
		{"not an object", []byte(`["tok"]`), ""},
		{"empty body", []byte{}, ""},
		{"invalid json", []byte(`{bad}`), ""},
		{"empty token value", []byte(`{"access_token":""}`), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractOAuthTokenFromJSON(tt.body); got != tt.want {
				t.Errorf("extractOAuthTokenFromJSON() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthProfileFromURLQueryParams(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantKey string
		wantVal string
	}{
		{"access_token param", "https://api.example.com/v1?access_token=abc", "Authorization", "Bearer " + "abc"},
		{"token param", "https://api.example.com/v1?token=def", "Authorization", "Bearer " + "def"},
		{"no token param", "https://api.example.com/v1?foo=bar", "", ""},
		{"empty param", "https://api.example.com/v1?access_token=", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := authProfileFromURLQueryParams(tt.rawURL)
			if tt.wantKey == "" {
				if len(p.Headers) != 0 {
					t.Errorf("expected no headers, got %v", p.Headers)
				}
				return
			}
			if got := p.Headers[tt.wantKey]; got != tt.wantVal {
				t.Errorf("headers[%q] = %q, want %q", tt.wantKey, got, tt.wantVal)
			}
		})
	}
}
