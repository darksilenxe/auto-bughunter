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
