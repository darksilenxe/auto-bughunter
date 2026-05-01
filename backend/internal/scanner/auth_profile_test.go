package scanner

import (
	"net/http"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestApplyAuthProfile_RejectsCRLFInjection(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	profile := model.ScanAuthProfile{
		Headers: map[string]string{
			"X-Trusted":         "ok",
			"X-Bad-Value":       "value\r\nHost: attacker.test",
			"X-Bad-Name\r\nFoo": "ignored",
			"X-Null-Value":      "v\x00v",
		},
		UserAgent: "scanner/1.0\r\nX-Inject: yes",
		Cookies: map[string]string{
			"good":  "fine",
			"bad":   "v\r\nHost: attacker.test",
			"split": "ok",
			"key\n": "val",
		},
	}
	ApplyAuthProfile(req, profile)

	if got := req.Header.Get("X-Trusted"); got != "ok" {
		t.Fatalf("safe header dropped: got %q", got)
	}
	if req.Header.Get("X-Bad-Value") != "" {
		t.Fatalf("CRLF in header value should have been rejected")
	}
	for name := range req.Header {
		if strings.ContainsAny(name, "\r\n") {
			t.Fatalf("header name with CRLF leaked: %q", name)
		}
		for _, v := range req.Header.Values(name) {
			if strings.ContainsAny(v, "\r\n\x00") {
				t.Fatalf("header value with CRLF/NUL leaked: %s=%q", name, v)
			}
		}
	}
	// User-Agent with CRLF must not be applied.
	if ua := req.Header.Get("User-Agent"); strings.ContainsAny(ua, "\r\n") {
		t.Fatalf("user-agent CRLF leaked: %q", ua)
	}
	// Cookie header should contain the safe entries only and never CRLF.
	cookie := req.Header.Get("Cookie")
	if strings.ContainsAny(cookie, "\r\n\x00") {
		t.Fatalf("cookie CRLF leaked: %q", cookie)
	}
	if !strings.Contains(cookie, "good=fine") || !strings.Contains(cookie, "split=ok") {
		t.Fatalf("expected safe cookies preserved, got %q", cookie)
	}
	if strings.Contains(cookie, "bad=") {
		t.Fatalf("unsafe cookie should have been dropped: %q", cookie)
	}
}

func TestIsSafeHeaderName(t *testing.T) {
	cases := map[string]bool{
		"X-Trusted":      true,
		"":               false,
		"Bad Name":       false,
		"Bad\rName":      false,
		"Bad\nName":      false,
		"Has:Colon":      false,
		"semi;colon":     false,
		"Authorization":  true,
		"With(Paren":     false,
	}
	for in, want := range cases {
		if got := isSafeHeaderName(in); got != want {
			t.Errorf("isSafeHeaderName(%q)=%v want %v", in, got, want)
		}
	}
}
