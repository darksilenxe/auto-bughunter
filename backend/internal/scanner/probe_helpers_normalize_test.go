package scanner

import (
	"strings"
	"testing"
)

func TestNormalizeResponseBody_TokenPatterns(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		mustNot []string // substrings that should NOT appear after normalization
	}{
		{
			name:  "uuid",
			input: `{"id":"550e8400-e29b-41d4-a716-446655440000"}`,
			mustNot: []string{
				"550e8400-e29b-41d4-a716-446655440000",
			},
		},
		{
			name:  "unix_ms_timestamp",
			input: `{"ts":1719800000123}`,
			mustNot: []string{
				"1719800000123",
			},
		},
		{
			name:  "long_hex",
			input: `session=deadbeefdeadbeefdeadbeef`,
			mustNot: []string{
				"deadbeefdeadbeefdeadbeef",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeResponseBody(tc.input)
			for _, s := range tc.mustNot {
				if strings.Contains(got, s) {
					t.Errorf("NormalizeResponseBody(%q) still contains %q; got %q", tc.input, s, got)
				}
			}
			if !strings.Contains(got, "<token>") {
				t.Errorf("expected <token> placeholder in %q", got)
			}
		})
	}
}

func TestNormalizeResponseBody_CSRFHiddenInput(t *testing.T) {
	body := `<form><input type="hidden" name="csrf_token" value="abc123xyz789"><input type="text" name="q" value="hello"></form>`
	got := NormalizeResponseBody(body)
	if strings.Contains(got, "abc123xyz789") {
		t.Errorf("csrf token value should have been redacted; got %q", got)
	}
	if !strings.Contains(got, `name="csrf_token"`) {
		t.Errorf("expected csrf_token attribute to be preserved; got %q", got)
	}
	if !strings.Contains(got, `name="q" value="hello"`) {
		t.Errorf("non-CSRF fields must not be altered; got %q", got)
	}
}

func TestNormalizeResponseBody_MetaCSRFTag(t *testing.T) {
	body := `<meta name="csrf-token" content="ZmakeToken123">`
	got := NormalizeResponseBody(body)
	if strings.Contains(got, "ZmakeToken123") {
		t.Errorf("meta csrf token content should be redacted; got %q", got)
	}
}

func TestNormalizeResponseBody_ETagAndLastModified(t *testing.T) {
	body := `ETag: "W/xyz-123-abc"` + "\n" + `Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT`
	got := NormalizeResponseBody(body)
	if strings.Contains(got, `"W/xyz-123-abc"`) {
		t.Errorf("ETag value should be redacted; got %q", got)
	}
	if strings.Contains(got, "21 Oct 2015") {
		t.Errorf("Last-Modified date should be redacted; got %q", got)
	}
	if !strings.Contains(got, "ETag:") || !strings.Contains(got, "Last-Modified:") {
		t.Errorf("header prefixes must be preserved; got %q", got)
	}
}

func TestNormalizeResponseBody_SetCookieValue(t *testing.T) {
	body := `Set-Cookie: session=xyz.random.9; Path=/; HttpOnly`
	got := NormalizeResponseBody(body)
	if strings.Contains(got, "xyz.random.9") {
		t.Errorf("Set-Cookie value should be redacted; got %q", got)
	}
	if !strings.Contains(got, "Set-Cookie: session=") {
		t.Errorf("Set-Cookie name= prefix must be preserved; got %q", got)
	}
	if !strings.Contains(got, "HttpOnly") {
		t.Errorf("trailing attributes must be preserved; got %q", got)
	}
}

func TestNormalizeResponseBody_WebSocketPingIDs(t *testing.T) {
	body := `{"type":"ping","seq":123456789}`
	got := NormalizeResponseBody(body)
	if strings.Contains(got, "123456789") {
		t.Errorf("WebSocket seq id should be redacted; got %q", got)
	}
}

func TestNormalizeResponseBody_TwoIdenticalBodiesConverge(t *testing.T) {
	// Two responses that differ only in token rotation should normalize identically.
	a := `<input name="csrf" value="AAA111"><p>hello 550e8400-e29b-41d4-a716-446655440000</p>`
	b := `<input name="csrf" value="BBB222"><p>hello 550e8400-e29b-41d4-a716-446655440001</p>`
	if NormalizeResponseBody(a) != NormalizeResponseBody(b) {
		t.Errorf("normalized bodies diverge:\nA=%q\nB=%q", NormalizeResponseBody(a), NormalizeResponseBody(b))
	}
}
