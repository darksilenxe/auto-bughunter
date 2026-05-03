package scanner

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestBuildCurlReproducer_BasicGET(t *testing.T) {
	got := buildCurlReproducer("GET", "https://example.com/path?a=1", model.ScanAuthProfile{}, "", "")
	if !strings.HasPrefix(got, "curl -i -sS --max-redirs 0 -X GET ") {
		t.Fatalf("unexpected curl prefix: %q", got)
	}
	if !strings.Contains(got, "'https://example.com/path?a=1'") {
		t.Fatalf("URL not properly quoted: %q", got)
	}
}

func TestBuildCurlReproducer_RedactsSecrets(t *testing.T) {
	got := buildCurlReproducer("GET", "https://example.com/", model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer real-token"},
		Cookies: map[string]string{"session": "secret"},
	}, "", "")
	if strings.Contains(got, "real-token") {
		t.Fatalf("Authorization secret leaked: %q", got)
	}
	if strings.Contains(got, "secret") && !strings.Contains(got, "REDACTED") {
		t.Fatalf("session secret leaked: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("expected REDACTED placeholder, got %q", got)
	}
}

func TestBuildCurlReproducer_PostWithBody(t *testing.T) {
	got := buildCurlReproducer("POST", "https://example.com/api", model.ScanAuthProfile{}, "application/json", `{"a":1}`)
	if !strings.Contains(got, "-H 'Content-Type: application/json'") {
		t.Fatalf("missing content-type header: %q", got)
	}
	if !strings.Contains(got, `--data '{"a":1}'`) {
		t.Fatalf("missing body: %q", got)
	}
}

func TestShellQuote_EscapesSingleQuote(t *testing.T) {
	got := shellQuote(`it's "ok"`)
	if got != `'it'\''s "ok"'` {
		t.Errorf("unexpected quoting: %q", got)
	}
}

func TestIsSensitiveHeaderName(t *testing.T) {
	for _, name := range []string{"Authorization", "Cookie", "X-API-Key", "x-csrf-token"} {
		if !isSensitiveHeaderName(name) {
			t.Errorf("expected %q to be sensitive", name)
		}
	}
	for _, name := range []string{"User-Agent", "Accept", "X-Request-ID"} {
		if isSensitiveHeaderName(name) {
			t.Errorf("did not expect %q to be sensitive", name)
		}
	}
}
