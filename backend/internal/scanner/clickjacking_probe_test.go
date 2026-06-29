package scanner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunClickjackingProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	resp, err := http.Get(target.URL)
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runClickjackingProbe(RunInput{Target: target.URL}, resp.Header)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "clickjacking-missing-protection" || findings[0].Severity != model.SeverityMedium || findings[0].CWE != "CWE-1021" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunClickjackingProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	resp, err := http.Get(target.URL)
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runClickjackingProbe(RunInput{Target: target.URL}, resp.Header)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// TestRunClickjackingProbe_NoFindingForNonHTMLResponse verifies that the probe
// does not flag JSON API endpoints for a missing X-Frame-Options header. SPAs
// expose many JSON endpoints that cannot be meaningfully framed.
func TestRunClickjackingProbe_NoFindingForNonHTMLResponse(t *testing.T) {
	for _, ct := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/vnd.api+json",
		"text/plain",
		"application/xml",
	} {
		ct := ct
		t.Run(ct, func(t *testing.T) {
			h := http.Header{}
			h.Set("Content-Type", ct)
			svc := NewService(Config{})
			findings := svc.runClickjackingProbe(RunInput{Target: "http://example.com"}, h)
			if len(findings) != 0 {
				t.Fatalf("Content-Type %q: expected 0 findings for non-HTML response, got %d", ct, len(findings))
			}
		})
	}
}

// TestRunClickjackingProbe_FlagsMissingHeaderWhenContentTypeAbsent verifies
// the conservative fallback: when the Content-Type header is absent the probe
// still reports the missing framing protection.
func TestRunClickjackingProbe_FlagsMissingHeaderWhenContentTypeAbsent(t *testing.T) {
	h := http.Header{}
	// No Content-Type set — conservative path should still flag.
	svc := NewService(Config{})
	findings := svc.runClickjackingProbe(RunInput{Target: "http://example.com"}, h)
	if len(findings) != 1 {
		t.Fatalf("missing Content-Type: expected 1 finding (conservative), got %d", len(findings))
	}
}
