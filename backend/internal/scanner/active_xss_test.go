package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunActiveXSSProbe_FindsReflection stands up a target that reflects
// the q parameter unescaped into HTML and expects a single high-severity
// finding.
func TestRunActiveXSSProbe_FindsReflection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Reflect the q value verbatim — the canonical XSS sink.
		_, _ = w.Write([]byte("<html><body>You searched: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")

	if len(findings) != 1 {
		t.Fatalf("expected 1 XSS finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-xss-reflected" || f.Severity != model.SeverityHigh {
		t.Fatalf("unexpected finding shape: %+v", f)
	}
	if f.AffectedParameter == "" {
		t.Fatalf("expected affected parameter to be populated, got empty")
	}
	if f.CWE != "CWE-79" {
		t.Fatalf("expected CWE-79, got %q", f.CWE)
	}
}

// TestRunActiveXSSProbe_NoFindingWhenEncoded ensures the probe does not
// false-positive when the target HTML-encodes the reflected payload.
func TestRunActiveXSSProbe_NoFindingWhenEncoded(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		v := r.URL.Query().Get("q")
		// Minimal HTML encoding of the dangerous chars.
		v = strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
		_, _ = w.Write([]byte("<html><body>You searched: " + v + "</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no finding on encoded reflection, got %d: %+v", len(findings), findings)
	}
}

// TestIsHTMLContextReflection covers the trivial helper.
func TestIsHTMLContextReflection(t *testing.T) {
	if !isHTMLContextReflection("xx"+xssMarker+"yy", xssMarker) {
		t.Fatal("expected reflection match")
	}
	if isHTMLContextReflection("&lt;svg/onload=...&gt;", xssMarker) {
		t.Fatal("encoded form must not match")
	}
	if isHTMLContextReflection("", xssMarker) || isHTMLContextReflection("body", "") {
		t.Fatal("empty inputs must not match")
	}
}

// TestRunActiveXSSProbe_NoFindingForJSONResponse verifies that the probe does
// not raise a false positive when the target reflects the payload into a JSON
// response body. A payload inside JSON is not executed as HTML; reporting it
// as XSS would be a false positive on SPA API endpoints.
func TestRunActiveXSSProbe_NoFindingForJSONResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// JSON body that reflects the query parameter verbatim.
		q := r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`{"query":"` + q + `"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("JSON response: expected 0 findings (not an HTML context), got %d", len(findings))
	}
}
