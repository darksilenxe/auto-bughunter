package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunDOMClobberingProbe_ReflectedUnescaped(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><p>You searched for: " + q + "</p></body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runDOMClobberingProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 DOM clobbering finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.ID != "dom-clobbering" {
		t.Fatalf("unexpected finding ID: %q", f.ID)
	}
	if f.CWE != "CWE-79" {
		t.Fatalf("expected CWE-79, got %q", f.CWE)
	}
}

func TestRunDOMClobberingProbe_EscapedNoFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><p>no reflection here</p></body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runDOMClobberingProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when payload is not reflected, got %d: %+v", len(findings), findings)
	}
}

func TestRunDOMClobberingProbe_JSONResponseNoFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"query":"` + q + `"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runDOMClobberingProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-HTML content type, got %d: %+v", len(findings), findings)
	}
}

func TestRunDOMClobberingProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL}
	in.Options.PassiveOnly = true
	if got := svc.runDOMClobberingProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestInjectQueryParam(t *testing.T) {
	got, err := injectQueryParam("https://example.com/search?a=b", "q", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/search?a=b&q=test" {
		t.Fatalf("unexpected URL: %q", got)
	}
	got, err = injectQueryParam(got, "q", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/search?a=b" {
		t.Fatalf("expected param removed, got %q", got)
	}
}

var _ = model.ScanOptions{}
