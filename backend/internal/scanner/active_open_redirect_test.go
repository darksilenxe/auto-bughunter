package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunActiveOpenRedirectProbe_FindsOffHostRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Naively echo the `next` parameter into Location.
		next := r.URL.Query().Get("next")
		if next != "" {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveOpenRedirectProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 open-redirect finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-open-redirect" || f.CWE != "CWE-601" {
		t.Fatalf("unexpected finding shape: %+v", f)
	}
	if f.AffectedParameter == "" {
		t.Fatalf("expected affected parameter populated")
	}
	if f.PoC == "" || !strings.HasPrefix(f.PoC, "curl") {
		t.Fatalf("expected curl reproducer in PoC, got %q", f.PoC)
	}
}

func TestRunActiveOpenRedirectProbe_NoFindingForSameHost(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate destination — only redirect to relative paths.
		next := r.URL.Query().Get("next")
		if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveOpenRedirectProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no finding when destination is validated, got %d: %+v", len(findings), findings)
	}
}

func TestRunActiveOpenRedirectProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("next"))
		w.WriteHeader(http.StatusFound)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveOpenRedirectProbe(context.Background(), RunInput{
		Target:  target.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(findings))
	}
}

func TestIsOpenRedirectLocation(t *testing.T) {
	cases := []struct {
		loc    string
		want   bool
	}{
		{"https://abh-redirect-canary.invalid/path", true},
		{"//abh-redirect-canary.invalid/path", true},
		{"https://example.com/safe", false},
		{"/local/path", false},
		{"", false},
	}
	for _, c := range cases {
		got := isOpenRedirectLocation(c.loc, "abh-redirect-canary.invalid")
		if got != c.want {
			t.Errorf("isOpenRedirectLocation(%q) = %v, want %v", c.loc, got, c.want)
		}
	}
}
