package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestRunReDoSProbe_TimingSpikeDetected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "!") && len(q) > 20 {
			time.Sleep(4200 * time.Millisecond)
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runReDoSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 ReDoS finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.CWE != "CWE-1333" {
		t.Fatalf("expected CWE-1333, got %q", f.CWE)
	}
}

func TestRunReDoSProbe_NoTimingSpikeNoFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runReDoSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when there is no timing spike, got %d: %+v", len(findings), findings)
	}
}

func TestRunReDoSProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL}
	in.Options.PassiveOnly = true
	if got := svc.runReDoSProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

var _ = model.ScanOptions{}
