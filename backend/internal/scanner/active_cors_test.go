package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunActiveCORSProbe_FindsCredentialedReflection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Naive reflection — the canonical "high severity" misconfig.
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveCORSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 CORS finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-cors-credentialed-reflection" {
		t.Fatalf("expected credentialed-reflection ID, got %q", f.ID)
	}
	if f.Severity != model.SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
}

func TestRunActiveCORSProbe_NoFindingForStrictPolicy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow only a known origin — should not trigger.
		w.Header().Set("Access-Control-Allow-Origin", "https://known.example.com")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveCORSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("strict allow-list should not trigger, got %d findings", len(findings))
	}
}

func TestRunActiveCORSProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveCORSProbe(context.Background(), RunInput{
		Target:  target.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly must disable, got %d findings", len(findings))
	}
}
