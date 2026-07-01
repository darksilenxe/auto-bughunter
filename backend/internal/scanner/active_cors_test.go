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

// TestRunActiveCORSProbe_NoFindingWhenBaselineAlreadySendsACAO verifies that
// the probe does not flag an endpoint when the server returns
// Access-Control-Allow-Origin unconditionally (without inspecting the Origin
// header). This is an intentional open CORS policy, not a reflection attack.
func TestRunActiveCORSProbe_NoFindingWhenBaselineAlreadySendsACAO(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return the same ACAO regardless of whether Origin was sent.
		w.Header().Set("Access-Control-Allow-Origin", "https://abh-cors-canary.invalid")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveCORSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("unconditional ACAO (not reflection): expected 0 findings, got %d", len(findings))
	}
}

// TestRunActiveCORSProbe_DowngradesNonCredentialedJSONAPIToInfo verifies that
// non-credentialed CORS reflection on a JSON API endpoint is downgraded to
// Info severity. SPA backends that serve Bearer-token-authenticated JSON APIs
// and happen to reflect the Origin header without credentials are much lower
// impact than HTML endpoints with cookies.
func TestRunActiveCORSProbe_DowngradesNonCredentialedJSONAPIToInfo(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// No Access-Control-Allow-Credentials header.
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveCORSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (downgraded), got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityInfo {
		t.Fatalf("expected Info severity for non-credentialed JSON API CORS, got %s", f.Severity)
	}
	if f.ID != "active-cors-json-api-origin-reflected" {
		t.Fatalf("expected json-api finding ID, got %q", f.ID)
	}
}

// TestRunActiveCORSProbe_EmitsPreReportVerifierStamps verifies that the
// credentialed reflection path routes through SubmitVerifiedFinding and
// attaches the shared verifier evidence fields (Phase 1 four-control
// migration).
func TestRunActiveCORSProbe_EmitsPreReportVerifierStamps(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if got := f.EvidenceFields["preReport.verified"]; got != "true" {
		t.Fatalf("expected preReport.verified=true, got %q", got)
	}
	if got := f.EvidenceFields["preReport.verifiedBy"]; got != "active-cors@v1" {
		t.Fatalf("expected preReport.verifiedBy=active-cors@v1, got %q", got)
	}
	if got := f.EvidenceFields["responseShape"]; got == "" {
		t.Fatalf("expected responseShape to be set, got empty")
	}
	// Category label must be preserved on the emitted finding even though
	// the verifier evaluated the "cors" canonical category.
	if f.Category != "cors_redirect" {
		t.Fatalf("expected category cors_redirect on emitted finding, got %q", f.Category)
	}
}
