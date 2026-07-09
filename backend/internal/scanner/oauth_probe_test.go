package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func newOAuthScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

func TestOAuthProbe_RedirectURIBaselineDifference(t *testing.T) {
	var attackerHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		switch {
		case strings.Contains(redirectURI, "attacker.example.com") || strings.Contains(redirectURI, "evil.attacker.example.com"):
			attackerHits++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"accepted_redirect_uri":"` + redirectURI + `"}`))
		case strings.Contains(redirectURI, "/oauth/callback"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"login":"required"}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		}
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.RunOAuthProbe(context.Background(), srv.URL, newOAuthScope(srv.URL), model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {})
	for _, f := range findings {
		if strings.HasPrefix(f.ID, "oauth-redirect-uri-") {
			if f.EvidenceFields["controlStatus"] == "" {
				t.Fatalf("expected control evidence on redirect finding, got %+v", f.EvidenceFields)
			}
			if f.EvidenceFields["preReport.verifiedBy"] == "" {
				t.Fatalf("expected verifier metadata on redirect finding, got %+v", f.EvidenceFields)
			}
			return
		}
	}
	if attackerHits == 0 {
		t.Fatal("expected mutated redirect_uri requests to be exercised")
	}
	t.Fatalf("expected redirect_uri finding; got: %+v", findings)
}

func TestOAuthProbe_RedirectURISuppressedWhenMatchesBenignBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.RunOAuthProbe(context.Background(), srv.URL, newOAuthScope(srv.URL), model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {})
	for _, f := range findings {
		if strings.HasPrefix(f.ID, "oauth-redirect-uri-") {
			t.Fatalf("unexpected redirect_uri finding when candidate matches benign baseline: %+v", f)
		}
	}
}

func TestOAuthProbe_StateAndPKCESuppressedWhenControlAlsoAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"required"}`))
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.RunOAuthProbe(context.Background(), srv.URL, newOAuthScope(srv.URL), model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {})
	for _, f := range findings {
		if f.ID == "oauth-csrf-no-state" || f.ID == "oauth-pkce-downgrade" {
			t.Fatalf("expected verifier gating to suppress %s when control also accepted; finding=%+v", f.ID, f)
		}
	}
}
