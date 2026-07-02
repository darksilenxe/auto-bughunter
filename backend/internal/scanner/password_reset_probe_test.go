package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func newPasswordResetScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

func TestPasswordResetProbe_TokenDisclosure_RequiresRejectedControl(t *testing.T) {
	const leakedToken = "reset-token-123456"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPost && strings.Contains(string(body), pwResetTestEmail):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"` + leakedToken + `"}`))
		case r.Method == http.MethodPost && strings.Contains(string(body), leakedToken):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"password changed successfully"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid token"}`))
		}
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.runPasswordResetProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{},
		Scope:   newPasswordResetScope(srv.URL),
		Session: NewScanSession(),
	})
	for _, f := range findings {
		if f.ID == "password-reset-token-disclosure" {
			if f.EvidenceFields["controlTokenRejected"] != "true" {
				t.Fatalf("expected control evidence, got %+v", f.EvidenceFields)
			}
			return
		}
	}
	t.Fatalf("expected password-reset-token-disclosure finding; got: %+v", findings)
}

func TestPasswordResetProbe_TokenDisclosure_SuppressedWhenControlAlsoWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPost && strings.Contains(string(body), pwResetTestEmail):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"reset-token-123456"}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "reset"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"password changed successfully"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.runPasswordResetProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{},
		Scope:   newPasswordResetScope(srv.URL),
		Session: NewScanSession(),
	})
	for _, f := range findings {
		if f.ID == "password-reset-token-disclosure" {
			t.Fatalf("unexpected token-disclosure finding when invalid control token also succeeds: %+v", f)
		}
	}
}
