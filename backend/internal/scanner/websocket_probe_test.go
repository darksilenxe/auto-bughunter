package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunWebSocketProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" && strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Upgrade", "websocket")
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	body := `new WebSocket("` + strings.Replace(target.URL, "http://", "ws://", 1) + `/ws")`
	findings := NewService(Config{}).runWebSocketProbe(context.Background(), RunInput{Target: target.URL}, body)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "cswsh-detected" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-1385" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunWebSocketProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	body := `new WebSocket("` + strings.Replace(target.URL, "http://", "ws://", 1) + `/ws")`
	findings := NewService(Config{}).runWebSocketProbe(context.Background(), RunInput{Target: target.URL}, body)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
