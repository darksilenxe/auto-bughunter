package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func TestFilterStateChangingPathsSuppressesUnchangedFallback(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><title>App</title><body>single page app shell</body></html>"))
	}))
	defer srv.Close()

	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	paths := filterStateChangingPaths(context.Background(), srv.Client(), srv.URL, []string{"/admin", "/debug"}, model.ScanAuthProfile{}, scanScope, 2, time.Second)
	if len(paths) != 0 {
		t.Fatalf("expected unchanged fallback paths to be suppressed, got %v", paths)
	}
}

func TestFilterStateChangingPathsKeepsMeaningfulDifferences(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/admin":
			_, _ = w.Write([]byte("<html><title>Admin</title><body>directory index of /admin</body></html>"))
		default:
			_, _ = w.Write([]byte("<html><title>App</title><body>single page app shell</body></html>"))
		}
	}))
	defer srv.Close()

	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	paths := filterStateChangingPaths(context.Background(), srv.Client(), srv.URL, []string{"/admin", "/debug"}, model.ScanAuthProfile{}, scanScope, 2, time.Second)
	if len(paths) != 1 || paths[0] != "/admin" {
		t.Fatalf("expected only the changed path to remain, got %v", paths)
	}
}
