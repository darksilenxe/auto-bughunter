package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func TestProbeMultipleSuppressesSPAFallbackResponses(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>App</title></head><body><div id="root"></div><script src="/assets/app.js"></script></body></html>`))
	}))
	defer srv.Close()

	ws := newWordlistTestScanner(srv.Client())
	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	profile, _, baseline := ws.captureEnumerationContext(context.Background(), srv.URL, model.ScanAuthProfile{}, scanScope)
	results, summary := ws.probeMultiple(context.Background(), srv.URL, []string{"/admin", "/debug"}, model.ScanAuthProfile{}, scanScope, wordlistScanKindDirectory, profile, baseline)
	if len(results) != 0 {
		t.Fatalf("expected no discoveries, got %+v", results)
	}
	if summary.SuppressedCount != 2 {
		t.Fatalf("expected 2 suppressed SPA fallbacks, got %d (%v)", summary.SuppressedCount, summary.Suppressed)
	}
	if joined := strings.Join(summary.Suppressed, " "); !strings.Contains(joined, "SPA shell fallback") {
		t.Fatalf("expected SPA fallback suppression reason, got %q", joined)
	}
}

func TestProbeMultipleSuppressesCustomBrandedFallback(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><head><title>Brand Home</title></head><body>Welcome</body></html>`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>Brand Missing</title></head><body>Sorry, page could not be found.</body></html>`))
		}
	}))
	defer srv.Close()

	ws := newWordlistTestScanner(srv.Client())
	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	profile, _, baseline := ws.captureEnumerationContext(context.Background(), srv.URL, model.ScanAuthProfile{}, scanScope)
	results, summary := ws.probeMultiple(context.Background(), srv.URL, []string{"/admin", "/debug"}, model.ScanAuthProfile{}, scanScope, wordlistScanKindDirectory, profile, baseline)
	if len(results) != 0 {
		t.Fatalf("expected no discoveries, got %+v", results)
	}
	if summary.SuppressedCount != 2 {
		t.Fatalf("expected 2 suppressed custom fallbacks, got %d", summary.SuppressedCount)
	}
	if joined := strings.Join(summary.Suppressed, " "); !strings.Contains(joined, "404-like response") && !strings.Contains(joined, "baseline fallback") {
		t.Fatalf("expected fallback suppression reason, got %q", joined)
	}
}

func TestProbeMultipleSuppressesReflectedFallbackResponses(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><head><title>Home</title></head><body>Welcome</body></html>`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>Route ` + r.URL.Path + `</title></head><body>Generic route shell for ` + r.URL.Path + `</body></html>`))
		}
	}))
	defer srv.Close()

	ws := newWordlistTestScanner(srv.Client())
	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	profile, _, baseline := ws.captureEnumerationContext(context.Background(), srv.URL, model.ScanAuthProfile{}, scanScope)
	results, summary := ws.probeMultiple(context.Background(), srv.URL, []string{"/admin", "/debug"}, model.ScanAuthProfile{}, scanScope, wordlistScanKindDirectory, profile, baseline)
	if len(results) != 0 {
		t.Fatalf("expected no discoveries, got %+v", results)
	}
	if summary.SuppressedCount != 2 {
		t.Fatalf("expected 2 suppressed reflected fallbacks, got %d (%v)", summary.SuppressedCount, summary.Suppressed)
	}
	if joined := strings.Join(summary.Suppressed, " "); !strings.Contains(joined, "reflects requested path in fallback template") {
		t.Fatalf("expected reflected fallback suppression reason, got %q", joined)
	}
}

func TestProbeMultipleKeepsLoginWallDiscoveries(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><head><title>Home</title></head><body>Welcome</body></html>`))
		case "/login":
			_, _ = w.Write([]byte(`<html><head><title>Login</title></head><body><form><input type="password" name="password"></form></body></html>`))
		case "/admin":
			http.Redirect(w, r, "/login", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`not found`))
		}
	}))
	defer srv.Close()

	ws := newWordlistTestScanner(srv.Client())
	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	profile, _, baseline := ws.captureEnumerationContext(context.Background(), srv.URL, model.ScanAuthProfile{}, scanScope)
	results, summary := ws.probeMultiple(context.Background(), srv.URL, []string{"/admin", "/debug"}, model.ScanAuthProfile{}, scanScope, wordlistScanKindDirectory, profile, baseline)
	if len(results) != 1 {
		t.Fatalf("expected 1 discovery, got %+v", results)
	}
	if results[0].Path != "/admin" || results[0].ResponseClass != responseClassAuthWall {
		t.Fatalf("expected auth-wall discovery for /admin, got %+v", results[0])
	}
	if summary.SuppressedCount != 1 {
		t.Fatalf("expected one suppressed fallback, got %d", summary.SuppressedCount)
	}
}

func TestProbeMultipleKeepsAPIErrorEnvelopeDiscoveries(t *testing.T) {
	t.Parallel()

	type apiEnvelope struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Status  int    `json:"status"`
		Path    string `json:"path"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Powered-By", "Express")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{"service":"api"}`))
		case "/api/users":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(apiEnvelope{Error: "Unauthorized", Message: "token required", Status: http.StatusUnauthorized, Path: r.URL.Path})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(apiEnvelope{Error: "Not Found", Message: "missing route", Status: http.StatusNotFound, Path: r.URL.Path})
		}
	}))
	defer srv.Close()

	ws := newWordlistTestScanner(srv.Client())
	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	profile, _, baseline := ws.captureEnumerationContext(context.Background(), srv.URL, model.ScanAuthProfile{}, scanScope)
	results, summary := ws.probeMultiple(context.Background(), srv.URL, []string{"/api/users", "/api/missing"}, model.ScanAuthProfile{}, scanScope, wordlistScanKindAPI, profile, baseline)
	if len(results) != 1 {
		t.Fatalf("expected one API discovery, got %+v", results)
	}
	if results[0].Path != "/api/users" || results[0].ResponseClass != responseClassAPIErrorEnvelope {
		t.Fatalf("expected API error-envelope discovery, got %+v", results[0])
	}
	if profile.Name != "express" {
		t.Fatalf("expected express profile from X-Powered-By, got %+v", profile)
	}
	if summary.SuppressedCount != 1 {
		t.Fatalf("expected one suppressed API fallback, got %d", summary.SuppressedCount)
	}
}

func TestProbeMultipleKeepsDistinctReflectedRouteDiscoveries(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><head><title>Home</title></head><body>Welcome</body></html>`))
		case "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>Console /admin</title></head><body>Admin console for /admin</body></html>`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>Route ` + r.URL.Path + `</title></head><body>Generic route shell for ` + r.URL.Path + `</body></html>`))
		}
	}))
	defer srv.Close()

	ws := newWordlistTestScanner(srv.Client())
	scanScope := scope.Normalize(srv.URL, model.ScanScope{})
	profile, _, baseline := ws.captureEnumerationContext(context.Background(), srv.URL, model.ScanAuthProfile{}, scanScope)
	results, summary := ws.probeMultiple(context.Background(), srv.URL, []string{"/admin", "/debug"}, model.ScanAuthProfile{}, scanScope, wordlistScanKindDirectory, profile, baseline)
	if len(results) != 1 {
		t.Fatalf("expected one discovery, got %+v", results)
	}
	if results[0].Path != "/admin" || results[0].ResponseClass != responseClassTrueContent {
		t.Fatalf("expected true-content discovery for /admin, got %+v", results[0])
	}
	if summary.SuppressedCount != 1 {
		t.Fatalf("expected one suppressed reflected fallback, got %d (%v)", summary.SuppressedCount, summary.Suppressed)
	}
}

func TestScanFunctionsEmitSeedRuntimeEndpointsForGenuineDiscoveries(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Home</title></head><body>Welcome</body></html>`))
		case "/admin":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Admin</title></head><body>directory index of /admin</body></html>`))
		case "/api/users":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users":[{"id":1}]}`))
		default:
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`not found`))
		}
	}))
	defer srv.Close()

	ws := newWordlistTestScanner(srv.Client())
	scanScope := scope.Normalize(srv.URL, model.ScanScope{})

	directoryFindings := buildWordlistFindings(
		"wordlist-directories",
		"directory",
		[]wordlistProbeResult{{Path: "/admin", URL: srv.URL + "/admin", Status: http.StatusOK, Score: 5, ResponseClass: responseClassTrueContent, Reason: "content differs from framework baseline"}},
		wordlistProbeSummary{},
		srv.URL,
		"review",
		"fallback",
	)
	if len(directoryFindings) != 1 {
		t.Fatalf("expected one synthesized directory finding, got %+v", directoryFindings)
	}
	if got := directoryFindings[0].EvidenceFields["seedRuntimeEndpoints"]; !strings.Contains(got, srv.URL+"/admin") {
		t.Fatalf("expected seedRuntimeEndpoints to include /admin, got %q", got)
	}

	apiFindings := ws.ScanAPIEndpoints(context.Background(), srv.URL, model.ScanAuthProfile{}, scanScope)
	if len(apiFindings) == 0 {
		t.Fatal("expected API finding")
	}
	if got := apiFindings[0].EvidenceFields["seedRuntimeEndpoints"]; !strings.Contains(got, srv.URL+"/api/users") {
		t.Fatalf("expected seedRuntimeEndpoints to include /api/users, got %q", got)
	}
	if apiFindings[0].EvidenceFields["acceptedCount"] == "0" {
		t.Fatalf("expected acceptedCount to be non-zero, got %+v", apiFindings[0].EvidenceFields)
	}
}

func newWordlistTestScanner(client *http.Client) *WordlistScanner {
	ws := NewWordlistScanner(4, time.Second)
	ws.httpClient = client
	return ws
}
