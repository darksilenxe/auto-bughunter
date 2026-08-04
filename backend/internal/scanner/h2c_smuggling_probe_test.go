package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/toolclient"
)

// mockH2CSmugglerServer starts a test server that mimics the h2csmuggler
// sidecar's POST /v1/scan and GET /health endpoints.
func mockH2CSmugglerServer(t *testing.T, resp toolclient.H2CScanResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/scan":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Errorf("mock server encode: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestRunH2CSmugglingProbe_H2CUpgradeAccepted(t *testing.T) {
	srv := mockH2CSmugglerServer(t, toolclient.H2CScanResponse{
		URL:                "http://example.com",
		H2CUpgradeAccepted: true,
		SmuggleAttempted:   true,
		Findings: []toolclient.H2CFinding{
			{
				Type:        "h2c-upgrade-accepted",
				Description: "Server responded with 101 Switching Protocols.",
				Evidence:    map[string]interface{}{"upgrade_status": 101},
			},
		},
	})
	defer srv.Close()

	t.Setenv("H2CSMUGGLER_SERVICE_URL", srv.URL)
	t.Setenv("SIDECAR_AUTH_TOKEN", "")

	svc := NewService(Config{})
	findings := svc.runH2CSmugglingProbe(context.Background(), RunInput{
		Target: "http://example.com",
		Scope:  model.ScanScope{IncludeHosts: []string{"example.com"}},
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "h2c-smuggling" {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Errorf("unexpected severity (expected medium after proof-policy downgrade): %s", findings[0].Severity)
	}
	if findings[0].CWE != "CWE-444" {
		t.Errorf("unexpected CWE: %s", findings[0].CWE)
	}
}

func TestRunH2CSmugglingProbe_SmugglingAnomaly(t *testing.T) {
	srv := mockH2CSmugglerServer(t, toolclient.H2CScanResponse{
		URL:                "http://example.com",
		H2CUpgradeAccepted: true,
		SmuggleAttempted:   true,
		Findings: []toolclient.H2CFinding{
			{
				Type:        "h2c-smuggling-anomaly",
				Description: "Smuggled request returned 200 vs baseline 403.",
				Evidence: map[string]interface{}{
					"baseline_status": 403,
					"anomalous_paths": []interface{}{
						map[string]interface{}{"path": "/../admin", "status": 200},
					},
				},
			},
		},
	})
	defer srv.Close()

	t.Setenv("H2CSMUGGLER_SERVICE_URL", srv.URL)
	t.Setenv("SIDECAR_AUTH_TOKEN", "")

	svc := NewService(Config{})
	findings := svc.runH2CSmugglingProbe(context.Background(), RunInput{
		Target: "http://example.com",
		Scope:  model.ScanScope{IncludeHosts: []string{"example.com"}},
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("expected high severity for smuggling anomaly after proof-policy downgrade, got %s", findings[0].Severity)
	}
}

func TestRunH2CSmugglingProbe_NoFindings(t *testing.T) {
	srv := mockH2CSmugglerServer(t, toolclient.H2CScanResponse{
		URL:                "http://example.com",
		H2CUpgradeAccepted: false,
		SmuggleAttempted:   true,
		Findings:           nil,
	})
	defer srv.Close()

	t.Setenv("H2CSMUGGLER_SERVICE_URL", srv.URL)
	t.Setenv("SIDECAR_AUTH_TOKEN", "")

	svc := NewService(Config{})
	findings := svc.runH2CSmugglingProbe(context.Background(), RunInput{
		Target: "http://example.com",
		Scope:  model.ScanScope{IncludeHosts: []string{"example.com"}},
	})

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestRunH2CSmugglingProbe_OutOfScope(t *testing.T) {
	svc := NewService(Config{})
	findings := svc.runH2CSmugglingProbe(context.Background(), RunInput{
		Target: "http://other.com",
		Scope:  model.ScanScope{IncludeHosts: []string{"example.com"}},
	})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for out-of-scope target, got %d", len(findings))
	}
}

func TestRunH2CSmugglingProbe_ServiceUnavailable(t *testing.T) {
	// Point at a non-existent server
	t.Setenv("H2CSMUGGLER_SERVICE_URL", "http://127.0.0.1:19998")
	t.Setenv("SIDECAR_AUTH_TOKEN", "")

	svc := NewService(Config{})
	findings := svc.runH2CSmugglingProbe(context.Background(), RunInput{
		Target: "http://example.com",
		Scope:  model.ScanScope{IncludeHosts: []string{"example.com"}},
	})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when service unavailable, got %d", len(findings))
	}
}
