package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestCollectToolHealth_HTTPMode_NucleiAndZAPConsideredInstalled verifies that
// when USE_HTTP_TOOL_SERVICES=true the nuclei and zap-baseline entries in
// collectToolHealth are considered installed when their sidecar health
// endpoints return HTTP 200 — regardless of whether the binaries exist on the
// backend PATH.
func TestCollectToolHealth_HTTPMode_NucleiAndZAPConsideredInstalled(t *testing.T) {
	// Spin up a minimal HTTP server that always returns 200 to stand in for
	// both the nuclei-service and zap-service health endpoints.
	mockSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockSvc.Close()

	t.Setenv("USE_HTTP_TOOL_SERVICES", "true")
	t.Setenv("NUCLEI_SERVICE_URL", mockSvc.URL)
	t.Setenv("ZAP_SERVICE_URL", mockSvc.URL)
	// Point the binaries at non-existent paths so exec.LookPath cannot find them.
	t.Setenv("NUCLEI_BINARY", "/nonexistent/nuclei-in-http-mode-test")
	t.Setenv("ZAP_BASELINE_BINARY", "/nonexistent/zap-baseline-in-http-mode-test.py")

	health := collectToolHealth()

	for _, item := range health {
		switch item.Name {
		case "nuclei":
			if !item.Installed {
				t.Errorf("nuclei should be considered installed when HTTP service is healthy, got Installed=false")
			}
		case "zap-baseline":
			if !item.Installed {
				t.Errorf("zap-baseline should be considered installed when HTTP service is healthy, got Installed=false")
			}
		}
	}
}

// TestCollectToolHealth_HTTPMode_NucleiAndZAPNotInstalled_WhenServiceDown verifies
// that when USE_HTTP_TOOL_SERVICES=true and the HTTP sidecar service is not
// reachable, the tools are correctly reported as not installed.
func TestCollectToolHealth_HTTPMode_NucleiAndZAPNotInstalled_WhenServiceDown(t *testing.T) {
	t.Setenv("USE_HTTP_TOOL_SERVICES", "true")
	// Port 1 is not a valid listener; connection will be refused immediately.
	t.Setenv("NUCLEI_SERVICE_URL", "http://127.0.0.1:1")
	t.Setenv("ZAP_SERVICE_URL", "http://127.0.0.1:1")
	t.Setenv("NUCLEI_BINARY", "/nonexistent/nuclei")
	t.Setenv("ZAP_BASELINE_BINARY", "/nonexistent/zap-baseline.py")

	health := collectToolHealth()

	for _, item := range health {
		switch item.Name {
		case "nuclei":
			if item.Installed {
				t.Errorf("nuclei should not be installed when HTTP service is unreachable, got Installed=true")
			}
		case "zap-baseline":
			if item.Installed {
				t.Errorf("zap-baseline should not be installed when HTTP service is unreachable, got Installed=true")
			}
		}
	}
}

// TestApplyHealthAwareExecutionGating_HTTPMode_DoesNotDisableIntegrations
// verifies that enabled integrations are NOT disabled by the health gate when
// USE_HTTP_TOOL_SERVICES=true and the sidecar services are healthy, even if
// the tool binaries are absent from the backend PATH.
func TestApplyHealthAwareExecutionGating_HTTPMode_DoesNotDisableIntegrations(t *testing.T) {
	mockSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockSvc.Close()

	t.Setenv("USE_HTTP_TOOL_SERVICES", "true")
	t.Setenv("NUCLEI_SERVICE_URL", mockSvc.URL)
	t.Setenv("ZAP_SERVICE_URL", mockSvc.URL)
	t.Setenv("NUCLEI_BINARY", "/nonexistent/nuclei")
	t.Setenv("ZAP_BASELINE_BINARY", "/nonexistent/zap-baseline.py")

	opts := model.ScanOptions{
		UseNucleiIntegration:      true,
		UseZAPBaselineIntegration: true,
	}

	result, disabled := applyHealthAwareExecutionGating(opts)

	for _, d := range disabled {
		switch d {
		case "nuclei":
			t.Errorf("nuclei was unexpectedly disabled by health gating in HTTP mode")
		case "zap-baseline":
			t.Errorf("zap-baseline was unexpectedly disabled by health gating in HTTP mode")
		}
	}
	if !result.UseNucleiIntegration {
		t.Errorf("UseNucleiIntegration should remain true in HTTP mode with healthy service")
	}
	if !result.UseZAPBaselineIntegration {
		t.Errorf("UseZAPBaselineIntegration should remain true in HTTP mode with healthy service")
	}
}
