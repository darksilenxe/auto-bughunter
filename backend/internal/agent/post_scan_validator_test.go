package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// xssTestMarker is the literal payload that scanner.verifyXSSHypothesis looks
// for in the response body.  Tests that need confirmation must echo it back.
const xssTestMarker = `"><svg/onload=abh_xss_7f9e2()><!--abh_xss_7f9e2-->`

// newTestScanService returns a scanner.Service suitable for unit tests.
// No external binaries or sidecars are required because only
// RunHypothesisVerification is exercised.
func newTestScanService() *scanner.Service {
	return scanner.NewService(scanner.Config{})
}

// TestPostScanValidatorAgent_Name verifies the agent's registered name.
func TestPostScanValidatorAgent_Name(t *testing.T) {
	a := NewPostScanValidatorAgent(nil, nil, true)
	if a.Name() != "post_scan_validator" {
		t.Errorf("Name() = %q, want post_scan_validator", a.Name())
	}
}

// TestPostScanValidatorAgent_Disabled verifies Enabled() reflects the flag.
func TestPostScanValidatorAgent_Disabled(t *testing.T) {
	a := NewPostScanValidatorAgent(nil, nil, false)
	if a.Enabled() {
		t.Error("expected disabled agent to report Enabled()=false")
	}
}

// TestPostScanValidatorAgent_SkippedWhenOptionOff verifies the agent is a
// no-op when UsePostScanValidation is false (the default).
func TestPostScanValidatorAgent_SkippedWhenOptionOff(t *testing.T) {
	a := NewPostScanValidatorAgent(newTestScanService(), nil, true)
	out, err := a.Run(context.Background(), AgentInput{
		Target:  "http://127.0.0.1",
		Options: model.ScanOptions{UsePostScanValidation: false},
		AllFindings: []model.Finding{
			{ID: "f1", Category: "xss", Confidence: 0.4, AffectedURL: "http://127.0.0.1/search"},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected 0 findings when disabled, got %d", len(out.Findings))
	}
	if !strings.Contains(out.DebugNotes, "UsePostScanValidation is false") {
		t.Errorf("expected skip note in DebugNotes, got %q", out.DebugNotes)
	}
}

// TestPostScanValidatorAgent_SkippedWhenNoScanService verifies graceful
// degradation when the scanService dependency is absent.
func TestPostScanValidatorAgent_SkippedWhenNoScanService(t *testing.T) {
	a := NewPostScanValidatorAgent(nil, nil, true)
	out, err := a.Run(context.Background(), AgentInput{
		Target:  "http://127.0.0.1",
		Options: model.ScanOptions{UsePostScanValidation: true},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected 0 findings when scanService is nil, got %d", len(out.Findings))
	}
}

// TestPostScanValidatorAgent_PassA_PassiveOnly verifies that Pass A (active
// re-probes) is entirely skipped in passive-only mode.
func TestPostScanValidatorAgent_PassA_PassiveOnly(t *testing.T) {
	a := NewPostScanValidatorAgent(newTestScanService(), nil, true)
	out, err := a.Run(context.Background(), AgentInput{
		Target: "http://127.0.0.1",
		Options: model.ScanOptions{
			UsePostScanValidation: true,
			PassiveOnly:           true,
		},
		AllFindings: []model.Finding{
			{ID: "f1", Category: "xss", Confidence: 0.40, AffectedURL: "http://127.0.0.1/search"},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Pass A skipped → no re-test annotations; Pass B skipped because
	// PassiveOnly; total findings should be 0.
	if len(out.Findings) != 0 {
		t.Errorf("expected 0 findings in passive-only mode, got %d", len(out.Findings))
	}
	if out.Metadata["fp_retest_total"] != "0" {
		t.Errorf("fp_retest_total = %q, want 0", out.Metadata["fp_retest_total"])
	}
}

// TestPostScanValidatorAgent_PassA_NotConfirmed verifies that when the re-probe
// returns no confirming signal, the finding is annotated not-confirmed and its
// confidence is reduced.
func TestPostScanValidatorAgent_PassA_NotConfirmed(t *testing.T) {
	// Test server returns a benign 200 response — no XSS marker echoed back.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, world!")
	}))
	defer srv.Close()

	svc := newTestScanService()
	a := NewPostScanValidatorAgent(svc, nil, true)

	const origConf = 0.50
	out, err := a.Run(context.Background(), AgentInput{
		Target: srv.URL,
		Options: model.ScanOptions{
			UsePostScanValidation: true,
		},
		AllFindings: []model.Finding{
			{
				ID:          "f1",
				Category:    "xss",
				Confidence:  origConf,
				AffectedURL: srv.URL + "/search",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(out.Findings) == 0 {
		t.Fatal("expected at least one annotated finding from Pass A")
	}
	f := out.Findings[0]
	if f.EvidenceFields["retestResult"] != "not-confirmed" {
		t.Errorf("retestResult = %q, want not-confirmed", f.EvidenceFields["retestResult"])
	}
	if f.Confidence >= origConf {
		t.Errorf("Confidence = %.2f, want < %.2f (reduced on not-confirmed)", f.Confidence, origConf)
	}
	if out.Metadata["fp_retest_unconfirmed"] != "1" {
		t.Errorf("fp_retest_unconfirmed = %q, want 1", out.Metadata["fp_retest_unconfirmed"])
	}
	if out.Metadata["fp_retest_confirmed"] != "0" {
		t.Errorf("fp_retest_confirmed = %q, want 0", out.Metadata["fp_retest_confirmed"])
	}
}

// TestPostScanValidatorAgent_PassA_Confirmed verifies that when the re-probe
// confirms the finding, its retestResult is set to "confirmed" and confidence
// is raised to at least 0.80.
func TestPostScanValidatorAgent_PassA_Confirmed(t *testing.T) {
	// Test server echoes the q parameter back verbatim so the XSS oracle
	// detects the marker and returns a finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html>%s</html>", q)
	}))
	defer srv.Close()

	svc := newTestScanService()
	a := NewPostScanValidatorAgent(svc, nil, true)

	const origConf = 0.50
	out, err := a.Run(context.Background(), AgentInput{
		Target: srv.URL,
		Options: model.ScanOptions{
			UsePostScanValidation: true,
		},
		AllFindings: []model.Finding{
			{
				ID:               "f1",
				Category:         "xss",
				Confidence:       origConf,
				AffectedURL:      srv.URL,
				AffectedParameter: "q",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(out.Findings) == 0 {
		t.Fatal("expected at least one annotated finding from Pass A")
	}
	f := out.Findings[0]
	if f.EvidenceFields["retestResult"] != "confirmed" {
		t.Errorf("retestResult = %q, want confirmed", f.EvidenceFields["retestResult"])
	}
	if f.Confidence < 0.80 {
		t.Errorf("Confidence = %.2f, want >= 0.80 on confirmed retest", f.Confidence)
	}
	if out.Metadata["fp_retest_confirmed"] != "1" {
		t.Errorf("fp_retest_confirmed = %q, want 1", out.Metadata["fp_retest_confirmed"])
	}
}

// TestPostScanValidatorAgent_PassB_UnprobedEndpoint verifies that Pass B
// emits at least one finding when an un-probed endpoint is in
// SeedRuntimeEndpoints and the server echoes back the XSS marker.
func TestPostScanValidatorAgent_PassB_UnprobedEndpoint(t *testing.T) {
	// Server echoes back query params → XSS oracle confirms.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html>%s</html>", q)
	}))
	defer srv.Close()

	svc := newTestScanService()
	a := NewPostScanValidatorAgent(svc, nil, true)

	unprobedEP := srv.URL + "/api/v1/search"

	out, err := a.Run(context.Background(), AgentInput{
		Target: srv.URL,
		Options: model.ScanOptions{
			UsePostScanValidation: true,
			SeedRuntimeEndpoints:  []string{unprobedEP},
		},
		// No existing finding covers the un-probed endpoint.
		AllFindings: []model.Finding{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Pass B should have found at least one new finding.
	fnNew := 0
	for _, f := range out.Findings {
		if f.EvidenceFields["sweepEndpoint"] == unprobedEP {
			fnNew++
		}
	}
	if fnNew == 0 {
		t.Errorf("expected at least one Pass B finding for the un-probed endpoint, got none (total=%d)", len(out.Findings))
	}
}

// TestPostScanValidatorAgent_PassB_SkippedWhenCovered verifies that Pass B
// does not re-probe endpoints already covered by an existing finding.
func TestPostScanValidatorAgent_PassB_SkippedWhenCovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html>%s</html>", q)
	}))
	defer srv.Close()

	svc := newTestScanService()
	a := NewPostScanValidatorAgent(svc, nil, true)

	// The only seed endpoint is already covered by an existing finding.
	coveredEP := srv.URL + "/api/v1/search"
	out, err := a.Run(context.Background(), AgentInput{
		Target: srv.URL,
		Options: model.ScanOptions{
			UsePostScanValidation: true,
			SeedRuntimeEndpoints:  []string{coveredEP},
		},
		AllFindings: []model.Finding{
			// Existing finding covers the seed endpoint (high confidence so
			// Pass A won't retest it).
			{
				ID:          "existing-1",
				Category:    "xss",
				Confidence:  0.95,
				AffectedURL: coveredEP,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Pass B should produce no findings because the only endpoint is covered.
	fnNew := 0
	for _, f := range out.Findings {
		if f.EvidenceFields["sweepEndpoint"] == coveredEP {
			fnNew++
		}
	}
	if fnNew > 0 {
		t.Errorf("expected 0 Pass B findings for already-covered endpoint, got %d", fnNew)
	}
}

// TestPostScanValidatorAgent_CtxCancellation verifies that the agent exits
// cleanly and returns a context error when the context is cancelled mid-run.
func TestPostScanValidatorAgent_CtxCancellation(t *testing.T) {
	// Slow server: blocks until the client disconnects.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	svc := newTestScanService()
	a := NewPostScanValidatorAgent(svc, nil, true)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately before any network call can complete.
	cancel()

	_, err := a.Run(ctx, AgentInput{
		Target: srv.URL,
		Options: model.ScanOptions{
			UsePostScanValidation: true,
		},
		AllFindings: []model.Finding{
			{ID: "f1", Category: "xss", Confidence: 0.4, AffectedURL: srv.URL + "/search"},
		},
	})
	// We expect either a nil error (agent exited early before issuing any
	// request) or the context cancellation error — no panic in either case.
	if err != nil && err != context.Canceled {
		t.Errorf("unexpected error: %v (want nil or context.Canceled)", err)
	}
}

// TestPostScanValidatorAgent_EvidenceTierTriggersRetest verifies that a
// finding with a weak EvidenceQualityTier (but confidence ≥ 0.65) still
// qualifies for Pass A re-testing.
func TestPostScanValidatorAgent_EvidenceTierTriggersRetest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "clean response")
	}))
	defer srv.Close()

	svc := newTestScanService()
	a := NewPostScanValidatorAgent(svc, nil, true)

	out, err := a.Run(context.Background(), AgentInput{
		Target: srv.URL,
		Options: model.ScanOptions{
			UsePostScanValidation: true,
		},
		AllFindings: []model.Finding{
			{
				ID:                  "f1",
				Category:            "xss",
				Confidence:          0.70, // above threshold but tier is weak
				EvidenceQualityTier: "speculative",
				AffectedURL:         srv.URL + "/form",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Metadata["fp_retest_total"] != "1" {
		t.Errorf("fp_retest_total = %q, want 1 (speculative tier should trigger retest)", out.Metadata["fp_retest_total"])
	}
}
