package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/cve"
	"auto-bughunter/backend/internal/model"
)

func TestCVEResearchAgent_Name(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	if a.Name() != "cve_reverse_engineer" {
		t.Errorf("expected name 'cve_reverse_engineer', got %q", a.Name())
	}
}

func TestCVEResearchAgent_Disabled(t *testing.T) {
	a := NewCVEResearchAgent(false, nil)
	if a.Enabled() {
		t.Error("expected disabled agent to report Enabled()=false")
	}
}

func TestCVEResearchAgent_NoFindings(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	out, err := a.Run(context.Background(), AgentInput{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(out.Findings))
	}
}

func TestCVEResearchAgent_NoTarget(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	out, err := a.Run(context.Background(), AgentInput{
		AllFindings: []model.Finding{{ID: "f1", Title: "Log4Shell", Description: "CVE-2021-44228 detected"}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected zero findings when target is empty, got %d", len(out.Findings))
	}
}

func TestCVEResearchAgent_NoCVEsDetected(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	out, err := a.Run(context.Background(), AgentInput{
		Target:      "https://example.com",
		AllFindings: []model.Finding{{ID: "f1", Title: "Reflected XSS", Description: "no CVE here"}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(out.Findings))
	}
}

// TestCVEResearchAgent_OfflineFallback verifies that with no AI client
// configured, a detected CVE still produces a catalog-grounded finding.
func TestCVEResearchAgent_OfflineFallback(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	input := AgentInput{
		Target: "https://example.com",
		AllFindings: []model.Finding{{
			ID:          "f1",
			Category:    "rce",
			Severity:    model.SeverityCritical,
			Title:       "Log4Shell detected via JNDI probe",
			Description: "The target reflected a JNDI lookup payload consistent with CVE-2021-44228.",
			Evidence:    "X-Api-Version: ${jndi:ldap://127.0.0.1/a}",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
	f := out.Findings[0]
	if f.EvidenceFields["cveId"] != "CVE-2021-44228" {
		t.Errorf("expected cveId evidence field, got %q", f.EvidenceFields["cveId"])
	}
	if f.EvidenceFields["cveAiPowered"] != "false" {
		t.Errorf("expected cveAiPowered=false in offline fallback, got %q", f.EvidenceFields["cveAiPowered"])
	}
	if f.CVSSScore != 10.0 {
		t.Errorf("expected CVSS 10.0 from offline knowledge base, got %v", f.CVSSScore)
	}
	if f.CWE == "" {
		t.Error("expected CWE populated from offline knowledge base")
	}
	if len(f.References) == 0 {
		t.Error("expected references populated")
	}
	if out.Metadata["cves_detected"] != "1" {
		t.Errorf("expected cves_detected=1, got %q", out.Metadata["cves_detected"])
	}
}

// TestCVEResearchAgent_UnknownCVENoAI verifies an unrecognised CVE with no AI
// client still produces a minimal finding rather than being dropped.
func TestCVEResearchAgent_UnknownCVENoAI(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	input := AgentInput{
		Target: "https://example.com",
		AllFindings: []model.Finding{{
			ID:          "f1",
			Title:       "Outdated library",
			Description: "Detected CVE-2099-12345 in vendored library.",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
	if out.Findings[0].Severity != model.SeverityInfo {
		t.Errorf("expected info severity fallback for unknown CVE with no CVSS data, got %q", out.Findings[0].Severity)
	}
}

// TestCVEResearchAgent_PoCGatedByDefault verifies that even with a proposed
// PoC, no live request is fired unless EnableCVEPoCExecution is set.
func TestCVEResearchAgent_PoCGatedByDefault(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := NewCVEResearchAgent(true, nil)
	input := AgentInput{
		Target: srv.URL,
		Options: model.ScanOptions{
			EnableCVEPoCExecution: false,
		},
		AllFindings: []model.Finding{{
			ID:          "f1",
			Title:       "Log4Shell",
			Description: "CVE-2021-44228 detected",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if requests != 0 {
		t.Errorf("expected zero live requests to target server (no AI client so no PoC proposed), got %d", requests)
	}
	if out.Metadata["pocs_executed"] != "0" {
		t.Errorf("expected pocs_executed=0, got %q", out.Metadata["pocs_executed"])
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
}

func TestCVEResearchAgent_EvaluatePoCRejectsCrossHost(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	input := AgentInput{
		Target: "http://1.1.1.1",
		Options: model.ScanOptions{
			EnableCVEPoCExecution: true,
		},
	}
	f := model.Finding{ID: "cve-x"}
	client := &http.Client{}
	updated, executed, confirmed := a.evaluateCVEPoC(context.Background(), client, input, "CVE-2021-44228", ai.CVEPoCRequest{Method: "GET", URL: "http://8.8.8.8/steal"}, &f)
	if executed {
		t.Error("expected PoC targeting a different host to never execute")
	}
	if confirmed {
		t.Error("expected confirmed=false when execution was rejected")
	}
	found := false
	for _, step := range updated.ReproductionSteps {
		if step == "PoC request rejected: proposed host does not match the scan target" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cross-host rejection reproduction step, got %v", updated.ReproductionSteps)
	}
}

func TestCVEResearchAgent_EvaluatePoCRejectsSSRFTarget(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	input := AgentInput{
		Target: "http://127.0.0.1",
		Options: model.ScanOptions{
			EnableCVEPoCExecution: true,
		},
	}
	f := model.Finding{ID: "cve-x"}
	client := &http.Client{}
	_, executed, _ := a.evaluateCVEPoC(context.Background(), client, input, "CVE-2021-44228", ai.CVEPoCRequest{Method: "GET", URL: "http://127.0.0.1/admin"}, &f)
	if executed {
		t.Error("expected PoC targeting a loopback host to be rejected by SSRF guard")
	}
}

func TestCVEResearchAgent_RegisteredInFactory(t *testing.T) {
	f := NewFactory(nil, nil)
	a, err := f.Create("cve_reverse_engineer")
	if err != nil {
		t.Fatalf("expected cve_reverse_engineer agent to be registered in factory: %v", err)
	}
	if a.Name() != "cve_reverse_engineer" {
		t.Errorf("expected name cve_reverse_engineer, got %q", a.Name())
	}
}

func TestCVEResearchAgent_RecentCVEDiscoveryGatedByOption(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	called := false
	a.discoverRecentCVEs = func(ctx context.Context, findings []model.Finding, opts cve.DiscoveryOptions) ([]cve.DiscoveredCVE, error) {
		called = true
		return []cve.DiscoveredCVE{
			{
				Record: cve.Record{
					ID:            "CVE-2026-1111",
					Summary:       "WordPress reflected XSS",
					Source:        "nvd-recent",
					PublishedDate: "2026-07-17T00:00:00Z",
				},
				MatchedTechnologies: []string{"WordPress"},
			},
		}, nil
	}

	input := AgentInput{
		Target: "https://example.com",
		Options: model.ScanOptions{
			UseRecentCVEFeed: false,
		},
		AllFindings: []model.Finding{{
			ID:          "integration",
			Description: "wappalyzergo identified WordPress",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if called {
		t.Fatal("expected recent CVE discovery to be skipped when UseRecentCVEFeed=false")
	}
	if got := out.Metadata["cves_recent_discovered"]; got != "0" {
		t.Fatalf("expected cves_recent_discovered=0, got %q", got)
	}
}

func TestCVEResearchAgent_RecentCVEDiscoveryEmitsInformationalFindings(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	a.discoverRecentCVEs = func(ctx context.Context, findings []model.Finding, opts cve.DiscoveryOptions) ([]cve.DiscoveredCVE, error) {
		return []cve.DiscoveredCVE{
			{
				Record: cve.Record{
					ID:            "CVE-2026-1111",
					Summary:       "WordPress plugin reflected XSS",
					CWE:           "CWE-79",
					CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
					CVSSScore:     8.2,
					References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-1111"},
					Source:        "nvd-recent",
					PublishedDate: "2026-07-17T00:00:00Z",
				},
				MatchedTechnologies: []string{"WordPress"},
			},
		}, nil
	}

	input := AgentInput{
		Target: "https://example.com",
		Options: model.ScanOptions{
			UseRecentCVEFeed: true,
		},
		AllFindings: []model.Finding{{
			ID:          "stack",
			Category:    "integration",
			Description: "wappalyzergo identified WordPress",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := out.Metadata["cves_recent_discovered"]; got != "1" {
		t.Fatalf("expected cves_recent_discovered=1, got %q", got)
	}
	found := false
	for _, f := range out.Findings {
		if f.EvidenceFields["cveId"] == "CVE-2026-1111" && f.Severity == model.SeverityInfo {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected informational recent-CVE finding in output, got %+v", out.Findings)
	}
}

func TestCVEResearchAgent_RecentCVEDiscoveryFailureDoesNotAbortRun(t *testing.T) {
	a := NewCVEResearchAgent(true, nil)
	a.discoverRecentCVEs = func(ctx context.Context, findings []model.Finding, opts cve.DiscoveryOptions) ([]cve.DiscoveredCVE, error) {
		return nil, fmt.Errorf("feed down")
	}
	input := AgentInput{
		Target: "https://example.com",
		Options: model.ScanOptions{
			UseRecentCVEFeed: true,
		},
		AllFindings: []model.Finding{{
			ID:          "f1",
			Title:       "Log4Shell",
			Description: "CVE-2021-44228 detected",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected fallback CVE analysis finding to still be produced, got %d", len(out.Findings))
	}
	if got := out.Metadata["cves_recent_discovered"]; got != "0" {
		t.Fatalf("expected cves_recent_discovered=0 on discovery failure, got %q", got)
	}
}
