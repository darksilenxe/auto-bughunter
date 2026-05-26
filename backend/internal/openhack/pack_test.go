package openhack

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestLoadDefaultLoadsExperts(t *testing.T) {
	p, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	if p == nil {
		t.Fatal("LoadDefault returned nil pack")
	}
	experts := p.Experts()
	if len(experts) < 10 {
		t.Fatalf("expected at least 10 experts, got %d", len(experts))
	}
	// Spot-check well-known experts.
	for _, want := range []string{"injection", "broken-access-control", "authentication-failures", "insecure-design"} {
		if p.ExpertByID(want) == nil {
			t.Errorf("missing expert %q", want)
		}
	}
	if proto := p.SharedProtocol(); proto == "" {
		t.Error("SharedProtocol is empty")
	}
	if p.Orchestration("scenario-router") == nil {
		t.Error("missing scenario-router orchestration prompt")
	}
	if p.Orchestration("finding-triage") == nil {
		t.Error("missing finding-triage orchestration prompt")
	}
}

func TestExpertParsedFrontmatter(t *testing.T) {
	p := MustLoadDefault()
	exp := p.ExpertByID("injection")
	if exp == nil {
		t.Fatal("injection expert missing")
	}
	if !strings.Contains(strings.ToLower(exp.Title), "injection") {
		t.Errorf("unexpected title %q", exp.Title)
	}
	if len(exp.RoutingSignals) == 0 {
		t.Error("expected routing signals")
	}
	gotSQL := false
	for _, s := range exp.RoutingSignals {
		if s == "sql" {
			gotSQL = true
			break
		}
	}
	if !gotSQL {
		t.Errorf("expected sql in routing signals, got %v", exp.RoutingSignals)
	}
	if len(exp.Body) < 100 {
		t.Errorf("expected non-trivial body, got %d chars", len(exp.Body))
	}
	if strings.HasPrefix(exp.Body, "---") {
		t.Errorf("body should have frontmatter stripped, got %q…", exp.Body[:min(40, len(exp.Body))])
	}
}

func TestExpertForFindingRoutesByCategory(t *testing.T) {
	p := MustLoadDefault()
	cases := []struct {
		name   string
		hints  FindingHints
		wantID string
	}{
		{
			name:   "sql injection by title",
			hints:  FindingHints{Category: "injection", Title: "SQL injection in id parameter", Evidence: "param=id sql"},
			wantID: "injection",
		},
		{
			name:   "broken access control by CWE",
			hints:  FindingHints{Category: "access_control", Title: "IDOR on profile endpoint", CWE: "CWE-639"},
			wantID: "broken-access-control",
		},
		{
			name:   "ssrf routes to broken access control per openhack mapping",
			hints:  FindingHints{Category: "ssrf", Title: "Server-Side Request Forgery", CWE: "CWE-918"},
			wantID: "broken-access-control",
		},
		{
			name:   "open redirect routes to security misconfiguration",
			hints:  FindingHints{Category: "cors_redirect", Title: "Open redirect via next parameter", Evidence: "redirect"},
			wantID: "security-misconfiguration",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.ExpertForFinding(tc.hints)
			if got == nil {
				t.Fatal("got nil expert")
			}
			if got.ID != tc.wantID {
				t.Errorf("got %q, want %q", got.ID, tc.wantID)
			}
		})
	}
}

func TestExpertForFindingFallbackInsecureDesign(t *testing.T) {
	p := MustLoadDefault()
	got := p.ExpertForFinding(FindingHints{Category: "totally-unknown", Title: "xyzzy"})
	if got == nil {
		t.Fatal("nil expert")
	}
	if got.ID != "insecure-design" {
		t.Errorf("fallback expected insecure-design, got %q", got.ID)
	}
}

func TestHintsFromFinding(t *testing.T) {
	f := model.Finding{Category: "injection", Title: "x", Evidence: "y", CWE: "CWE-89", Severity: model.SeverityHigh}
	h := HintsFromFinding(f)
	if h.Category != "injection" || h.CWE != "CWE-89" || h.Severity != "high" {
		t.Fatalf("unexpected hints %+v", h)
	}
}

func TestSystemPromptForCombinesShared(t *testing.T) {
	p := MustLoadDefault()
	sp := p.SystemPromptFor("finding-triage")
	if sp == "" {
		t.Fatal("empty system prompt")
	}
	if !strings.Contains(sp, "Finding Triage") && !strings.Contains(sp, "finding-triage") {
		t.Errorf("system prompt does not include finding-triage body: %q…", sp[:min(200, len(sp))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
