package report

import (
	"encoding/json"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// ─── Item 1: New category profiles ──────────────────────────────────────────

func TestEnrichFinding_NewCategories(t *testing.T) {
	cases := []struct {
		category  string
		wantCWE   string
		wantOWASP string
	}{
		{"sqli", "CWE-89", "A03:2021"},
		{"ssrf", "CWE-918", "A10:2021"},
		{"csrf", "CWE-352", "A01:2021"},
		{"xxe", "CWE-611", "A05:2021"},
		{"ssti", "CWE-94", "A03:2021"},
		{"command-injection", "CWE-78", "A03:2021"},
		{"command_injection", "CWE-78", "A03:2021"},
		{"file-upload", "CWE-434", "A04:2021"},
		{"file_upload", "CWE-434", "A04:2021"},
		{"websocket", "CWE-1385", "A01:2021"},
		{"clickjacking", "CWE-1021", "A05:2021"},
		{"auth", "CWE-287", "A07:2021"},
		{"auth_bypass", "CWE-287", "A07:2021"},
		{"authentication", "CWE-287", "A07:2021"},
		{"headers", "CWE-693", "A05:2021"},
		{"cookies", "CWE-614", "A05:2021"},
		{"prompt-injection", "CWE-1336", "A03:2021"},
		{"race-condition", "CWE-362", "A04:2021"},
		{"open_redirect", "CWE-601", "A01:2021"},
		{"dom-xss", "CWE-79", "A03:2021"},
		{"client-side", "CWE-79", "A03:2021"},
		{"nosql", "CWE-943", "A03:2021"},
		{"ldap", "CWE-90", "A03:2021"},
		{"xpath", "CWE-643", "A03:2021"},
		{"xpath-injection", "CWE-643", "A03:2021"},
		{"ssi", "CWE-97", "A03:2021"},
		{"formula-injection", "CWE-1236", "A03:2021"},
		{"smtp-injection", "CWE-93", "A03:2021"},
		{"vulnerable-dependency", "CWE-1035", "A06:2021"},
		{"jwt", "CWE-347", "A07:2021"},
		{"cors-redirect", "CWE-942", "A05:2021"},
		{"information-disclosure", "CWE-200", "A01:2021"},
	}
	for _, tc := range cases {
		f := EnrichFinding(model.Finding{Category: tc.category})
		if f.CWE != tc.wantCWE {
			t.Errorf("category=%q: CWE want %q got %q", tc.category, tc.wantCWE, f.CWE)
		}
		if !strings.Contains(f.OWASPCategory, tc.wantOWASP) {
			t.Errorf("category=%q: OWASP want substring %q got %q", tc.category, tc.wantOWASP, f.OWASPCategory)
		}
		if f.CVSSScore == 0 {
			t.Errorf("category=%q: expected non-zero CVSSScore", tc.category)
		}
		if f.Impact == "" {
			t.Errorf("category=%q: expected non-empty Impact", tc.category)
		}
	}
}

// ─── Item 1: Reproduction templates for new categories ──────────────────────

func TestReproductionTemplates_NewCategories(t *testing.T) {
	withSteps := []string{
		"sqli", "nosql", "ldap", "xpath", "xpath-injection",
		"ssi", "ssi-injection", "formula-injection", "smtp-injection",
		"ssrf", "xxe", "csrf", "ssti",
		"command-injection", "command_injection",
		"file-upload", "file_upload",
		"dom-xss", "jwt", "headers", "cookies", "clickjacking",
		"auth", "auth_bypass", "authentication", "websocket",
		"prompt-injection", "race-condition", "vulnerable-dependency",
	}
	for _, cat := range withSteps {
		steps := reproductionTemplates(cat)
		if len(steps) == 0 {
			t.Errorf("reproductionTemplates(%q) returned no steps", cat)
		}
	}
}

// ─── Item 2: Stable fingerprint ─────────────────────────────────────────────

func TestEnrichFinding_StableFingerprint(t *testing.T) {
	f := model.Finding{
		Category:          "xss",
		AffectedURL:       "https://example.com/search",
		AffectedParameter: "q",
		EvidenceFields:    map[string]string{"payloadClass": "xss-reflected"},
	}
	enriched := EnrichFinding(f)
	if enriched.StableFingerprint == "" {
		t.Fatal("expected StableFingerprint to be set")
	}
	// Same input must produce same fingerprint.
	enriched2 := EnrichFinding(f)
	if enriched.StableFingerprint != enriched2.StableFingerprint {
		t.Errorf("stable fingerprint not deterministic: %q vs %q", enriched.StableFingerprint, enriched2.StableFingerprint)
	}
	// Different URL must produce different fingerprint.
	f2 := f
	f2.AffectedURL = "https://example.com/other"
	enriched3 := EnrichFinding(f2)
	if enriched.StableFingerprint == enriched3.StableFingerprint {
		t.Error("expected different fingerprint for different URL")
	}
}

func TestEnrichFinding_DoesNotOverwriteExistingFingerprint(t *testing.T) {
	f := model.Finding{
		Category:          "xss",
		StableFingerprint: "custom-fp",
	}
	out := EnrichFinding(f)
	if out.StableFingerprint != "custom-fp" {
		t.Errorf("should not overwrite existing StableFingerprint, got %q", out.StableFingerprint)
	}
}

// ─── Item 3: Contextual severity adjustment ──────────────────────────────────

func TestEnrichFinding_StoredXSSUpgradedToHigh(t *testing.T) {
	f := model.Finding{
		Category:  "xss",
		Severity:  model.SeverityMedium,
		EvidenceFields: map[string]string{"payloadClass": "stored-xss"},
	}
	out := EnrichFinding(f)
	if out.Severity != model.SeverityHigh {
		t.Errorf("stored XSS: expected HIGH severity, got %s", out.Severity)
	}
	if out.CVSSScore < 9.0 {
		t.Errorf("stored XSS: expected CVSSScore >= 9.0, got %.1f", out.CVSSScore)
	}
}

func TestEnrichFinding_UnauthenticatedPRNUpgrade(t *testing.T) {
	f := model.Finding{
		Category:   "access_control",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		CVSSScore:  8.1,
		Exploitability: &model.Exploitability{
			RequiredRole: "none",
		},
	}
	out := EnrichFinding(f)
	if strings.Contains(out.CVSSVector, "/PR:L/") {
		t.Errorf("expected PR:L to be upgraded to PR:N for unauthenticated finding, got %s", out.CVSSVector)
	}
	if out.CVSSScore <= 8.1 {
		t.Errorf("expected CVSSScore to increase for unauthenticated finding, got %.1f", out.CVSSScore)
	}
}

// ─── Item 4: PoC appended as last reproduction step ─────────────────────────

func TestEnrichFinding_PoCAppendedToReproductionSteps(t *testing.T) {
	f := model.Finding{
		Category: "xss",
		PoC:      "curl -s 'https://example.com/?q=<script>alert(1)</script>'",
	}
	out := EnrichFinding(f)
	if len(out.ReproductionSteps) == 0 {
		t.Fatal("expected reproduction steps to be populated")
	}
	last := out.ReproductionSteps[len(out.ReproductionSteps)-1]
	if !strings.Contains(last, f.PoC) {
		t.Errorf("expected PoC to appear in last reproduction step, got %q", last)
	}
}

// ─── Item 7: Time-to-exploit estimate ────────────────────────────────────────

func TestEnrichFinding_TimeToExploit(t *testing.T) {
	cases := []struct {
		sev     model.Severity
		conf    float64
		reachable bool
		want    string
	}{
		{model.SeverityCritical, 0.9, true, "minutes"},
		{model.SeverityHigh, 0.9, true, "minutes"},
		{model.SeverityHigh, 0.5, false, "hours"},
		{model.SeverityMedium, 0.7, true, "hours"},
		{model.SeverityMedium, 0.5, false, "days"},
		{model.SeverityLow, 0.5, false, "days"},
		{model.SeverityInfo, 0.5, false, "weeks"},
	}
	for _, tc := range cases {
		var exploitability *model.Exploitability
		if tc.reachable {
			exploitability = &model.Exploitability{Reachable: true}
		}
		f := model.Finding{
			Category:       "xss",
			Severity:       tc.sev,
			Confidence:     tc.conf,
			Exploitability: exploitability,
		}
		out := EnrichFinding(f)
		if out.TimeToExploit != tc.want {
			t.Errorf("sev=%s conf=%.1f reachable=%v: want TimeToExploit=%q got %q",
				tc.sev, tc.conf, tc.reachable, tc.want, out.TimeToExploit)
		}
	}
}

func TestEnrichFinding_DoesNotOverwriteExistingTimeToExploit(t *testing.T) {
	f := model.Finding{
		Category:      "xss",
		Severity:      model.SeverityCritical,
		TimeToExploit: "custom",
	}
	out := EnrichFinding(f)
	if out.TimeToExploit != "custom" {
		t.Errorf("should not overwrite existing TimeToExploit, got %q", out.TimeToExploit)
	}
}

// ─── Item 8: Business impact narrative ──────────────────────────────────────

func TestEnrichFinding_BusinessImpactNarrative(t *testing.T) {
	cases := []struct {
		category     string
		tags         []string
		wantContains string
	}{
		{"xss", []string{"payment"}, "payment checkout"},
		{"information_disclosure", []string{"pii"}, "PII"},
		{"access_control", []string{"admin"}, "administrative"},
		{"sqli", []string{"pii"}, "PII"},
		{"ssrf", []string{"api"}, "SSRF"},
	}
	for _, tc := range cases {
		f := model.Finding{
			Category:     tc.category,
			BusinessTags: tc.tags,
		}
		out := EnrichFinding(f)
		if !strings.Contains(out.Impact, tc.wantContains) {
			t.Errorf("category=%q tags=%v: impact should contain %q, got: %q",
				tc.category, tc.tags, tc.wantContains, out.Impact)
		}
	}
}

// ─── Item 10: Deduplicated references merge ──────────────────────────────────

func TestEnrichFinding_ReferencesAreMerged(t *testing.T) {
	probeRef := "https://portswigger.net/web-security/sql-injection"
	f := model.Finding{
		Category:   "sqli",
		References: []string{probeRef},
	}
	out := EnrichFinding(f)
	// The probe-supplied reference must be kept.
	foundProbe := false
	// A profile-level reference must also be present.
	foundProfile := false
	for _, r := range out.References {
		if r == probeRef {
			foundProbe = true
		}
		if strings.Contains(r, "owasp.org") || strings.Contains(r, "cwe.mitre.org") {
			foundProfile = true
		}
	}
	if !foundProbe {
		t.Error("probe-supplied reference was lost after merge")
	}
	if !foundProfile {
		t.Error("profile references were not merged in")
	}
	// No duplicates.
	seen := map[string]int{}
	for _, r := range out.References {
		seen[r]++
		if seen[r] > 1 {
			t.Errorf("duplicate reference: %q", r)
		}
	}
}

func TestEnrichFinding_EmptyReferencesFilledFromProfile(t *testing.T) {
	f := model.Finding{Category: "cors"}
	out := EnrichFinding(f)
	if len(out.References) == 0 {
		t.Error("expected references to be populated from category profile")
	}
}

// ─── Item 5: Compliance matrix — GDPR and NIST columns ──────────────────────

func TestBuildComplianceMatrix_IncludesGDPRAndNIST(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQLi", CWE: "CWE-89", Severity: model.SeverityHigh},
		{Title: "Info disclosure", CWE: "CWE-200", Severity: model.SeverityMedium},
		{Title: "SSRF", CWE: "CWE-918", Severity: model.SeverityHigh},
	}
	matrix := BuildComplianceMatrix(findings)
	for _, m := range matrix {
		if m.GDPR == "" {
			t.Errorf("finding %q (CWE %s): expected non-empty GDPR mapping", m.FindingTitle, m.CWE)
		}
		if m.NIST == "" {
			t.Errorf("finding %q (CWE %s): expected non-empty NIST mapping", m.FindingTitle, m.CWE)
		}
	}
}

func TestBuildComplianceMatrix_NewCWEs(t *testing.T) {
	cases := []struct {
		cwe      string
		wantPCI  string
		wantNIST string
	}{
		{"CWE-434", "6.2.4", "SI-3"},
		{"CWE-611", "6.2.4", "SI-10"},
		{"CWE-352", "6.2.4", "SC-8"},
		{"CWE-347", "8.2", "IA-2"},
		{"CWE-1021", "6.4.1", "SC-8"},
		{"CWE-942", "6.4.1", "SC-7"},
		{"CWE-1035", "6.3", "SA-12"},
	}
	for _, tc := range cases {
		pci := pciControl(tc.cwe)
		if !strings.Contains(pci, tc.wantPCI) {
			t.Errorf("pciControl(%q): want substring %q got %q", tc.cwe, tc.wantPCI, pci)
		}
		nist := nistControl(tc.cwe)
		if !strings.Contains(nist, tc.wantNIST) {
			t.Errorf("nistControl(%q): want substring %q got %q", tc.cwe, tc.wantNIST, nist)
		}
	}
}

// ─── Item 9: SARIF enhancements ──────────────────────────────────────────────

func TestRenderSARIF_EnrichedFields(t *testing.T) {
	job := &model.ScanJob{
		ID:     "s1",
		Target: "https://example.com",
		Findings: []model.Finding{
			{
				ID:                "f1",
				Category:          "xss",
				CWE:               "CWE-79",
				OWASPCategory:     "A03:2021 - Injection",
				MITRETechniques:   []string{"T1059.007"},
				Severity:          model.SeverityHigh,
				Title:             "Reflected XSS",
				Description:       "XSS via q parameter",
				Evidence:          "payload reflected",
				Recommendation:    "Encode output",
				AffectedURL:       "https://example.com/search",
				AffectedParameter: "q",
				StableFingerprint: "abc123",
				TimeToExploit:     "minutes",
				ReproductionSteps: []string{"Step 1", "Step 2"},
			},
		},
	}
	raw, err := RenderSARIF(job, model.ReportTemplateOptions{})
	if err != nil {
		t.Fatalf("RenderSARIF error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	sarifStr := string(raw)

	// properties.tags should include CWE, OWASP, and MITRE technique.
	if !strings.Contains(sarifStr, "CWE-79") {
		t.Error("expected CWE-79 in SARIF tags")
	}
	if !strings.Contains(sarifStr, "T1059.007") {
		t.Error("expected MITRE technique T1059.007 in SARIF tags")
	}
	if !strings.Contains(sarifStr, "A03:2021") {
		t.Error("expected OWASP category in SARIF")
	}
	// relatedLocations for the affected parameter.
	if !strings.Contains(sarifStr, "relatedLocations") {
		t.Error("expected relatedLocations in SARIF result")
	}
	if !strings.Contains(sarifStr, "Vulnerable parameter: q") {
		t.Error("expected vulnerable parameter annotation in relatedLocations")
	}
	// fixes from Recommendation.
	if !strings.Contains(sarifStr, "fixes") {
		t.Error("expected fixes in SARIF result")
	}
	if !strings.Contains(sarifStr, "Encode output") {
		t.Error("expected recommendation text in SARIF fixes")
	}
	// stableFingerprint and timeToExploit in properties.
	if !strings.Contains(sarifStr, "stableFingerprint") {
		t.Error("expected stableFingerprint in SARIF result properties")
	}
	if !strings.Contains(sarifStr, "timeToExploit") {
		t.Error("expected timeToExploit in SARIF result properties")
	}
	// help text on the rule.
	if !strings.Contains(sarifStr, `"help"`) {
		t.Error("expected help field on SARIF rule")
	}
}

// ─── Model fields: AttackChainIDs and ChainRole ──────────────────────────────

func TestFinding_AttackChainFields(t *testing.T) {
	f := model.Finding{
		ID:             "f1",
		AttackChainIDs: []string{"chain-1", "chain-2"},
		ChainRole:      "pivot",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var out model.Finding
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(out.AttackChainIDs) != 2 {
		t.Errorf("expected 2 AttackChainIDs, got %d", len(out.AttackChainIDs))
	}
	if out.ChainRole != "pivot" {
		t.Errorf("expected ChainRole=pivot, got %q", out.ChainRole)
	}
}

// ─── Compliance markdown includes GDPR/NIST headers ─────────────────────────

func TestRenderComplianceMarkdown_IncludesGDPRAndNIST(t *testing.T) {
	md := RenderComplianceMarkdown(sampleJobWithCWE(), model.ReportTemplateOptions{})
	if !strings.Contains(md, "GDPR") {
		t.Error("compliance markdown should include GDPR column")
	}
	if !strings.Contains(md, "NIST") {
		t.Error("compliance markdown should include NIST column")
	}
}

func sampleJobWithCWE() *model.ScanJob {
	return &model.ScanJob{
		ID:     "s-cwe",
		Target: "https://example.com",
		Findings: []model.Finding{
			{ID: "f1", Title: "SQLi", CWE: "CWE-89", Category: "injection", Severity: model.SeverityHigh},
		},
	}
}
