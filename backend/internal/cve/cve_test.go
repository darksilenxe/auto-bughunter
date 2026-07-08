package cve

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestDetectFindingCVEs(t *testing.T) {
	f := model.Finding{
		Title:       "Log4Shell RCE detected",
		Description: "The target is vulnerable to cve-2021-44228 (Log4Shell).",
		Evidence:    "X-Api-Version: ${jndi:ldap://127.0.0.1/a}",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		EvidenceFields: map[string]string{
			"nucleiTemplate": "cve-2021-44228",
		},
	}
	got := DetectFindingCVEs(f)
	if len(got) != 1 || got[0] != "CVE-2021-44228" {
		t.Fatalf("expected single deduplicated CVE-2021-44228, got %v", got)
	}
}

func TestDetectFindingCVEsMultiple(t *testing.T) {
	f := model.Finding{
		Description: "Affected by CVE-2022-22965 and also CVE-2014-6271.",
	}
	got := DetectFindingCVEs(f)
	if len(got) != 2 {
		t.Fatalf("expected 2 CVEs, got %v", got)
	}
	if got[0] != "CVE-2014-6271" || got[1] != "CVE-2022-22965" {
		t.Errorf("expected sorted CVE list, got %v", got)
	}
}

func TestDetectFindingCVEsNone(t *testing.T) {
	f := model.Finding{Title: "Reflected XSS", Description: "No CVE here."}
	if got := DetectFindingCVEs(f); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestLookupKnown(t *testing.T) {
	rec, ok := Lookup("cve-2021-44228")
	if !ok {
		t.Fatal("expected known CVE-2021-44228 to be found")
	}
	if rec.CVSSScore != 10.0 {
		t.Errorf("expected CVSS 10.0, got %v", rec.CVSSScore)
	}
	if rec.Source != "offline" {
		t.Errorf("expected source=offline, got %q", rec.Source)
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("CVE-1999-99999"); ok {
		t.Error("expected unknown CVE to not be found")
	}
}
