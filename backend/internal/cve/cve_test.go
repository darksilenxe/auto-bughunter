package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestDiscoverRecentWebCVEs_FiltersDedupesAndPrioritizes(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2026-9999",
						"published": "2026-07-16T00:00:00.000Z",
						"descriptions": [{"lang":"en","value":"Kernel local privilege escalation in scheduler"}],
						"references": [{"url":"https://example.com/cve-2026-9999"}],
						"metrics": {"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","baseScore":7.8}}]}
					}
				},
				{
					"cve": {
						"id": "CVE-2026-1111",
						"published": "2026-07-17T00:00:00.000Z",
						"descriptions": [{"lang":"en","value":"WordPress plugin reflected XSS via unsanitized parameter"}],
						"references": [{"url":"https://example.com/cve-2026-1111"}],
						"weaknesses":[{"description":[{"lang":"en","value":"CWE-79"}]}],
						"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:wordpress:plugin:*:*:*:*:*:*:*:*"}]}]}],
						"metrics": {"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","baseScore":8.2}}]}
					}
				},
				{
					"cve": {
						"id": "cve-2026-1111",
						"published": "2026-07-15T00:00:00.000Z",
						"descriptions": [{"lang":"en","value":"Duplicate entry should be ignored"}]
					}
				},
				{
					"cve": {
						"id": "CVE-2026-2222",
						"published": "2026-07-17T00:00:00.000Z",
						"descriptions": [{"lang":"en","value":"Apache HTTP Server request smuggling vulnerability"}],
						"references": [{"url":"https://example.com/cve-2026-2222"}],
						"weaknesses":[{"description":[{"lang":"en","value":"CWE-444"}]}],
						"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}]}]}],
						"metrics": {"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8}}]}
					}
				}
			]
		}`))
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	findings := []model.Finding{
		{
			ID:       "wappalyzergo-summary",
			Category: "integration",
			Evidence: "technologies=2, top=WordPress,Apache HTTP Server",
		},
		{
			ID:          "already-known",
			Title:       "Known finding",
			Description: "Existing evidence indicates CVE-2026-2222",
		},
	}
	out, err := DiscoverRecentWebCVEs(context.Background(), findings, DiscoveryOptions{
		Client:     srv.Client(),
		BaseURL:    srv.URL,
		Lookback:   7 * 24 * time.Hour,
		MaxResults: 10,
		Now:        func() time.Time { return time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("DiscoverRecentWebCVEs: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected only one new relevant CVE, got %d: %+v", len(out), out)
	}
	if out[0].Record.ID != "CVE-2026-1111" {
		t.Fatalf("expected CVE-2026-1111, got %s", out[0].Record.ID)
	}
	if out[0].Record.CWE != "CWE-79" {
		t.Fatalf("expected CWE-79, got %s", out[0].Record.CWE)
	}
	if out[0].Record.CVSSScore != 8.2 {
		t.Fatalf("expected CVSS 8.2, got %v", out[0].Record.CVSSScore)
	}
	if out[0].Record.PublishedDate == "" {
		t.Fatal("expected published date to be set")
	}
	if !strings.Contains(strings.Join(out[0].MatchedTechnologies, ","), "WordPress") {
		t.Fatalf("expected matched technology WordPress, got %v", out[0].MatchedTechnologies)
	}
}
