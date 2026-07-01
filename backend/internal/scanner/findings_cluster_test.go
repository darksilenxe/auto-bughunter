package scanner

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":                                       "",
		"https://x.test/users/42/posts/7":        "/users/{id}/posts/{id}",
		"https://x.test/Users/99/Posts/12":       "/users/{id}/posts/{id}",
		"https://x.test/api/v1/orders/abc123def456789012/items": "/api/v1/orders/{id}/items",
		"https://x.test/":                        "/",
		"https://x.test":                         "/",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Fatalf("normalizePath(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestClusterFindings_FoldsDuplicates(t *testing.T) {
	ResetClusterMetrics()
	in := []model.Finding{
		{ID: "a", Category: "xss", Severity: model.SeverityMedium, AffectedURL: "https://x.test/users/1/profile", AffectedParameter: "q", Evidence: "reflected marker"},
		{ID: "b", Category: "xss", Severity: model.SeverityHigh, AffectedURL: "https://x.test/users/2/profile", AffectedParameter: "q", Evidence: "reflected marker"},
		{ID: "c", Category: "xss", Severity: model.SeverityLow, AffectedURL: "https://x.test/users/3/profile", AffectedParameter: "q", Evidence: "reflected marker"},
		{ID: "d", Category: "sqli", Severity: model.SeverityHigh, AffectedURL: "https://x.test/search", AffectedParameter: "q", Evidence: "sql error"},
	}
	out := ClusterFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 clusters, got %d: %+v", len(out), out)
	}
	// Highest-severity finding "b" should be survivor for the xss cluster.
	var xss model.Finding
	for _, f := range out {
		if f.Category == "xss" {
			xss = f
		}
	}
	if xss.ID != "b" {
		t.Fatalf("expected xss survivor to be b (highest severity), got %s", xss.ID)
	}
	if xss.EvidenceFields["clusterSize"] != "3" {
		t.Fatalf("expected clusterSize=3, got %q", xss.EvidenceFields["clusterSize"])
	}
	if !strings.Contains(xss.EvidenceFields["clusterSiblings"], "a") ||
		!strings.Contains(xss.EvidenceFields["clusterSiblings"], "c") {
		t.Fatalf("expected clusterSiblings to include a and c, got %q", xss.EvidenceFields["clusterSiblings"])
	}
	if xss.EvidenceFields["clusterId"] == "" {
		t.Fatal("expected clusterId to be set")
	}
	m := GetClusterMetrics()
	if m.TotalIn != 4 || m.TotalOut != 2 || m.Clustered != 2 {
		t.Fatalf("metrics wrong: %+v", m)
	}
	if m.Ratio != 0.5 {
		t.Fatalf("ratio=%v want 0.5", m.Ratio)
	}
}

func TestClusterFindings_DifferentCategoriesNotFolded(t *testing.T) {
	ResetClusterMetrics()
	in := []model.Finding{
		{ID: "a", Category: "xss", Severity: model.SeverityHigh, AffectedURL: "https://x.test/a", AffectedParameter: "q", Evidence: "x"},
		{ID: "b", Category: "sqli", Severity: model.SeverityHigh, AffectedURL: "https://x.test/a", AffectedParameter: "q", Evidence: "x"},
	}
	out := ClusterFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
}

func TestClusterFindings_EvidenceHashStripsTokens(t *testing.T) {
	ResetClusterMetrics()
	in := []model.Finding{
		{ID: "a", Category: "leak", Severity: model.SeverityMedium, AffectedURL: "https://x.test/x", AffectedParameter: "q",
			Evidence: "trace-id: 550e8400-e29b-41d4-a716-446655440000 body=leak"},
		{ID: "b", Category: "leak", Severity: model.SeverityMedium, AffectedURL: "https://x.test/x", AffectedParameter: "q",
			Evidence: "trace-id: 6ba7b810-9dad-11d1-80b4-00c04fd430c8 body=leak"},
	}
	out := ClusterFindings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 cluster (tokens stripped), got %d", len(out))
	}
	if out[0].EvidenceFields["clusterSize"] != "2" {
		t.Fatalf("expected clusterSize=2, got %q", out[0].EvidenceFields["clusterSize"])
	}
}

func TestClusterFindings_PreservesOrdering(t *testing.T) {
	ResetClusterMetrics()
	in := []model.Finding{
		{ID: "a", Category: "x", Severity: model.SeverityLow, AffectedURL: "https://x.test/1", Evidence: "1"},
		{ID: "b", Category: "y", Severity: model.SeverityLow, AffectedURL: "https://x.test/2", Evidence: "2"},
		{ID: "c", Category: "x", Severity: model.SeverityLow, AffectedURL: "https://x.test/1", Evidence: "1"},
	}
	out := ClusterFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].ID != "a" || out[1].ID != "b" {
		t.Fatalf("ordering broken: got %s,%s", out[0].ID, out[1].ID)
	}
}

func TestClusterFindings_EmptyPassThrough(t *testing.T) {
	if got := ClusterFindings(nil); got != nil {
		t.Fatalf("expected nil pass-through, got %+v", got)
	}
	if got := ClusterFindings([]model.Finding{}); len(got) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}

func TestStrongerOrdering(t *testing.T) {
	hi := model.Finding{ID: "a", Severity: model.SeverityHigh, Confidence: 0.5}
	lo := model.Finding{ID: "b", Severity: model.SeverityLow, Confidence: 0.9}
	if !stronger(hi, lo) {
		t.Fatal("higher severity should win over higher confidence")
	}
	a := model.Finding{ID: "a", Severity: model.SeverityMedium, Confidence: 0.9}
	b := model.Finding{ID: "b", Severity: model.SeverityMedium, Confidence: 0.5}
	if !stronger(a, b) {
		t.Fatal("higher confidence should win at equal severity")
	}
}
