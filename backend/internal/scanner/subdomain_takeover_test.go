package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestMatchTakeoverFingerprint_PositiveAndNegative covers the curated
// fingerprint matcher: known unclaimed-resource bodies must match, generic
// bodies must not.
func TestMatchTakeoverFingerprint_PositiveAndNegative(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    bool
		service string
	}{
		{name: "s3 unclaimed bucket", body: "<Error><Code>NoSuchBucket</Code></Error>", want: true, service: "AWS S3"},
		{name: "github pages", body: "There isn't a GitHub Pages site here.", want: true, service: "GitHub Pages"},
		{name: "heroku", body: "No such app", want: true, service: "Heroku"},
		{name: "shopify", body: "Sorry, this shop is currently unavailable", want: true, service: "Shopify"},
		{name: "fastly", body: "Fastly error: unknown domain", want: true, service: "Fastly"},
		{name: "generic 404", body: "<html><title>404 Not Found</title></html>", want: false},
		{name: "empty body", body: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp, ok := matchTakeoverFingerprint(tc.body)
			if ok != tc.want {
				t.Fatalf("match=%v want=%v (body=%q)", ok, tc.want, tc.body)
			}
			if tc.want && fp.Service != tc.service {
				t.Fatalf("service=%q want=%q", fp.Service, tc.service)
			}
		})
	}
}

// TestCollectTakeoverCandidates_ExcludesTargetAndWildcards verifies the
// candidate-collection helper dedupes, drops the target host, and rejects
// wildcard scope entries (which cannot be GETed directly).
func TestCollectTakeoverCandidates_ExcludesTargetAndWildcards(t *testing.T) {
	scanScope := model.ScanScope{
		IncludeHosts: []string{"example.com", "api.example.com", "*.example.com", "api.example.com"},
	}
	got := collectTakeoverCandidates("https://example.com/", "", scanScope, "example.com", maxTakeoverHosts)
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("expected [api.example.com], got %v", got)
	}
}

// TestCollectTakeoverCandidates_RespectsExcludeHosts ensures hosts excluded
// by scope.ExcludeHosts are not probed even when listed in IncludeHosts.
func TestCollectTakeoverCandidates_RespectsExcludeHosts(t *testing.T) {
	scanScope := model.ScanScope{
		IncludeHosts: []string{"api.example.com", "internal.example.com"},
		ExcludeHosts: []string{"internal.example.com"},
	}
	got := collectTakeoverCandidates("https://example.com/", "", scanScope, "example.com", maxTakeoverHosts)
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("expected only api.example.com, got %v", got)
	}
}

// TestCollectTakeoverCandidates_RespectsCap ensures the helper does not
// exceed the requested maximum even when more hosts are in scope.
func TestCollectTakeoverCandidates_RespectsCap(t *testing.T) {
	scanScope := model.ScanScope{
		IncludeHosts: []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"},
	}
	got := collectTakeoverCandidates("https://example.com/", "", scanScope, "example.com", 2)
	if len(got) != 2 {
		t.Fatalf("expected cap=2 candidates, got %d (%v)", len(got), got)
	}
}
