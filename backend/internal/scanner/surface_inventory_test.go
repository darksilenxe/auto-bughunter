package scanner

import (
	"testing"
)

func TestNormalizeSurfaceKey_DedupesEquivalentEndpoints(t *testing.T) {
	// Different path IDs should collapse to the same key.
	k1 := NormalizeSurfaceKey("GET", "https://a.example.com/users/42/posts", nil)
	k2 := NormalizeSurfaceKey("get", "https://a.example.com/users/99/posts", nil)
	if k1 != k2 {
		t.Fatalf("expected numeric ids to normalize, got %s vs %s", k1, k2)
	}
	// Case-insensitive method + host.
	if got := NormalizeSurfaceKey("post", "HTTPS://A.EXAMPLE.COM/api", []string{"Foo", "bar"}); got != NormalizeSurfaceKey("POST", "https://a.example.com/api", []string{"BAR", "foo"}) {
		t.Fatalf("expected case/param-order invariance, got %s", got)
	}
	// Different methods produce different keys.
	if NormalizeSurfaceKey("GET", "https://a/x", nil) == NormalizeSurfaceKey("POST", "https://a/x", nil) {
		t.Fatalf("expected method to affect key")
	}
	// Distinct param sets produce distinct keys.
	if NormalizeSurfaceKey("GET", "https://a/x", []string{"a"}) == NormalizeSurfaceKey("GET", "https://a/x", []string{"b"}) {
		t.Fatalf("expected param sets to affect key")
	}
}

func TestSurfaceInventory_AddAndSnapshot(t *testing.T) {
	inv := NewSurfaceInventory()
	inv.Add("GET", "https://a.example.com/users/1?x=1", []string{"y"}, SurfaceSourceCrawl)
	// same key, additional source + param
	inv.Add("get", "https://a.example.com/users/2?x=2", []string{"Z"}, SurfaceSourceRuntimeXHR)
	inv.AddMany([]string{"https://a.example.com/other"}, SurfaceSourceSitemap)

	if got, want := inv.Size(), 2; got != want {
		t.Fatalf("inventory size = %d, want %d", got, want)
	}

	snap := inv.Snapshot()
	var merged *SurfaceEntry
	for i := range snap {
		if snap[i].Path == "/users/{id}" {
			merged = &snap[i]
			break
		}
	}
	if merged == nil {
		t.Fatalf("expected merged /users/{id} entry, got %#v", snap)
	}
	// Union of params x, y, z.
	got := merged.Params
	want := []string{"x", "y", "z"}
	if len(got) != len(want) {
		t.Fatalf("params = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("params[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	// Both crawl and runtime_xhr sources kept.
	if len(merged.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %v", merged.Sources)
	}
}

func TestDetectSurfaceGaps_Unprobed_Param_Method(t *testing.T) {
	ResetSurfaceCoverageMetrics()
	inv := NewSurfaceInventory()
	inv.Add("GET", "https://a/api/users?id=1", []string{"id", "role"}, SurfaceSourceRuntimeXHR)
	inv.Add("POST", "https://a/api/users", []string{"id"}, SurfaceSourceOpenAPI)
	inv.Add("GET", "https://a/legacy", nil, SurfaceSourceCrawl)

	// Probe the GET /api/users but only param "id"; POST /api/users unprobed; legacy unprobed.
	RecordProbedKey("GET", "https://a/api/users?id=1", "id")

	gaps := DetectSurfaceGaps(inv)
	var reasons = map[SurfaceGapReason]int{}
	for _, g := range gaps {
		reasons[g.Reason]++
	}
	if reasons[SurfaceGapUnprobed] < 2 {
		t.Fatalf("expected at least 2 unprobed gaps, got %d (%v)", reasons[SurfaceGapUnprobed], gaps)
	}
	if reasons[SurfaceGapParamNotFuzzed] < 1 {
		t.Fatalf("expected role param gap, got %v", gaps)
	}
	if reasons[SurfaceGapMethodNotTested] < 1 {
		t.Fatalf("expected POST method-not-tested gap, got %v", gaps)
	}
	m := GetSurfaceCoverageMetrics()
	if m.InventoryTotal != 3 || m.ProbedUnique != 1 {
		t.Fatalf("unexpected coverage metrics: %+v", m)
	}
	if m.CoverageRatio <= 0 || m.CoverageRatio > 1 {
		t.Fatalf("coverage ratio out of range: %v", m.CoverageRatio)
	}
}

func TestParamDiscoveryMarker_Deterministic(t *testing.T) {
	if got := paramDiscoveryMarker("id"); got != "abhpd-id-marker" {
		t.Fatalf("marker mismatch: %s", got)
	}
	if paramDiscoveryMarker("Foo") == paramDiscoveryMarker("foo") {
		// Callers lower-case before calling; assert we do not do
		// implicit normalization inside the marker generator.
		t.Fatalf("marker should not implicitly lower-case")
	}
}

func TestSelectHighROIGaps_OrdersByScore(t *testing.T) {
	ent := func(method, u string, sources ...SurfaceSource) SurfaceEntry {
		return SurfaceEntry{
			Method:  method,
			URL:     u,
			Host:    hostOf(u),
			Path:    normalizePath(u),
			Sources: sources,
		}
	}
	gaps := []SurfaceGap{
		{Reason: SurfaceGapParamNotFuzzed, Entry: ent("GET", "https://a/api", SurfaceSourceCrawl), MissingItem: "q"},
		{Reason: SurfaceGapUnprobed, Entry: ent("GET", "https://a/api/list", SurfaceSourceRuntimeXHR)},
		{Reason: SurfaceGapMethodNotTested, Entry: ent("POST", "https://a/api/list", SurfaceSourceOpenAPI), MissingItem: "POST"},
		{Reason: SurfaceGapUnprobed, Entry: ent("GET", "https://a/static.html", SurfaceSourceCrawl)},
	}
	sel := SelectHighROIGaps(gaps, 3)
	if len(sel) != 3 {
		t.Fatalf("expected 3 selected, got %d", len(sel))
	}
	// Highest ROI should be the runtime_xhr Unprobed entry.
	if sel[0].Reason != SurfaceGapUnprobed || sel[0].Entry.Host != "a" || sel[0].Entry.Path != "/api/list" {
		t.Fatalf("unexpected top selection: %#v", sel[0])
	}
	urls := GapReQueueURLs(sel)
	if len(urls) == 0 {
		t.Fatalf("expected requeue urls, got none")
	}
}
