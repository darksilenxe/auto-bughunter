package mitre

import (
	"reflect"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestTechniqueIDsForByCategory(t *testing.T) {
	got := TechniqueIDsFor(model.Finding{Category: "xss"})
	want := []string{"T1059.007", "T1190"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("xss: got %v want %v", got, want)
	}
}

func TestTechniqueIDsForByCWE(t *testing.T) {
	// CWE-918 is SSRF; resolution should add T1190 + T1190.001 even when
	// the category is unknown.
	got := TechniqueIDsFor(model.Finding{Category: "unknown-cat", CWE: "cwe-918"})
	want := []string{"T1190", "T1190.001"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CWE-918: got %v want %v", got, want)
	}
}

func TestTechniqueIDsForUnknown(t *testing.T) {
	if got := TechniqueIDsFor(model.Finding{Category: "made-up", CWE: "CWE-999999"}); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestTechniqueIDsForDeduplicates(t *testing.T) {
	// Both category and CWE map to T1190.
	got := TechniqueIDsFor(model.Finding{Category: "injection", CWE: "CWE-89"})
	want := []string{"T1059", "T1190"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedup: got %v want %v", got, want)
	}
}

func TestAnnotateFindingPreservesExisting(t *testing.T) {
	f := model.Finding{Category: "xss", MITRETechniques: []string{"T9999"}}
	out := AnnotateFinding(f)
	if !reflect.DeepEqual(out.MITRETechniques, []string{"T9999"}) {
		t.Fatalf("existing annotations should be preserved, got %v", out.MITRETechniques)
	}
}

func TestAnnotateFindingPopulates(t *testing.T) {
	out := AnnotateFinding(model.Finding{Category: "ssrf"})
	if len(out.MITRETechniques) == 0 {
		t.Fatalf("expected SSRF to be annotated")
	}
}

func TestAnnotateFindings(t *testing.T) {
	in := []model.Finding{{Category: "xss"}, {Category: "made-up"}, {Category: "injection"}}
	out := AnnotateFindings(in)
	if len(out) != 3 {
		t.Fatalf("len mismatch")
	}
	if len(out[0].MITRETechniques) == 0 {
		t.Fatalf("xss not annotated")
	}
	if len(out[1].MITRETechniques) != 0 {
		t.Fatalf("unknown category should not be annotated")
	}
	if len(out[2].MITRETechniques) == 0 {
		t.Fatalf("injection not annotated")
	}
}

func TestHeatmap(t *testing.T) {
	findings := []model.Finding{
		{MITRETechniques: []string{"T1190", "T1059"}},
		{MITRETechniques: []string{"T1190"}},
		{MITRETechniques: []string{"T9999"}}, // unknown — ignored
	}
	h := Heatmap(findings)
	if h["T1190"] != 2 {
		t.Fatalf("expected T1190 count 2, got %d", h["T1190"])
	}
	if h["T1059"] != 1 {
		t.Fatalf("expected T1059 count 1, got %d", h["T1059"])
	}
	if _, ok := h["T9999"]; ok {
		t.Fatalf("unknown technique should not appear in heatmap")
	}
}

func TestHeatmapEmpty(t *testing.T) {
	if h := Heatmap(nil); h != nil {
		t.Fatalf("expected nil heatmap, got %v", h)
	}
}

func TestSortedHeatmap(t *testing.T) {
	h := map[string]int{"T1190": 5, "T1059": 5, "T1083": 1}
	entries := SortedHeatmap(h)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// equal counts → sort by ID asc; T1059 before T1190
	if entries[0].ID != "T1059" || entries[1].ID != "T1190" || entries[2].ID != "T1083" {
		t.Fatalf("unexpected order: %+v", entries)
	}
	if entries[0].Name == "" {
		t.Fatalf("entry should carry name")
	}
}

func TestLookup(t *testing.T) {
	if _, ok := Lookup("T1190"); !ok {
		t.Fatalf("T1190 must exist")
	}
	if _, ok := Lookup("not-a-technique"); ok {
		t.Fatalf("unknown technique should not be found")
	}
}
