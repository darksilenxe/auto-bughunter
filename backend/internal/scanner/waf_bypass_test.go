package scanner

import (
	"strings"
	"testing"
)

func TestXSSBypassVariants_PreservesSentinel(t *testing.T) {
	const sentinel = "abh_xss_7f9e2"
	const marker = `"><svg/onload=` + sentinel + `()><!--` + sentinel + `-->`

	variants := xssBypassVariants(marker)
	if len(variants) < 5 {
		t.Fatalf("expected at least 5 variants, got %d", len(variants))
	}
	if variants[0] != marker {
		t.Fatalf("first variant must be the canonical marker, got %q", variants[0])
	}
	for i, v := range variants {
		if !strings.Contains(v, sentinel) {
			t.Errorf("variant %d does not contain sentinel %q: %q", i, sentinel, v)
		}
	}
	// Variants must be unique.
	seen := map[string]struct{}{}
	for _, v := range variants {
		if _, ok := seen[v]; ok {
			t.Errorf("duplicate variant: %q", v)
		}
		seen[v] = struct{}{}
	}
}

func TestSQLiBypassVariants_IncludesCanonical(t *testing.T) {
	variants := sqliBypassVariants("'")
	if len(variants) < 3 {
		t.Fatalf("expected at least 3 variants, got %d", len(variants))
	}
	if variants[0] != "'" {
		t.Fatalf("first variant must be the canonical payload, got %q", variants[0])
	}
	// All variants must contain at least one quote-equivalent breakout
	// character so they have a chance of triggering an SQL parser error.
	hasBreakout := func(s string) bool {
		for _, c := range []string{"'", "`", ")", "%2527", `\`} {
			if strings.Contains(s, c) {
				return true
			}
		}
		return false
	}
	for _, v := range variants {
		if !hasBreakout(v) {
			t.Errorf("variant %q has no breakout character", v)
		}
	}
	// No UNION / OR / SLEEP — these would be destructive and out of scope
	// for the error-based probe.
	for _, v := range variants {
		lower := strings.ToLower(v)
		for _, banned := range []string{"union", " or ", "sleep", "benchmark", "drop"} {
			if strings.Contains(lower, banned) {
				t.Errorf("variant %q contains banned destructive token %q", v, banned)
			}
		}
	}
}

func TestSSTIBypassVariants_AllEvaluateTo49(t *testing.T) {
	variants := sstiBypassVariants()
	if len(variants) < len(sstiPayloads) {
		t.Fatalf("bypass variants (%d) must be a superset of canonical sstiPayloads (%d)",
			len(variants), len(sstiPayloads))
	}
	for _, v := range variants {
		if v.expect != "49" {
			t.Errorf("variant %+v: expected result must be %q (so isSSTIEvaluation works), got %q",
				v, "49", v.expect)
		}
		if v.engine == "" || v.payload == "" {
			t.Errorf("variant %+v: engine/payload must be set", v)
		}
	}
	// Each canonical payload from sstiPayloads must appear in the bypass
	// list so behaviour is purely additive when WAFBypass is enabled.
	for _, canonical := range sstiPayloads {
		found := false
		for _, v := range variants {
			if v.payload == canonical.payload {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("canonical payload %q missing from bypass variants", canonical.payload)
		}
	}
}

func TestDedupStrings(t *testing.T) {
	got := dedupStrings([]string{"a", "", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestContainsAll(t *testing.T) {
	if !containsAll("hello world", "hello", "world") {
		t.Error("expected true for both substrings present")
	}
	if containsAll("hello", "hello", "missing") {
		t.Error("expected false when one substring missing")
	}
}
