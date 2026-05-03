package scanner

import (
	"strings"
	"testing"
)

// TestRaceSlug verifies that the raceSlug function produces non-empty,
// lowercase, URL-safe identifiers for typical URL inputs.
func TestRaceSlug(t *testing.T) {
	cases := []struct {
		input    string
		nonempty bool
	}{
		{"https://example.com/api/checkout", true},
		{"Simple Test", true},
		{"already-slug", true},
	}
	for _, tc := range cases {
		got := raceSlug(tc.input)
		if tc.nonempty && got == "" {
			t.Errorf("raceSlug(%q): expected non-empty result", tc.input)
		}
		// Must only contain lowercase alphanum and dashes.
		for _, r := range got {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				t.Errorf("raceSlug(%q): unexpected char %q in %q", tc.input, r, got)
			}
		}
		// Must not start or end with a dash.
		if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
			t.Errorf("raceSlug(%q): starts/ends with dash: %q", tc.input, got)
		}
	}
}

// TestRaceSlugTruncation verifies that the slug is capped at 40 characters.
func TestRaceSlugTruncation(t *testing.T) {
	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // >40
	got := raceSlug(long)
	if len(got) > 40 {
		t.Errorf("raceSlug(%q): expected ≤40 chars, got %d", long, len(got))
	}
}

