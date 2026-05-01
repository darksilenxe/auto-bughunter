package toolbuilder

import (
	"strings"
	"testing"
)

func TestSanitizeName_TruncatesLongNames(t *testing.T) {
	long := strings.Repeat("a", 500)
	got := sanitizeName(long)
	if len(got) > 100 {
		t.Fatalf("expected sanitized name length <= 100, got %d", len(got))
	}
	if got != strings.Repeat("a", 100) {
		t.Fatalf("unexpected truncation: %q", got)
	}
}

func TestSanitizeName_ReplacesUnsafeChars(t *testing.T) {
	got := sanitizeName("My Tool/Name@2024")
	for _, r := range got {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			t.Fatalf("unexpected character %q in %q", r, got)
		}
	}
}
