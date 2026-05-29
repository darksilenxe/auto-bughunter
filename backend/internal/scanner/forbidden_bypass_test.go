package scanner

import (
	"net/http"
	"testing"
)

func TestIsForbiddenBypass(t *testing.T) {
	cases := []struct {
		base, bypass int
		want         bool
	}{
		{http.StatusForbidden, http.StatusOK, true},
		{http.StatusUnauthorized, http.StatusNoContent, true},
		{http.StatusForbidden, http.StatusForbidden, false},
		{http.StatusForbidden, http.StatusFound, false},
		{http.StatusOK, http.StatusOK, false},
		{http.StatusNotFound, http.StatusOK, false},
	}
	for _, c := range cases {
		if got := isForbiddenBypass(c.base, c.bypass); got != c.want {
			t.Errorf("isForbiddenBypass(%d,%d)=%v want %v", c.base, c.bypass, got, c.want)
		}
	}
}

func TestForbiddenPathMutations(t *testing.T) {
	muts := forbiddenPathMutations("/admin")
	if len(muts) == 0 {
		t.Fatal("expected mutations for /admin")
	}
	seen := map[string]bool{}
	for _, m := range muts {
		if m == "/admin" {
			t.Errorf("mutation must differ from original path")
		}
		if seen[m] {
			t.Errorf("duplicate mutation %q", m)
		}
		seen[m] = true
	}
	// A couple of signature bypass variants should be present.
	want := []string{"/admin/", "/admin/..;/", "//admin"}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("expected mutation %q to be present", w)
		}
	}
}
