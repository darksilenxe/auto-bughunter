package scanner

import (
	"testing"
)

func TestTruncateStr(t *testing.T) {
	cases := []struct {
		input string
		n     int
		want  string
	}{
		{"hello world", 5, "hello"},
		{"short", 100, "short"},
		{"", 10, ""},
		{"abc", 0, ""},
	}
	for _, tc := range cases {
		got := truncateStr(tc.input, tc.n)
		if got != tc.want {
			t.Errorf("truncateStr(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
		}
	}
}
