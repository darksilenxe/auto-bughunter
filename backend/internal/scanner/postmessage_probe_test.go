package scanner

import "testing"

func TestClassifyPostMessageLeak_IgnoresOriginEcho(t *testing.T) {
	collected := `[{"origin":"https://evil.example.com","dataType":"object","dataStr":"{\"allowedOrigin\":\"https://auth.example.com\"}"}]`
	patterns := []string{"token", "auth", "session"}
	if _, _, ok := classifyPostMessageLeak(collected, patterns); ok {
		t.Fatal("expected origin-only echo to be suppressed")
	}
}

func TestClassifyPostMessageLeak_FindsActionableSensitiveData(t *testing.T) {
	collected := `[{"origin":"https://evil.example.com","dataType":"object","dataStr":"{\"access_token\":\"abc123\"}"}]`
	patterns := []string{"token", "auth", "session", "access_token"}
	pattern, contextLabel, ok := classifyPostMessageLeak(collected, patterns)
	if !ok {
		t.Fatal("expected actionable postMessage leak")
	}
	if pattern != "token" && pattern != "access_token" {
		t.Fatalf("unexpected pattern %q", pattern)
	}
	if contextLabel != "message-data" {
		t.Fatalf("unexpected context %q", contextLabel)
	}
}

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
