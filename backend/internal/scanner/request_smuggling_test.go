package scanner

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestClassifySmuggling(t *testing.T) {
	rt := smugglingReadTimeout
	cases := []struct {
		name             string
		baseline, probe  time.Duration
		timedOut         bool
		want             bool
	}{
		{"timeout-on-fast-baseline", 200 * time.Millisecond, rt, true, true},
		{"large-delta", 200 * time.Millisecond, 200*time.Millisecond + smugglingMinDelta, false, true},
		{"small-delta", 200 * time.Millisecond, 400 * time.Millisecond, false, false},
		{"slow-baseline-untrusted", rt, rt, true, false},
	}
	for _, c := range cases {
		if got := classifySmuggling(c.baseline, c.probe, c.timedOut); got != c.want {
			t.Errorf("%s: classifySmuggling=%v want %v", c.name, got, c.want)
		}
	}
}

func TestSmugglingRequestShapes(t *testing.T) {
	clte := smugglingCLTERequest("/", "example.com")
	if !strings.Contains(clte, "Transfer-Encoding: chunked") || !strings.Contains(clte, "Content-Length:") {
		t.Fatal("CL.TE payload must include both Content-Length and Transfer-Encoding")
	}
	if !strings.HasPrefix(clte, "POST / HTTP/1.1\r\n") {
		t.Fatal("CL.TE payload must be a well-formed request line")
	}
	base := smugglingBaselineRequest("/", "example.com")
	if !strings.HasPrefix(base, "GET / HTTP/1.1\r\n") || !strings.HasSuffix(base, "\r\n\r\n") {
		t.Fatal("baseline request must be a well-formed GET ending in CRLFCRLF")
	}
}

func TestSmugglingAddr(t *testing.T) {
	cases := map[string]string{
		"http://example.com/":       "example.com:80",
		"https://example.com/":      "example.com:443",
		"https://example.com:8443/": "example.com:8443",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if got := smugglingAddr(u); got != want {
			t.Errorf("smugglingAddr(%q)=%q want %q", in, got, want)
		}
	}
}
