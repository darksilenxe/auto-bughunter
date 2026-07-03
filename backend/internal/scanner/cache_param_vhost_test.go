package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCachePoisonReflected(t *testing.T) {
	if !cachePoisonReflected("see https://"+cachePoisonCanary+"/x", http.Header{}, cachePoisonCanary) {
		t.Fatal("canary in body must be detected")
	}
	h := http.Header{}
	h.Set("Location", "https://"+cachePoisonCanary+"/")
	if !cachePoisonReflected("nope", h, cachePoisonCanary) {
		t.Fatal("canary in header must be detected")
	}
	if cachePoisonReflected("clean body", http.Header{}, cachePoisonCanary) {
		t.Fatal("absent canary must not match")
	}
}

func TestResponseAppearsCacheable(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want bool
	}{
		{"x-cache-hit", http.Header{"X-Cache": {"HIT"}}, true},
		{"age", http.Header{"Age": {"120"}}, true},
		{"cf-cache", http.Header{"Cf-Cache-Status": {"DYNAMIC"}}, true},
		{"public-maxage", http.Header{"Cache-Control": {"public, max-age=60"}}, true},
		{"no-store", http.Header{"Cache-Control": {"no-store"}}, false},
		{"private", http.Header{"Cache-Control": {"private, max-age=60"}}, false},
		{"empty", http.Header{}, false},
	}
	for _, c := range cases {
		if got := responseAppearsCacheable(c.h); got != c.want {
			t.Errorf("%s: responseAppearsCacheable=%v want %v", c.name, got, c.want)
		}
	}
}

func TestHppDiffers(t *testing.T) {
	if !hppDiffers(bodyStatus{status: 200}, bodyStatus{status: 500}) {
		t.Fatal("status change must differ")
	}
	if hppDiffers(bodyStatus{status: 200, body: "same"}, bodyStatus{status: 200, body: "same"}) {
		t.Fatal("identical bodies must not differ")
	}
	big := make([]byte, 1000)
	if !hppDiffers(bodyStatus{status: 200, body: string(big)}, bodyStatus{status: 200, body: ""}) {
		t.Fatal("large body delta must differ")
	}
	// Tiny reflected-value difference should not trip.
	if hppDiffers(bodyStatus{status: 200, body: "value=abh1"}, bodyStatus{status: 200, body: "value=abh2"}) {
		t.Fatal("trivial reflected difference must not differ")
	}
}

func TestVhostApex(t *testing.T) {
	cases := map[string]string{
		"www.example.com":     "example.com",
		"a.b.example.co":      "example.co",
		"example.com":         "example.com",
		"localhost":           "",
		"127.0.0.1":           "",
		"":                    "",
	}
	for in, want := range cases {
		if got := vhostApex(in); got != want {
			t.Errorf("vhostApex(%q)=%q want %q", in, got, want)
		}
	}
}

func TestVhostDiffers(t *testing.T) {
	if !vhostDiffers(bodyStatus{status: 404}, bodyStatus{status: 200}) {
		t.Fatal("status change must differ")
	}
	if vhostDiffers(bodyStatus{status: 200, body: "x"}, bodyStatus{status: 200, body: "x"}) {
		t.Fatal("identical must not differ")
	}
}

func TestWithCacheBusterParam(t *testing.T) {
got := withCacheBusterParam("https://example.com/path?x=1", "abhcb", "tok123")
u, err := url.Parse(got)
if err != nil {
t.Fatalf("unexpected parse error: %v", err)
}
if u.Query().Get("abhcb") != "tok123" {
t.Fatalf("expected cache-buster param preserved, got %q", got)
}
if u.Query().Get("x") != "1" {
t.Fatalf("expected existing query params preserved, got %q", got)
}
}

func TestCacheBusterTokenStableAndDistinct(t *testing.T) {
a1 := cacheBusterToken("X-Forwarded-Host")
a2 := cacheBusterToken("X-Forwarded-Host")
if a1 != a2 {
t.Fatalf("expected deterministic token for same header, got %q vs %q", a1, a2)
}
b := cacheBusterToken("X-Host")
if a1 == b {
t.Fatalf("expected distinct tokens for distinct headers, both %q", a1)
}
}

// TestCachePoisonReplayConfirmed_RejectsLoopback documents that
// cachePoisonReplayConfirmed re-validates its target through the SSRF guard
// independently, so it can never be used to reach loopback/internal
// infrastructure even if a caller passed through a stale/unvalidated URL.
func TestCachePoisonReplayConfirmed_RejectsLoopback(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("host=" + cachePoisonCanary))
	}))
	defer target.Close()

	client := target.Client()
	confirmed, err := cachePoisonReplayConfirmed(context.Background(), client, RunInput{}, target.URL+"?poisoned=1")
	if err == nil {
		t.Fatal("expected loopback replay target to be rejected by safety.ValidateOutboundURL")
	}
	if confirmed {
		t.Fatal("rejected replay must not report confirmed")
	}
}
