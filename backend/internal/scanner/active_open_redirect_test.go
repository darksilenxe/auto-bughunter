package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunActiveOpenRedirectProbe_PassiveOnlyDisables exercises the gating
// path. The probe's network code is covered by isOpenRedirectLocation
// below; an end-to-end test against an httptest server cannot be written
// here because safety.ValidateOutboundURL (correctly) rejects loopback.
func TestRunActiveOpenRedirectProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("next"))
		w.WriteHeader(http.StatusFound)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveOpenRedirectProbe(context.Background(), RunInput{
		Target:  target.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(findings))
	}
}

// TestRunActiveOpenRedirectProbe_RejectsLoopback documents that the SSRF
// guard intentionally rejects loopback targets even when scope would
// otherwise allow them — the probe must never originate requests to
// internal infrastructure.
func TestRunActiveOpenRedirectProbe_RejectsLoopback(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://attacker.example/")
		w.WriteHeader(http.StatusFound)
	}))
	defer target.Close()

	svc := NewService(Config{})
	got := svc.runActiveOpenRedirectProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(got) != 0 {
		t.Fatalf("loopback target must be skipped by SSRF safety check, got %d findings", len(got))
	}
}

func TestIsOpenRedirectLocation(t *testing.T) {
	cases := []struct {
		loc  string
		want bool
	}{
		{"https://abh-redirect-canary.invalid/path", true},
		{"//abh-redirect-canary.invalid/path", true},
		{"https://example.com/safe", false},
		{"/local/path", false},
		{"", false},
	}
	for _, c := range cases {
		got := isOpenRedirectLocation(c.loc, "abh-redirect-canary.invalid")
		if got != c.want {
			t.Errorf("isOpenRedirectLocation(%q) = %v, want %v", c.loc, got, c.want)
		}
	}
}
