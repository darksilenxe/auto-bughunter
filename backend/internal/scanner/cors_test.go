package scanner

import (
	"net/http"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestClassifyCORSResponse_WildcardWithCredentialsHigh(t *testing.T) {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Credentials", "true")
	got := classifyCORSResponse("https://example.com/", h)
	if len(got) != 1 || got[0].ID != "cors-wildcard-with-credentials" || got[0].Severity != model.SeverityHigh {
		t.Fatalf("expected wildcard+credentials high finding, got %#v", got)
	}
}

func TestClassifyCORSResponse_ReflectedOriginWithCredentialsHigh(t *testing.T) {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", corsProbeOrigin)
	h.Set("Access-Control-Allow-Credentials", "true")
	got := classifyCORSResponse("https://example.com/", h)
	if len(got) != 1 || got[0].ID != "cors-reflected-origin-with-credentials" || got[0].Severity != model.SeverityHigh {
		t.Fatalf("expected reflected-origin+credentials high finding, got %#v", got)
	}
}

func TestClassifyCORSResponse_ReflectedOriginMedium(t *testing.T) {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", corsProbeOrigin)
	got := classifyCORSResponse("https://example.com/", h)
	if len(got) != 1 || got[0].ID != "cors-reflected-origin" || got[0].Severity != model.SeverityMedium {
		t.Fatalf("expected reflected-origin medium finding, got %#v", got)
	}
}

func TestClassifyCORSResponse_NoCORSHeaders(t *testing.T) {
	h := http.Header{}
	if got := classifyCORSResponse("https://example.com/", h); got != nil {
		t.Fatalf("expected nil for no CORS headers, got %#v", got)
	}
}

func TestClassifyCORSResponse_AllowedOriginIsSafe(t *testing.T) {
	// A correctly configured server only echoes a safe / pre-approved origin,
	// not the attacker-controlled probe origin. The classifier must say nothing.
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "https://app.example.com")
	h.Set("Access-Control-Allow-Credentials", "true")
	if got := classifyCORSResponse("https://example.com/", h); got != nil {
		t.Fatalf("expected nil for allow-listed origin, got %#v", got)
	}
}

func TestRedirectsTo_AbsoluteAndSchemeRelative(t *testing.T) {
	cases := []struct {
		name     string
		location string
		marker   string
		want     bool
	}{
		{"exact", "https://abh-redirect-probe.example/", "https://abh-redirect-probe.example/", true},
		{"different-host", "https://other.example/", "https://abh-redirect-probe.example/", false},
		{"relative-path", "/login", "https://abh-redirect-probe.example/", false},
		{"empty", "", "https://abh-redirect-probe.example/", false},
		{"scheme-relative-marker-host", "//abh-redirect-probe.example/x", "https://abh-redirect-probe.example/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redirectsTo(tc.location, tc.marker); got != tc.want {
				t.Fatalf("redirectsTo(%q,%q) = %v, want %v", tc.location, tc.marker, got, tc.want)
			}
		})
	}
}
