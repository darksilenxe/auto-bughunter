package scanner

import (
	"errors"
	"testing"
)

func TestEvaluateHTTPSRedirectResponse_NoRedirect(t *testing.T) {
	f := evaluateHTTPSRedirectResponse("http://example.com", "https://example.com", 200, "")
	if f == nil {
		t.Fatal("expected finding when HTTP server does not redirect to HTTPS")
	}
	if f.CWE != "CWE-319" {
		t.Errorf("expected CWE-319, got %s", f.CWE)
	}
}

func TestEvaluateHTTPSRedirectResponse_RedirectsToHTTPS_NoFinding(t *testing.T) {
	f := evaluateHTTPSRedirectResponse("http://example.com", "https://example.com", 301, "https://example.com/")
	if f != nil {
		t.Fatalf("expected no finding when HTTP redirects to HTTPS, got: %+v", f)
	}
}

func TestEvaluateHTTPSRedirectResponse_NonHTTPSRedirectIsFinding(t *testing.T) {
	f := evaluateHTTPSRedirectResponse("http://example.com", "https://example.com", 302, "http://other.example.com/")
	if f == nil {
		t.Fatal("expected finding when redirect target is not HTTPS")
	}
}

func TestIsCertError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"x509: certificate signed by unknown authority", true},
		{"tls: failed to verify certificate", true},
		{"dial tcp: connection refused", false},
		{"EOF", false},
	}
	for _, tc := range cases {
		got := isCertError(errors.New(tc.msg))
		if got != tc.want {
			t.Errorf("isCertError(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}
