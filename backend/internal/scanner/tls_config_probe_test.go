package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunTLSConfigProbe_HTTPNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	// srv is plain HTTP, so simulate the "check redirect" path directly.
	// The target is the HTTP server itself; we expect a finding because it
	// doesn't redirect to HTTPS.
	f := svc.checkHTTPSRedirect(context.Background(), RunInput{Target: srv.URL}, srv.URL, "https://"+srv.Listener.Addr().String()+"/")
	if f == nil {
		t.Fatal("expected finding when HTTP server does not redirect to HTTPS")
	}
	if f.CWE != "CWE-319" {
		t.Errorf("expected CWE-319, got %s", f.CWE)
	}
}

func TestRunTLSConfigProbe_HTTPRedirectsToHTTPS_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	f := svc.checkHTTPSRedirect(context.Background(), RunInput{Target: srv.URL}, srv.URL, "https://"+srv.Listener.Addr().String()+"/")
	if f != nil {
		t.Fatalf("expected no finding when HTTP properly redirects to HTTPS, got: %+v", f)
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
