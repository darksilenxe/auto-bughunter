package scanner

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func newSAMLScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

// TestSAMLProbe_PassiveOnly ensures the probe is a no-op in passive mode.
func TestSAMLProbe_PassiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("passive-only mode must not make requests")
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunSAMLProbe(
		context.Background(), srv.URL,
		newSAMLScope(srv.URL),
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in passive mode, got %d", len(findings))
	}
}

// TestSAMLProbe_SurfaceDiscovered verifies an Info finding when a SAML
// metadata endpoint responds with 200.
func TestSAMLProbe_SurfaceDiscovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/metadata") || strings.Contains(r.URL.Path, "saml") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"></EntityDescriptor>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunSAMLProbe(
		context.Background(), srv.URL,
		newSAMLScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "saml-surface-discovered" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected saml-surface-discovered finding; got: %+v", findings)
	}
}

// TestSAMLProbe_UnsignedAssertion_Accepted verifies a Critical finding when
// the ACS endpoint accepts a SAML response with no signature.
func TestSAMLProbe_UnsignedAssertion_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "saml") && r.Method == http.MethodPost {
			// ACS accepts everything — no signature check.
			if r.PostFormValue("SAMLResponse") != "" {
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunSAMLProbe(
		context.Background(), srv.URL,
		newSAMLScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "saml-unsigned-assertion" {
			found = true
			if f.Severity != model.SeverityCritical {
				t.Fatalf("expected Critical severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-347" {
				t.Fatalf("expected CWE-347, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected saml-unsigned-assertion-accepted finding; got: %+v", findings)
	}
}

// TestSAMLProbe_UnsignedAssertion_Rejected ensures no finding when the ACS
// rejects unsigned assertions (returns 400/403).
func TestSAMLProbe_UnsignedAssertion_Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.PostFormValue("SAMLResponse") != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid signature"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunSAMLProbe(
		context.Background(), srv.URL,
		newSAMLScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	for _, f := range findings {
		if f.ID == "saml-unsigned-assertion-accepted" {
			t.Fatalf("unexpected saml-unsigned-assertion-accepted finding when server returns 400")
		}
	}
}

// TestSAMLProbe_AssertionReplay_Accepted verifies a High finding when the
// ACS accepts the same SAMLResponse ID twice.
func TestSAMLProbe_AssertionReplay_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept every request — no replay detection, no signature validation.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunSAMLProbe(
		context.Background(), srv.URL,
		newSAMLScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "saml-assertion-replay" {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected saml-assertion-replay finding; got: %+v", findings)
	}
}

// TestSAMLProbe_CertificateExposure verifies a Low finding when metadata
// contains an X509Certificate element.
func TestSAMLProbe_CertificateExposure(t *testing.T) {
	certPEM := base64.StdEncoding.EncodeToString([]byte("FAKECERTDATA"))
	xmlBody := `<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<KeyDescriptor><KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<ds:X509Data><ds:X509Certificate>` + certPEM + `</ds:X509Certificate></ds:X509Data>` +
		`</KeyInfo></KeyDescriptor></EntityDescriptor>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(xmlBody))
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunSAMLProbe(
		context.Background(), srv.URL,
		newSAMLScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "saml-metadata-cert-exposure" {
			found = true
			if f.CWE != "CWE-200" {
				t.Fatalf("expected CWE-200, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected certificate-exposure finding; got: %+v", findings)
	}
}
