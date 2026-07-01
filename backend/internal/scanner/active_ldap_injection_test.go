package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunActiveLDAPInjectionProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, value := range r.URL.Query() {
			if strings.Contains(value[0], "uid") || strings.Contains(value[0], "admin)(|(cn=*)") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("LDAP error: invalid DN syntax"))
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActiveLDAPInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "active-ldap-injection" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-90" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunActiveLDAPInjectionProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActiveLDAPInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}

// TestRunActiveLDAPInjectionProbe_SuppressesStaticErrorPage verifies the
// Phase 1 differential re-verify strips false positives where the endpoint
// always emits an LDAP error signature regardless of input.
func TestRunActiveLDAPInjectionProbe_SuppressesStaticErrorPage(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return an LDAP error signature — this is baseline noise,
		// not a payload-specific injection signal. The differential
		// re-verify must strip this false positive because the benign
		// payload also produces the same signature.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("LDAP error: invalid DN syntax"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActiveLDAPInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("static error page should be stripped by differential re-verify, got %d findings", len(findings))
	}
}

// TestRunActiveLDAPInjectionProbe_SkipsBinaryResponses verifies the
// Phase 1 binary-shape gate: an LDAP signature substring embedded in a
// binary asset (image/PDF/etc.) is not evidence of injection.
func TestRunActiveLDAPInjectionProbe_SkipsBinaryResponses(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		// Byte sequence that coincidentally contains "ldap error" — must
		// not be treated as a vulnerability finding.
		_, _ = w.Write([]byte("\x89PNG...ldap error: not really..."))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActiveLDAPInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("binary response must be skipped by the shape gate, got %d findings", len(findings))
	}
}
