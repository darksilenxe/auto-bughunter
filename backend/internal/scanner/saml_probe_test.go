package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunSAMLProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml" && r.URL.Query().Get("SAMLResponse") != "" {
			_, _ = w.Write([]byte(`<samlp:Response><saml:Assertion>admin</saml:Assertion></samlp:Response>`))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runSAMLProbe(context.Background(), RunInput{Target: target.URL}, `<form><input name="SAMLResponse"/></form>`)
	if len(findings) == 0 {
		t.Fatal("expected SAML finding")
	}
	if findings[0].ID != "saml-endpoint-detected" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-347" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunSAMLProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runSAMLProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
