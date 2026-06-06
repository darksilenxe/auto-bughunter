package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunCrossDomainPolicyProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runCrossDomainPolicyProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	})
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestAnalyzeCrossDomainXML_WildcardDomain(t *testing.T) {
	body := `<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*" secure="false"/>
</cross-domain-policy>`
	got := analyzeCrossDomainXML("https://example.com/crossdomain.xml", body)
	if len(got) == 0 {
		t.Fatal("expected finding for wildcard allow-access-from in crossdomain.xml")
	}
	for _, f := range got {
		if f.CWE != "CWE-942" {
			t.Errorf("expected CWE-942, got %s", f.CWE)
		}
	}
}

func TestAnalyzeCrossDomainXML_RestrictedDomainNoFinding(t *testing.T) {
	body := `<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="trusted.example.com" secure="true"/>
</cross-domain-policy>`
	got := analyzeCrossDomainXML("https://example.com/crossdomain.xml", body)
	if len(got) != 0 {
		t.Fatalf("expected no findings for restricted domain, got %d", len(got))
	}
}

func TestAnalyzeClientAccessPolicy_WildcardHeaders(t *testing.T) {
	body := `<?xml version="1.0"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from http-request-headers="*">
        <domain uri="*"/>
      </allow-from>
    </policy>
  </cross-domain-access>
</access-policy>`
	got := analyzeClientAccessPolicy("https://example.com/clientaccesspolicy.xml", body)
	if len(got) == 0 {
		t.Fatal("expected finding for wildcard clientaccesspolicy.xml")
	}
}

func TestRunCrossDomainPolicyProbe_NotFoundNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runCrossDomainPolicyProbe(context.Background(), RunInput{Target: srv.URL})
	if len(got) != 0 {
		t.Fatalf("expected no findings when policy files return 404, got %d", len(got))
	}
}

