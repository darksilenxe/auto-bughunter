package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/oast"
)

// TestRunOASTHeaderSSRFProbe_FiresOnVulnerableTarget simulates a target
// whose code dereferences X-Forwarded-Host: it makes an outbound GET to
// whatever URL the header contains. The probe must surface a finding.
func TestRunOASTHeaderSSRFProbe_FiresOnVulnerableTarget(t *testing.T) {
	oastSvc := oast.NewService(oast.Config{TTL: time.Minute})
	oastListener := httptest.NewServer(oastSvc.Handler())
	defer oastListener.Close()
	// Reconfigure with the real listener URL so issued tokens point at it.
	oastSvc = oast.NewService(oast.Config{TTL: time.Minute, PublicBaseURL: oastListener.URL})
	// Replace the handler-mux on the existing test server to keep the URL stable.
	oastListener.Config.Handler = oastSvc.Handler()

	// Vulnerable target: fetches the URL it finds in X-Forwarded-Host.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.Header.Get("X-Forwarded-Host"); strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			req, _ := http.NewRequest(http.MethodGet, u+"/triggered", nil)
			req.Header.Set("User-Agent", "vulnerable-app/1.0")
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	svc.SetOAST(oastSvc)

	findings := svc.runOASTHeaderSSRFProbe(context.Background(), RunInput{Target: target.URL})
	if len(findings) != 1 {
		t.Fatalf("expected 1 SSRF finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "oast-ssrf-headers" || f.Severity != model.SeverityHigh {
		t.Fatalf("unexpected finding shape: %+v", f)
	}
	if !strings.Contains(f.Evidence, "vulnerable-app/1.0") {
		t.Fatalf("evidence should include captured user-agent, got: %s", f.Evidence)
	}
}

// TestRunOASTHeaderSSRFProbe_NoCallbackNoFinding ensures the probe stays
// quiet when the target ignores the injected headers.
func TestRunOASTHeaderSSRFProbe_NoCallbackNoFinding(t *testing.T) {
	oastSvc := oast.NewService(oast.Config{TTL: time.Minute})
	oastListener := httptest.NewServer(oastSvc.Handler())
	defer oastListener.Close()
	oastSvc = oast.NewService(oast.Config{TTL: time.Minute, PublicBaseURL: oastListener.URL})
	oastListener.Config.Handler = oastSvc.Handler()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	svc.SetOAST(oastSvc)

	// The probe waits up to defaultOASTSSRFWait for a callback; allow a
	// small buffer over that.
	ctx, cancel := context.WithTimeout(context.Background(), defaultOASTSSRFWait+time.Second)
	defer cancel()
	findings := svc.runOASTHeaderSSRFProbe(ctx, RunInput{Target: target.URL})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestRunOASTHeaderSSRFProbe_DisabledWithoutOAST(t *testing.T) {
	svc := NewService(Config{})
	if got := svc.runOASTHeaderSSRFProbe(context.Background(), RunInput{Target: "http://example.invalid"}); got != nil {
		t.Fatalf("expected nil findings when OAST not configured, got %+v", got)
	}
}
