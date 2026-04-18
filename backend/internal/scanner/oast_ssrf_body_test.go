package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/oast"
)

// TestRunOASTBodySSRFProbe_FiresOnVulnerableTarget simulates a JSON
// endpoint that fetches whatever URL it finds in a "callback" field. The
// probe must observe the OAST callback and emit a high-severity finding.
func TestRunOASTBodySSRFProbe_FiresOnVulnerableTarget(t *testing.T) {
	oastSvc := oast.NewService(oast.Config{TTL: time.Minute})
	listener := httptest.NewServer(oastSvc.Handler())
	defer listener.Close()
	oastSvc = oast.NewService(oast.Config{TTL: time.Minute, PublicBaseURL: listener.URL})
	listener.Config.Handler = oastSvc.Handler()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8*1024))
		var obj map[string]string
		if json.Unmarshal(body, &obj) == nil {
			if u := obj["callback"]; strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
				req, _ := http.NewRequest(http.MethodGet, u+"/triggered", nil)
				req.Header.Set("User-Agent", "vuln-body/1.0")
				if resp, err := http.DefaultClient.Do(req); err == nil {
					resp.Body.Close()
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	svc.SetOAST(oastSvc)

	findings := svc.runOASTBodySSRFProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 body-SSRF finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "oast-ssrf-body-params" || f.Severity != model.SeverityHigh {
		t.Fatalf("unexpected finding shape: %+v", f)
	}
	if !strings.Contains(f.Evidence, "vuln-body/1.0") {
		t.Fatalf("evidence should include captured user-agent, got: %s", f.Evidence)
	}
}

// TestRunOASTBodySSRFProbe_NoCallbackNoFinding ensures the probe stays
// silent when the target does not dereference any body parameter.
func TestRunOASTBodySSRFProbe_NoCallbackNoFinding(t *testing.T) {
	oastSvc := oast.NewService(oast.Config{TTL: time.Minute})
	listener := httptest.NewServer(oastSvc.Handler())
	defer listener.Close()
	oastSvc = oast.NewService(oast.Config{TTL: time.Minute, PublicBaseURL: listener.URL})
	listener.Config.Handler = oastSvc.Handler()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	svc.SetOAST(oastSvc)

	ctx, cancel := context.WithTimeout(context.Background(), defaultOASTBodySSRFWait+time.Second)
	defer cancel()
	findings := svc.runOASTBodySSRFProbe(ctx, RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestRunOASTBodySSRFProbe_DisabledWithoutOAST(t *testing.T) {
	svc := NewService(Config{})
	if got := svc.runOASTBodySSRFProbe(context.Background(), RunInput{Target: "http://example.invalid"}, ""); got != nil {
		t.Fatalf("expected nil findings when OAST not configured, got %+v", got)
	}
}

func TestUniqueEndpoints(t *testing.T) {
	in := []string{"a", "b", "a", "", "c", "b"}
	got := uniqueEndpoints(in)
	want := []string{"a", "b", "c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("uniqueEndpoints = %v, want %v", got, want)
	}
}
