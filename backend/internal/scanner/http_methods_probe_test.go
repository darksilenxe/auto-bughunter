package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunHTTPMethodsProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runHTTPMethodsProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestProbeOptionsMethod_DangerousMethodReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, TRACE")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.probeOptionsMethod(context.Background(), srv.URL, RunInput{Target: srv.URL})
	if len(findings) == 0 {
		t.Fatal("expected finding for TRACE in Allow header")
	}
	hasDangerousTrace := false
	for _, f := range findings {
		if f.CWE == "CWE-16" {
			hasDangerousTrace = true
		}
	}
	if !hasDangerousTrace {
		t.Fatal("expected CWE-16 finding for TRACE method")
	}
}

func TestProbeOptionsMethod_SafeMethodsNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, HEAD")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.probeOptionsMethod(context.Background(), srv.URL, RunInput{Target: srv.URL})
	if len(findings) != 0 {
		t.Fatalf("expected no findings for safe methods, got %d", len(findings))
	}
}

func TestProbeTraceMethod_DetectsXST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACE" {
			w.WriteHeader(http.StatusOK)
			// Echo the request headers back as required by RFC 7231 TRACE behaviour.
			for k, vs := range r.Header {
				for _, v := range vs {
					_, _ = w.Write([]byte(k + ": " + v + "\r\n"))
				}
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	f := svc.probeTraceMethod(context.Background(), srv.URL, RunInput{Target: srv.URL})
	if f == nil {
		t.Fatal("expected XST finding when TRACE echoes headers")
	}
	if f.CWE != "CWE-16" {
		t.Errorf("expected CWE-16, got %s", f.CWE)
	}
}

func TestProbeTraceMethod_NoFindingWhenTraceDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACE" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	f := svc.probeTraceMethod(context.Background(), srv.URL, RunInput{Target: srv.URL})
	if f != nil {
		t.Fatal("expected no finding when TRACE returns 405")
	}
}
