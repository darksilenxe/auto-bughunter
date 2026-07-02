package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunDNSRebindingProbe_InternalSignatureDetected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		u := body["url"]
		if strings.Contains(u, "127.0.0.1.nip.io") {
			_, _ = w.Write([]byte(`{"fetched":"ami-id: i-0abcd1234"}`))
			return
		}
		_, _ = w.Write([]byte(`{"fetched":"ok"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runDNSRebindingProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) == 0 {
		t.Fatalf("expected at least 1 DNS rebinding finding, got 0")
	}
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-918" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CWE-918 finding, got %+v", findings)
	}
}

func TestRunDNSRebindingProbe_NoDivergenceNoFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"fetched":"ok"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runDNSRebindingProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when responses do not diverge, got %d: %+v", len(findings), findings)
	}
}

func TestRunDNSRebindingProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"fetched":"ami-id"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL}
	in.Options.PassiveOnly = true
	if got := svc.runDNSRebindingProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestRunDNSRebindingProbe_RejectedEndpointNoFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runDNSRebindingProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when control request is rejected, got %d: %+v", len(findings), findings)
	}
}

var _ = model.ScanOptions{}
