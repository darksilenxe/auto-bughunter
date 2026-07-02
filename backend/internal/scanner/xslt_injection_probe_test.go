package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunXSLTInjectionProbe_ReflectedFileRead(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if r.Method == http.MethodPost && strings.Contains(ct, "xml") && strings.Contains(string(body), "xsl:stylesheet") && strings.Contains(string(body), "document(") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte("<abh_probe>root:x:0:0:root:/root:/bin/bash\n</abh_probe>"))
			return
		}
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runXSLTInjectionProbe(context.Background(), RunInput{
		Target:  target.URL + "/xslt-transform",
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/xslt-transform"}},
	}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 XSLT injection finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.ID != "xslt-injection" {
		t.Fatalf("unexpected finding ID: %q", f.ID)
	}
	if f.CWE != "CWE-611" {
		t.Fatalf("expected CWE-611, got %q", f.CWE)
	}
}

func TestRunXSLTInjectionProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<result>ok</result>`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runXSLTInjectionProbe(context.Background(), RunInput{
		Target:  target.URL + "/xslt-transform",
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/xslt-transform"}},
	}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
	}
}

func TestRunXSLTInjectionProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("root:x:0:0:"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL + "/xslt-transform"}
	in.Options.PassiveOnly = true
	if got := svc.runXSLTInjectionProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestRunXSLTInjectionProbe_NoCandidates_NoFindings(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	// Target path has no XSLT-suggestive keyword and no seeded endpoints do
	// either, so no candidates should be collected.
	got := svc.runXSLTInjectionProbe(context.Background(), RunInput{Target: target.URL + "/home"}, "")
	if len(got) != 0 {
		t.Fatalf("expected no findings when no XSLT-like candidates exist, got %d", len(got))
	}
}

func TestCollectXSLTCandidates_MatchesKeywords(t *testing.T) {
	in := RunInput{
		Target: "https://example.com/home",
		Options: model.ScanOptions{
			SeedRuntimeEndpoints: []string{
				"https://example.com/api/xslt-transform",
				"https://example.com/api/unrelated",
			},
		},
	}
	got := collectXSLTCandidates(in)
	found := false
	for _, c := range got {
		if strings.Contains(c, "xslt-transform") {
			found = true
		}
		if strings.Contains(c, "unrelated") {
			t.Fatalf("did not expect unrelated endpoint in XSLT candidates: %v", got)
		}
	}
	if !found {
		t.Fatalf("expected xslt-transform endpoint in candidates: %v", got)
	}
}
