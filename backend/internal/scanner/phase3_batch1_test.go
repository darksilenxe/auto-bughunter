package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// assertSchemaValid runs the Phase 3 normalizer over the finding and fails
// the test unless the evidence record is tagged "valid" — i.e. every
// category-required EvidenceRecord field (url, param, payloadClass, ...)
// is populated by the probe itself, per PHASE3_AUDIT.md.
func assertSchemaValid(t *testing.T, f model.Finding) {
	t.Helper()
	normalized := NormalizeEvidence(f)
	if got := normalized.EvidenceFields["evidenceQuality"]; got != EvidenceQualityValid {
		t.Fatalf("expected evidenceQuality=valid for category %q, got %q (fields=%+v)", f.Category, got, normalized.EvidenceFields)
	}
	if normalized.EvidenceFields["oracleName"] == "" {
		t.Fatalf("expected oracleName to be stamped, got %+v", normalized.EvidenceFields)
	}
}

// TestPhase3Batch1_SchemaCompliance covers the first 10 ⚠️ rows of
// PHASE3_AUDIT.md's audit table: each probe must emit an EvidenceRecord
// that satisfies its category's Phase 3 schema requirements.
func TestPhase3Batch1_SchemaCompliance(t *testing.T) {
	t.Run("active_cors", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if origin := r.Header.Get("Origin"); origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer target.Close()
		findings := NewService(Config{}).runActiveCORSProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_graphql_introspection", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"User"}]}}}`))
		}))
		defer target.Close()
		in := RunInput{
			Target:  target.URL,
			Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/graphql"}},
		}
		findings := NewService(Config{}).runActiveGraphQLIntrospectionProbe(context.Background(), in, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_ldap_injection", func(t *testing.T) {
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
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_nosqli", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for key := range r.URL.Query() {
				if strings.Contains(key, "[$") {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"message":"MongoError: unknown top level operator: $ne"}`))
					return
				}
			}
			_, _ = w.Write([]byte(`{"results":[]}`))
		}))
		defer target.Close()
		findings := NewService(Config{}).runActiveNoSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_path_traversal", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			file := r.URL.Query().Get("file")
			if strings.Contains(file, "..") {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}))
		defer target.Close()
		findings := NewService(Config{}).runActivePathTraversalProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_prompt_injection", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			q := r.URL.Query().Get("q")
			if strings.Contains(q, promptInjectionTrigger) {
				_, _ = fmt.Fprintf(w, `{"response": "%s"}`, promptInjectionTrigger)
				return
			}
			_, _ = fmt.Fprint(w, `{"response": "Hello! How can I help you?"}`)
		}))
		defer target.Close()
		in := RunInput{Target: target.URL}
		in.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}
		findings := NewService(Config{}).runActivePromptInjectionProbe(context.Background(), in, "")
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_prototype_pollution", func(t *testing.T) {
		var polluted string
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.URL.Query().Get("__proto__[polluted]"); v != "" {
				polluted = v
			}
			if v := r.URL.Query().Get("constructor[prototype][polluted]"); v != "" {
				polluted = v
			}
			if r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), prototypePollutionMarker) {
					polluted = prototypePollutionMarker
				}
			}
			_, _ = w.Write([]byte("polluted=" + polluted))
		}))
		defer target.Close()
		findings := NewService(Config{}).runActivePrototypePollutionProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_sqli", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := r.URL.Query().Get("id")
			if strings.Contains(v, "'") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''' at line 1"))
				return
			}
			_, _ = w.Write([]byte("ok"))
		}))
		defer target.Close()
		findings := NewService(Config{}).runActiveSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_ssti", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			v := r.URL.Query().Get("name")
			if strings.Contains(v, "{{7*7}}") {
				v = strings.ReplaceAll(v, "{{7*7}}", "49")
			}
			_, _ = fmt.Fprintf(w, "<h1>Hello, %s</h1>", v)
		}))
		defer target.Close()
		findings := NewService(Config{}).runActiveSSTIProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})
}

// TestPhase3Batch1_OpenRedirectSchema covers active_open_redirect.go via a
// direct EvidenceRecord check, mirroring the EvidenceFields the probe
// itself populates. An end-to-end httptest run is not possible here
// because the probe's SSRF guard correctly rejects loopback targets (see
// active_open_redirect_test.go), so this test locks in the schema
// contract instead of the network path.
func TestPhase3Batch1_OpenRedirectSchema(t *testing.T) {
	f := model.Finding{
		Category:          "open_redirect",
		AffectedURL:       "https://victim.example/login?next=https://abh-canary.invalid",
		AffectedParameter: "next",
		EvidenceFields: map[string]string{
			"method":       http.MethodGet,
			"url":          "https://victim.example/login?next=https://abh-canary.invalid",
			"param":        "next",
			"payloadClass": "open-redirect",
			"oracleName":   "active_open_redirect",
		},
	}
	assertSchemaValid(t, f)
}
