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

// TestRunActiveNoSQLiProbe_FindsErrorSignature simulates an endpoint that
// leaks a MongoDB driver error when an operator payload is included in the
// query string.
func TestRunActiveNoSQLiProbe_FindsErrorSignature(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trigger a NoSQL error when a bracket-notation key is detected.
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

	svc := NewService(Config{})
	findings := svc.runActiveNoSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 NoSQLi finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-nosqli" {
		t.Fatalf("unexpected finding ID: %q", f.ID)
	}
	if f.Severity != model.SeverityHigh {
		t.Fatalf("expected high severity, got %q", f.Severity)
	}
	if f.CWE != "CWE-943" {
		t.Fatalf("expected CWE-943, got %q", f.CWE)
	}
}

// TestRunActiveNoSQLiProbe_FindsLengthDelta simulates an endpoint that returns
// a significantly larger response when an operator is injected, which the
// probe treats as a successful injection via the length-delta heuristic.
func TestRunActiveNoSQLiProbe_FindsLengthDelta(t *testing.T) {
	// Simulate an auth endpoint that returns all users when $ne is injected.
	largeBody := `{"users":[` + strings.Repeat(`{"id":1,"email":"a@b.com"},`, 30) + `{"id":999}]}`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key := range r.URL.Query() {
			if strings.Contains(key, "[$") {
				_, _ = w.Write([]byte(largeBody))
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveNoSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 NoSQLi finding from length delta, got %d", len(findings))
	}
}

// TestRunActiveNoSQLiProbe_JSONBodyErrorSignature simulates a POST endpoint
// that returns a MongoDB error when an operator is injected in the JSON body.
func TestRunActiveNoSQLiProbe_JSONBodyErrorSignature(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			_, _ = w.Write([]byte("ok"))
			return
		}
		var parsed map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&parsed); err != nil {
			_, _ = w.Write([]byte("ok"))
			return
		}
		for _, v := range parsed {
			if m, ok := v.(map[string]interface{}); ok {
				if _, hasOp := m["$where"]; hasOp {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"MongoError: queryfailed: $where not allowed"}`))
					return
				}
			}
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveNoSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 NoSQLi finding from JSON body, got %d", len(findings))
	}
}

// TestRunActiveNoSQLiProbe_NoFindingWhenSafe ensures the probe stays silent
// when the target returns consistent, short responses.
func TestRunActiveNoSQLiProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveNoSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no NoSQLi findings, got %d: %+v", len(findings), findings)
	}
}

// TestRunActiveNoSQLiProbe_PassiveOnlyDisables verifies the probe respects
// the PassiveOnly flag.
func TestRunActiveNoSQLiProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":"MongoError: queryfailed"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL}
	in.Options.PassiveOnly = true
	if got := svc.runActiveNoSQLiProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable NoSQLi probe, got %d findings", len(got))
	}
}

// TestMatchNoSQLErrorSignature validates the signature matcher.
func TestMatchNoSQLErrorSignature(t *testing.T) {
	cases := map[string]string{
		`{"message":"MongoError: unknown top level operator"}`: "mongoerror",
		`Internal server error`:                                "",
		``:                                                     "",
		`queryfailed: bad operator`:                            "queryfailed",
	}
	for body, want := range cases {
		got := matchNoSQLErrorSignature(body)
		if got != want {
			t.Fatalf("matchNoSQLErrorSignature(%q) = %q, want %q", body, got, want)
		}
	}
}

// TestIsLikelyAuthEndpoint validates auth-endpoint heuristic.
func TestIsLikelyAuthEndpoint(t *testing.T) {
	if !isLikelyAuthEndpoint("/api/login") {
		t.Fatal("expected /api/login to match")
	}
	if !isLikelyAuthEndpoint("/auth/token") {
		t.Fatal("expected /auth/token to match")
	}
	if isLikelyAuthEndpoint("/api/products") {
		t.Fatal("expected /api/products not to match")
	}
}

// TestRunActiveNoSQLiProbe_SuppressesStaticErrorPage verifies the Phase 1
// differential re-verify strips false positives where the endpoint always
// emits a NoSQL error signature regardless of input.
func TestRunActiveNoSQLiProbe_SuppressesStaticErrorPage(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return a NoSQL error signature — this is baseline noise,
		// not payload-specific. Differential re-verify must strip it.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"MongoError: unknown top level operator: $ne"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveNoSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("static error page should be stripped by differential re-verify, got %d findings", len(findings))
	}
}

// TestRunActiveNoSQLiProbe_EmitsPreReportVerifierStamps verifies the Phase 1
// pre-report verification path stamps the emitted finding with
// verifiedBy=active-nosqli and preserves the external "input-validation"
// category label.
func TestRunActiveNoSQLiProbe_EmitsPreReportVerifierStamps(t *testing.T) {
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

	svc := NewService(Config{})
	findings := svc.runActiveNoSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 NoSQLi finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Category != "input-validation" {
		t.Fatalf("expected external category %q preserved, got %q", "input-validation", f.Category)
	}
	if got := f.EvidenceFields["preReport.verifiedBy"]; got != "active-nosqli@v1" {
		t.Fatalf("expected preReport.verifiedBy=active-nosqli@v1, got %q", got)
	}
	// nosqli is a strict-emission category with MinCoverage=1.0; the
	// finding's rich description should satisfy the proof-policy rules
	// and the three provided evidence signals should meet the min.
	if got := f.EvidenceFields["preReport.verified"]; got != "true" {
		t.Fatalf("expected preReport.verified=true, got %q (reason=%q)", got, f.EvidenceFields["preReport.reason"])
	}
}

// Silence unused-import warnings for the json package (kept for parity with
// existing tests that construct JSON bodies).
var _ = json.Marshal
