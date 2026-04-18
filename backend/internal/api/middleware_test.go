package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestAuthMiddleware_AllowsExemptPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := authMiddleware("secret-token", mux)
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{"/api/health", "/metrics"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for exempt %s, got %d", path, resp.StatusCode)
		}
	}

	// Without token -> 401
	resp, err := http.Get(srv.URL + "/api/scan")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("expected WWW-Authenticate header, got %q", got)
	}

	// With wrong token -> 401
	req, _ := http.NewRequest("GET", srv.URL+"/api/scan", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", resp.StatusCode)
	}

	// With correct token -> 200
	req, _ = http.NewRequest("GET", srv.URL+"/api/scan", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct token, got %d", resp.StatusCode)
	}

	// X-API-Token alternate header
	req, _ = http.NewRequest("GET", srv.URL+"/api/scan", nil)
	req.Header.Set("X-API-Token", "secret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with X-API-Token, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_DisabledWhenTokenEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := authMiddleware("", mux)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/scan")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204 when auth disabled, got %d", resp.StatusCode)
	}
}

func TestRateLimiter_AllowsBelowLimitBlocksAbove(t *testing.T) {
	rl := newRateLimiter(3)
	if rl == nil {
		t.Fatal("expected limiter")
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		ok, _, _ := rl.allow("client-a", now)
		if !ok {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
	ok, remaining, _ := rl.allow("client-a", now)
	if ok {
		t.Errorf("4th request should be blocked")
	}
	if remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", remaining)
	}
	// Different client unaffected.
	if ok, _, _ := rl.allow("client-b", now); !ok {
		t.Errorf("different client should be allowed")
	}
	// New window resets.
	later := now.Add(2 * time.Minute)
	if ok, _, _ := rl.allow("client-a", later); !ok {
		t.Errorf("new window should reset")
	}
}

func TestRateLimiter_DisabledWhenZero(t *testing.T) {
	if rl := newRateLimiter(0); rl != nil {
		t.Errorf("expected nil limiter when limit=0")
	}
	if rl := newRateLimiter(-5); rl != nil {
		t.Errorf("expected nil limiter when limit<0")
	}
}

func TestRateLimitMiddleware_AddsHeadersAnd429(t *testing.T) {
	rl := newRateLimiter(2)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := rateLimitMiddleware(rl, mux)
	srv := httptest.NewServer(h)
	defer srv.Close()

	for i := 0; i < 2; i++ {
		resp, err := http.Get(srv.URL + "/api/scan")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-RateLimit-Limit") != "2" {
			t.Errorf("expected X-RateLimit-Limit=2")
		}
	}
	resp, err := http.Get(srv.URL + "/api/scan")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header")
	}
}

func TestSendWebhookJSON_SignsPayload(t *testing.T) {
	var (
		gotSig  string
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Auto-Bughunter-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	payload := map[string]string{"hello": "world"}
	sendWebhookJSON(srv.URL, payload, "shhh")
	// give the handler a moment in case of any async, though sendWebhookJSON is sync.
	time.Sleep(50 * time.Millisecond)

	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("expected sha256= prefix, got %q", gotSig)
	}
	wantBody, _ := json.Marshal(payload)
	if string(gotBody) != string(wantBody) {
		t.Fatalf("unexpected body: %s vs %s", gotBody, wantBody)
	}
	mac := hmac.New(sha256.New, []byte("shhh"))
	mac.Write(wantBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Errorf("signature mismatch: got %s want %s", gotSig, want)
	}
}

func TestSendWebhookJSON_NoSignatureWhenSecretEmpty(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Auto-Bughunter-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sendWebhookJSON(srv.URL, map[string]string{"k": "v"}, "")
	time.Sleep(50 * time.Millisecond)
	if gotSig != "" {
		t.Errorf("expected no signature header, got %q", gotSig)
	}
}

func TestBuildSARIF_BasicShape(t *testing.T) {
	now := time.Now().UTC()
	completed := now.Add(time.Minute)
	job := &model.ScanJob{
		ID:          "scan-123",
		Target:      "https://example.com",
		Status:      "completed",
		StartedAt:   now,
		CompletedAt: &completed,
		Findings: []model.Finding{
			{
				ID:             "f1",
				Category:       "headers",
				Severity:       model.SeverityHigh,
				Title:          "Missing Strict-Transport-Security",
				Description:    "HSTS is not enabled",
				Recommendation: "Enable HSTS",
				Confidence:     0.95,
				EvidenceFields: map[string]string{"url": "https://example.com/login"},
			},
			{
				ID:       "f2",
				Category: "cookies",
				Severity: model.SeverityLow,
				Title:    "Cookie missing Secure flag",
			},
		},
	}
	doc := buildSARIF(job)
	if doc.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "auto-bughunter" {
		t.Errorf("unexpected driver name: %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	// High severity should sort first.
	if run.Results[0].Level != "error" {
		t.Errorf("expected high to map to error, got %q", run.Results[0].Level)
	}
	if run.Results[1].Level != "note" {
		t.Errorf("expected low to map to note, got %q", run.Results[1].Level)
	}
	// Location should pick up the EvidenceFields[url] for the first result.
	if uri := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "https://example.com/login" {
		t.Errorf("unexpected location uri: %q", uri)
	}
	// And fall back to target for the second.
	if uri := run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "https://example.com" {
		t.Errorf("unexpected fallback uri: %q", uri)
	}
	// Rules should be deduplicated by category/title.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
	// Document must marshal to valid JSON.
	if _, err := json.Marshal(doc); err != nil {
		t.Errorf("sarif must marshal cleanly: %v", err)
	}
}

func TestSanitizeRuleID(t *testing.T) {
	cases := []struct{ cat, title, want string }{
		{"Headers", "Missing X-Frame-Options", "headers/missing-x-frame-options"},
		{"", "", "finding/issue"},
		{"TLS!!!", "Weak Cipher (3DES)", "tls/weak-cipher-3des"},
	}
	for _, c := range cases {
		got := sanitizeRuleID(c.cat, c.title)
		if got != c.want {
			t.Errorf("sanitizeRuleID(%q, %q) = %q, want %q", c.cat, c.title, got, c.want)
		}
	}
}

func TestMetricsEndpointFormat(t *testing.T) {
	// reset by replacing global.
	metrics = &metricsRegistry{}
	metrics.recordScanStarted()
	metrics.recordScanCompleted(true)
	metrics.recordFindings(map[string]int{"high": 2, "low": 1})
	metrics.recordHTTP("GET", 200)
	metrics.recordHTTP("POST", 401)

	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	s.handleMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	mustContain := []string{
		"# TYPE auto_bughunter_scans_total counter",
		"auto_bughunter_scans_total 1",
		`auto_bughunter_scans_completed_total{outcome="succeeded"} 1`,
		`auto_bughunter_findings_total{severity="high"} 2`,
		`auto_bughunter_findings_total{severity="low"} 1`,
		`auto_bughunter_http_requests_total{method="GET",status="200"} 1`,
		`auto_bughunter_http_requests_total{method="POST",status="401"} 1`,
		"auto_bughunter_auth_rejected_requests_total 1",
	}
	for _, want := range mustContain {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in metrics output:\n%s", want, body)
		}
	}
}
