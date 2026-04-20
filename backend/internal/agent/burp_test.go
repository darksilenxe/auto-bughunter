package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newBurpInput(target string) AgentInput {
	return AgentInput{
		Target:      target,
		AuthProfile: model.ScanAuthProfile{},
		Options:     model.ScanOptions{},
	}
}

// ── BurpAgent basics ──────────────────────────────────────────────────────────

func TestBurpAgent_Name(t *testing.T) {
	a := NewBurpAgent(true)
	if a.Name() != "burp" {
		t.Errorf("expected name 'burp', got %q", a.Name())
	}
}

func TestBurpAgent_Disabled(t *testing.T) {
	a := NewBurpAgent(false)
	if a.Enabled() {
		t.Error("expected disabled agent to report Enabled()=false")
	}
}

func TestBurpAgent_RunNoEnterprise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello")) //nolint:errcheck
	}))
	defer srv.Close()

	t.Setenv("BURP_API_URL", "")
	t.Setenv("BURP_API_KEY", "")

	a := NewBurpAgent(true)
	out, err := a.Run(context.Background(), newBurpInput(srv.URL))
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if out.AgentName != "burp" {
		t.Errorf("wrong AgentName: %s", out.AgentName)
	}
	if out.Status != "completed" {
		t.Errorf("expected status 'completed', got %q", out.Status)
	}
	if out.Metadata["active_checks_run"] != "10" {
		t.Errorf("expected active_checks_run=10, got %q", out.Metadata["active_checks_run"])
	}

	// Without BURP_API_URL, there should be an info finding about enterprise not configured.
	found := false
	for _, f := range out.Findings {
		if f.ID == "burp-enterprise-not-configured" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'burp-enterprise-not-configured' info finding when BURP_API_URL is empty")
	}
}

// ── Factory registration ──────────────────────────────────────────────────────

func TestFactory_BurpRegistered(t *testing.T) {
	f := NewFactory(nil, nil)
	names := f.Names()
	found := false
	for _, n := range names {
		if n == "burp" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'burp' agent not registered in factory; got: %v", names)
	}
}

func TestFactory_CreateBurp(t *testing.T) {
	f := NewFactory(nil, nil)
	a, err := f.Create("burp")
	if err != nil {
		t.Fatalf("Create('burp') returned error: %v", err)
	}
	if a == nil {
		t.Fatal("Create('burp') returned nil agent")
	}
	if a.Name() != "burp" {
		t.Errorf("unexpected agent name: %s", a.Name())
	}
}

// ── burpExtractParams ─────────────────────────────────────────────────────────

func TestBurpExtractParams_FromURL(t *testing.T) {
	params := burpExtractParams("https://example.com/search?q=test&id=42")
	qFound := false
	idFound := false
	for _, p := range params {
		if p == "q" {
			qFound = true
		}
		if p == "id" {
			idFound = true
		}
	}
	if !qFound {
		t.Error("expected 'q' in params extracted from URL")
	}
	if !idFound {
		t.Error("expected 'id' in params extracted from URL")
	}
}

func TestBurpExtractParams_CommonParams(t *testing.T) {
	// Even a URL with no query string should return common params.
	params := burpExtractParams("https://example.com/page")
	if len(params) == 0 {
		t.Error("expected at least common params when URL has no query string")
	}
}

// ── injectParam ───────────────────────────────────────────────────────────────

func TestInjectParam_AddsNew(t *testing.T) {
	result, err := injectParam("https://example.com/search", "q", "<script>test</script>")
	if err != nil {
		t.Fatalf("injectParam returned error: %v", err)
	}
	if !strings.Contains(result, "q=") {
		t.Errorf("expected result to contain q= parameter, got: %s", result)
	}
}

func TestInjectParam_ReplacesExisting(t *testing.T) {
	result, err := injectParam("https://example.com/search?q=original", "q", "injected")
	if err != nil {
		t.Fatalf("injectParam returned error: %v", err)
	}
	if strings.Contains(result, "original") {
		t.Errorf("expected original value to be replaced, got: %s", result)
	}
}

// ── burpScanXSS ───────────────────────────────────────────────────────────────

func TestBurpScanXSS_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>safe response</body></html>")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanXSS(context.Background(), client, srv.URL+"?q=test", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no XSS findings on safe server, got %d", len(findings))
	}
}

func TestBurpScanXSS_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Reflect the q parameter value unencoded.
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanXSS(context.Background(), client, srv.URL+"?q=test", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected XSS finding when payload is reflected in HTML")
	}
	if len(findings) > 0 && findings[0].ID != "burp-reflected-xss" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
	if len(findings) > 0 && findings[0].AffectedParameter == "" {
		t.Error("XSS finding should populate AffectedParameter")
	}
}

// ── burpScanSQLi ──────────────────────────────────────────────────────────────

func TestBurpScanSQLi_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("results: []")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanSQLi(context.Background(), client, srv.URL+"?id=1", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no SQLi findings, got %d", len(findings))
	}
}

func TestBurpScanSQLi_ErrorBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			// Simulate a SQL error message leaking.
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("You have an error in your SQL syntax near 'baseline_value_8f3a2b'")) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanSQLi(context.Background(), client, srv.URL+"?id=1", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected SQLi finding when SQL error is in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-sqli-error" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanCmdInjection ──────────────────────────────────────────────────────

func TestBurpScanCmdInjection_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("no command output here")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanCmdInjection(context.Background(), client, srv.URL+"?q=test", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no command injection findings, got %d", len(findings))
	}
}

func TestBurpScanCmdInjection_Vulnerable(t *testing.T) {
	canary := "BURPCMD_CANARY_8f3a2b"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Simulate command execution returning the canary.
		if strings.Contains(q, "echo") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(canary)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanCmdInjection(context.Background(), client, srv.URL+"?q=test", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected command injection finding when canary is in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-cmd-injection" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanPathTraversal ─────────────────────────────────────────────────────

func TestBurpScanPathTraversal_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("page content")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanPathTraversal(context.Background(), client, srv.URL+"?file=index.html", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no path traversal findings, got %d", len(findings))
	}
}

func TestBurpScanPathTraversal_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any request returns passwd content.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanPathTraversal(context.Background(), client, srv.URL+"?file=index.html", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected path traversal finding when /etc/passwd content is in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-path-traversal" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanSSTI ─────────────────────────────────────────────────────────────

func TestBurpScanSSTI_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Echo back the payload literally (not evaluated).
		q := r.URL.Query().Get("q")
		w.Write([]byte(q)) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanSSTI(context.Background(), client, srv.URL+"?q=hello", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no SSTI findings when expression is echoed literally, got %d", len(findings))
	}
}

func TestBurpScanSSTI_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate template evaluation returning 49.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Result: 49")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanSSTI(context.Background(), client, srv.URL+"?q=hello", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected SSTI finding when 49 is in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-ssti" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanXXE ───────────────────────────────────────────────────────────────

func TestBurpScanXXE_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<response>ok</response>")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanXXE(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no XXE findings, got %d", len(findings))
	}
}

func TestBurpScanXXE_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate server returning /etc/passwd content in the response.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanXXE(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected XXE finding when /etc/passwd content is in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-xxe" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanOpenRedirect ──────────────────────────────────────────────────────

func TestBurpScanOpenRedirect_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanOpenRedirect(context.Background(), client, srv.URL+"?redirect=https://safe.example.com", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no open redirect findings, got %d", len(findings))
	}
}

func TestBurpScanOpenRedirect_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("redirect")
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// noFollowClient needed — burpScanOpenRedirect uses its own no-follow client internally.
	client := &http.Client{}
	findings := burpScanOpenRedirect(context.Background(), client, srv.URL+"?redirect=https://safe.example.com", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected open redirect finding when server redirects to injected URL")
	}
	if len(findings) > 0 && findings[0].ID != "burp-open-redirect" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanCRLF ─────────────────────────────────────────────────────────────

func TestBurpScanCRLF_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanCRLF(context.Background(), client, srv.URL+"?q=test", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no CRLF findings, got %d", len(findings))
	}
}

func TestBurpScanCRLF_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the query param value as a response header (simulates header injection).
		q := r.URL.Query().Get("q")
		// Simulate the injected header being set.
		if strings.Contains(q, "CRLF_CANARY") {
			w.Header().Set("X-Burp-CRLF-Test", "CRLF_CANARY_8f3a2b")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanCRLF(context.Background(), client, srv.URL+"?q=test", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected CRLF finding when injected header appears in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-crlf-injection" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanDeserialisation ───────────────────────────────────────────────────

func TestBurpScanDeserialisation_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("generic response")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanDeserialisation(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no deserialisation findings, got %d", len(findings))
	}
}

func TestBurpScanDeserialisation_JavaIndicator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "java-serialized") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("java.lang.ClassNotFoundException: java.io.Serializable not found during deserializ")) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanDeserialisation(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected deserialisation finding when Java deserialization keyword is in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-deserialisation-java" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpScanLDAPInjection ─────────────────────────────────────────────────────

func TestBurpScanLDAPInjection_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("user not found")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanLDAPInjection(context.Background(), client, srv.URL+"?username=admin", model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no LDAP injection findings, got %d", len(findings))
	}
}

func TestBurpScanLDAPInjection_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		if strings.Contains(username, "*") || strings.Contains(username, ")(") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("LDAP filter error: invalid distinguished name syntax ldap_search failed")) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("user not found")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := burpScanLDAPInjection(context.Background(), client, srv.URL+"?username=admin", model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected LDAP injection finding when LDAP error is in response")
	}
	if len(findings) > 0 && findings[0].ID != "burp-ldap-injection" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── burpSeverityToModel ───────────────────────────────────────────────────────

func TestBurpSeverityToModel(t *testing.T) {
	tests := []struct {
		input    string
		expected model.Severity
	}{
		{"high", model.SeverityHigh},
		{"High", model.SeverityHigh},
		{"HIGH", model.SeverityHigh},
		{"medium", model.SeverityMedium},
		{"low", model.SeverityLow},
		{"info", model.SeverityInfo},
		{"informational", model.SeverityInfo},
		{"unknown", model.SeverityInfo},
		{"", model.SeverityInfo},
	}
	for _, tc := range tests {
		got := burpSeverityToModel(tc.input)
		if got != tc.expected {
			t.Errorf("burpSeverityToModel(%q): expected %s, got %s", tc.input, tc.expected, got)
		}
	}
}

// ── Finding field completeness ────────────────────────────────────────────────

func TestBurpFindings_HaveRequiredFields(t *testing.T) {
	// A server that echoes params (XSS), returns passwd (traversal), and
	// SQL error keyword (SQLi) — triggers several checks in one pass.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		q := r.URL.Query().Get("q")
		body := fmt.Sprintf("%s root:x:0:0 sql syntax error Result: 49", q)
		w.Write([]byte(body)) //nolint:errcheck
	}))
	defer srv.Close()

	t.Setenv("BURP_API_URL", "")
	t.Setenv("BURP_API_KEY", "")

	a := NewBurpAgent(true)
	out, err := a.Run(context.Background(), newBurpInput(srv.URL+"?q=hello&id=1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range out.Findings {
		if f.ID == "burp-enterprise-not-configured" {
			continue
		}
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Title == "" {
			t.Errorf("finding %s has empty Title", f.ID)
		}
		if f.Category == "" {
			t.Errorf("finding %s has empty Category", f.ID)
		}
		if f.Severity == "" {
			t.Errorf("finding %s has empty Severity", f.ID)
		}
		if f.Recommendation == "" {
			t.Errorf("finding %s has empty Recommendation", f.ID)
		}
		if f.OWASPCategory == "" {
			t.Errorf("finding %s has empty OWASPCategory", f.ID)
		}
		if f.CWE == "" {
			t.Errorf("finding %s has empty CWE", f.ID)
		}
	}
}
