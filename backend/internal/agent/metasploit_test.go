package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newMetasploitInput(target string) AgentInput {
	return AgentInput{
		Target:      target,
		AuthProfile: model.ScanAuthProfile{},
		Options:     model.ScanOptions{},
	}
}

// ── MetasploitAgent.Run ───────────────────────────────────────────────────────

func TestMetasploitAgent_Name(t *testing.T) {
	a := NewMetasploitAgent(true)
	if a.Name() != "metasploit" {
		t.Errorf("expected name 'metasploit', got %q", a.Name())
	}
}

func TestMetasploitAgent_Disabled(t *testing.T) {
	a := NewMetasploitAgent(false)
	if a.Enabled() {
		t.Error("expected disabled agent to report Enabled()=false")
	}
}

func TestMetasploitAgent_RunNoRPC(t *testing.T) {
	// Start a minimal test server that always returns 200 OK with an empty body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("MSF_RPC_URL", "")

	a := NewMetasploitAgent(true)
	out, err := a.Run(context.Background(), newMetasploitInput(srv.URL))
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if out.AgentName != "metasploit" {
		t.Errorf("wrong AgentName: %s", out.AgentName)
	}
	if out.Status != "completed" {
		t.Errorf("expected status 'completed', got %q", out.Status)
	}

	// Without MSF_RPC_URL, exactly one info finding must appear about RPC not configured.
	rpcNotConfigured := false
	for _, f := range out.Findings {
		if f.ID == "metasploit-rpc-not-configured" {
			rpcNotConfigured = true
		}
	}
	if !rpcNotConfigured {
		t.Error("expected a 'metasploit-rpc-not-configured' info finding when MSF_RPC_URL is empty")
	}
}

// ── Log4Shell probe ───────────────────────────────────────────────────────────

func TestProbeLog4Shell_NoReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello world")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeLog4Shell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings on non-vulnerable server, got %d", len(findings))
	}
}

func TestProbeLog4Shell_ReflectedPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the User-Agent header — simulates a vulnerable app reflecting jndi.
		ua := r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(ua)) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeLog4Shell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected at least one finding when jndi payload is reflected")
	}
	if len(findings) > 0 && findings[0].ID != "msf-log4shell" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeLog4Shell_StatusFlip500(t *testing.T) {
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First request (baseline) is 200; all subsequent are 500.
		if first {
			first = false
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeLog4Shell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected a finding on 200→500 status flip")
	}
	if len(findings) > 0 && findings[0].Severity != model.SeverityHigh {
		t.Errorf("expected High severity, got %s", findings[0].Severity)
	}
}

// ── Shellshock probe ──────────────────────────────────────────────────────────

func TestProbeShellshock_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeShellshock(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestProbeShellshock_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate the canary string being echoed (as if bash executed the injected cmd).
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("SHELLSHOCK_CANARY_8f3a2b\n")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeShellshock(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected a Shellshock finding when canary is returned")
	}
	if len(findings) > 0 && findings[0].ID != "msf-shellshock" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── Apache path traversal probe ───────────────────────────────────────────────

func TestProbeApachePathTraversal_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeApachePathTraversal(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestProbeApachePathTraversal_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeApachePathTraversal(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected a path traversal finding when /etc/passwd content is returned")
	}
	if len(findings) > 0 && findings[0].ID != "msf-apache-path-traversal" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── HTTP PUT webshell probe ───────────────────────────────────────────────────

func TestProbeHTTPPutWebshell_NotAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeHTTPPutWebshell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings when PUT is rejected, got %d", len(findings))
	}
}

func TestProbeHTTPPutWebshell_PutAcceptedNoExec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			// Return the raw PHP source without the canary in plaintext —
			// the server serves the file as text/plain, not executing the PHP.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<?php echo 'hello'; ?>")) //nolint:errcheck
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeHTTPPutWebshell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	// Should report misconfiguration (PUT allowed) but NOT full RCE.
	if len(findings) == 0 {
		t.Error("expected at least one finding when PUT is accepted")
	}
	for _, f := range findings {
		if f.ID == "msf-http-put-webshell" {
			t.Error("should not report full RCE when PHP was not executed")
		}
		if f.ID == "msf-http-put-allowed" && f.Severity != model.SeverityMedium {
			t.Errorf("expected Medium severity for PUT-allowed, got %s", f.Severity)
		}
	}
}

func TestProbeHTTPPutWebshell_FullRCE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			// Canary is executed — full RCE confirmed.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("HTTPPUT_PROBE_8f3a2b")) //nolint:errcheck
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeHTTPPutWebshell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	rce := false
	for _, f := range findings {
		if f.ID == "msf-http-put-webshell" {
			rce = true
		}
	}
	if !rce {
		t.Error("expected msf-http-put-webshell finding when canary is returned")
	}
}

// ── Spring4Shell probe ────────────────────────────────────────────────────────

func TestProbeSpring4Shell_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeSpring4Shell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings on non-vulnerable server, got %d", len(findings))
	}
}

func TestProbeSpring4Shell_ReflectedKeyword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First request is baseline (GET /); subsequent requests reflect classloader keyword.
		if r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("home")) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Error: classloader chain detected")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeSpring4Shell(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected a Spring4Shell finding when classloader keyword is reflected")
	}
}

// ── PHP CGI probe ─────────────────────────────────────────────────────────────

func TestProbePHPCGIInjection_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probePHPCGIInjection(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestProbePHPCGIInjection_SourceDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".php") {
			w.WriteHeader(http.StatusOK)
			// Return raw PHP source — simulates -s flag revealing source code.
			w.Write([]byte("<?php echo 'hello'; ?>")) //nolint:errcheck
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probePHPCGIInjection(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected a PHP CGI finding when PHP source is disclosed")
	}
	if len(findings) > 0 && findings[0].ID != "msf-php-cgi-injection" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

// ── Factory registration ──────────────────────────────────────────────────────

func TestFactory_MetasploitRegistered(t *testing.T) {
	f := NewFactory(nil, nil)
	names := f.Names()
	found := false
	for _, n := range names {
		if n == "metasploit" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'metasploit' agent not registered in factory; got: %v", names)
	}
}

func TestFactory_CreateMetasploit(t *testing.T) {
	f := NewFactory(nil, nil)
	a, err := f.Create("metasploit")
	if err != nil {
		t.Fatalf("Create('metasploit') returned error: %v", err)
	}
	if a == nil {
		t.Fatal("Create('metasploit') returned nil agent")
	}
	if a.Name() != "metasploit" {
		t.Errorf("unexpected agent name: %s", a.Name())
	}
}

// ── Finding field completeness ────────────────────────────────────────────────

func TestMetasploitFindings_HaveRequiredFields(t *testing.T) {
	// Use a server that always reflects jndi to trigger Log4Shell, and
	// also returns /etc/passwd for traversal checks, etc.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		default:
			ua := r.Header.Get("User-Agent")
			body := "root:x:0:0\nSHELLSHOCK_CANARY_8f3a2b\nclassloader\n" + ua
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(body)) //nolint:errcheck
		}
	}))
	defer srv.Close()

	t.Setenv("MSF_RPC_URL", "")

	a := NewMetasploitAgent(true)
	out, err := a.Run(context.Background(), newMetasploitInput(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range out.Findings {
		if f.ID == "metasploit-rpc-not-configured" {
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
	}
}

// ── Extended probe tests ──────────────────────────────────────────────────────

func TestProbeDrupalgeddon2_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("no drupal here")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeDrupalgeddon2(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings on non-vulnerable server, got %d", len(findings))
	}
}

func TestProbeDrupalgeddon2_Vulnerable(t *testing.T) {
	canary := "DRUPAL_CVE201876_CANARY"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate Drupal echoing the canary as if passthru was executed.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(canary)) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeDrupalgeddon2(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected Drupalgeddon2 finding when canary is in response")
	}
	if len(findings) > 0 && findings[0].ID != "msf-drupalgeddon2" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeConfluenceOGNL_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeConfluenceOGNL(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestProbeConfluenceOGNL_Vulnerable(t *testing.T) {
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Atlassian Confluence ognl error valuestack")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeConfluenceOGNL(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected Confluence OGNL finding when keyword is in response")
	}
	if len(findings) > 0 && findings[0].ID != "msf-confluence-ognl" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeJenkinsScriptConsole_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeJenkinsScriptConsole(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings on protected Jenkins, got %d", len(findings))
	}
}

func TestProbeJenkinsScriptConsole_Exposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/script" {
			w.WriteHeader(http.StatusOK)
			// Return a Jenkins-like script console page.
			w.Write([]byte(`<html><body><textarea id="script"></textarea><button>Run Script</button><p>groovy script console</p></body></html>`)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeJenkinsScriptConsole(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected Jenkins script console finding when endpoint is exposed")
	}
	if len(findings) > 0 && findings[0].ID != "msf-jenkins-script-console" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeCitrixADCTraversal_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeCitrixADCTraversal(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestProbeCitrixADCTraversal_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[global]\nworkgroup = WORKGROUP\n")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeCitrixADCTraversal(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected Citrix traversal finding when smb.conf is returned")
	}
	if len(findings) > 0 && findings[0].ID != "msf-citrix-adc-traversal" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeThinkPHPRCE_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("normal app response")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeThinkPHPRCE(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestProbeThinkPHPRCE_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("PHP Version 7.4.3 phpinfo() zend engine details")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeThinkPHPRCE(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected ThinkPHP RCE finding when phpinfo() is in response")
	}
	if len(findings) > 0 && findings[0].ID != "msf-thinkphp-rce" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeExchangeProxyLogon_NotExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeExchangeProxyLogon(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	// Should produce no findings when the server is not Exchange.
	if len(findings) > 0 {
		t.Errorf("expected no findings on non-Exchange server, got %d", len(findings))
	}
}

func TestProbeExchangeProxyLogon_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fingerprinting paths return Exchange indicators.
		if strings.Contains(r.URL.Path, "/owa") {
			w.Header().Set("X-OWA-Version", "15.1.2375.7")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Microsoft Exchange Server OWA")) //nolint:errcheck
			return
		}
		// ProxyLogon SSRF endpoint.
		if strings.Contains(r.URL.Path, "proxyLogon") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("exchange proxylogon ssrf response")) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeExchangeProxyLogon(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Error("expected Exchange ProxyLogon finding on vulnerable server")
	}
	if len(findings) > 0 && findings[0].ID != "msf-exchange-proxylogon" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeWebAssemblyModuleAbuse_NotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>no wasm</html>")) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeWebAssemblyModuleAbuse(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) > 0 {
		t.Errorf("expected no findings when no wasm module is exposed, got %d", len(findings))
	}
}

func TestProbeWebAssemblyModuleAbuse_DetectedNoUpload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/app.wasm" {
			w.Header().Set("Content-Type", "application/wasm")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}) //nolint:errcheck
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeWebAssemblyModuleAbuse(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Fatal("expected a wasm surface finding when wasm module is detected")
	}
	if findings[0].ID != "msf-wasm-surface-detected" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestProbeWebAssemblyModuleAbuse_ExploitableUpload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/app.wasm":
			w.Header().Set("Content-Type", "application/wasm")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}) //nolint:errcheck
		case r.Method == http.MethodPut && r.URL.Path == "/uploads/abh_probe_8f3a2b.wasm":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/uploads/abh_probe_8f3a2b.wasm":
			w.Header().Set("Content-Type", "application/wasm")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}) //nolint:errcheck
		case r.Method == http.MethodDelete && r.URL.Path == "/uploads/abh_probe_8f3a2b.wasm":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &http.Client{}
	findings := probeWebAssemblyModuleAbuse(context.Background(), client, srv.URL, model.ScanAuthProfile{})
	if len(findings) == 0 {
		t.Fatal("expected a wasm exploit finding when upload/overwrite works")
	}
	if findings[0].ID != "msf-wasm-module-overwrite" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("expected High severity, got %s", findings[0].Severity)
	}
}

func TestFactory_NativeProbesCount(t *testing.T) {
	t.Setenv("MSF_RPC_URL", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := NewMetasploitAgent(true)
	out, err := a.Run(context.Background(), newMetasploitInput(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Metadata["native_probes_run"] != "14" {
		t.Errorf("expected native_probes_run=14, got %q", out.Metadata["native_probes_run"])
	}
}
