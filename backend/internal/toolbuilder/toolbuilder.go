// Package toolbuilder lets autonomous agents generate, write, and execute
// custom Python or Bash tools at runtime.  All generated scripts are:
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
)

// ToolSpec describes a dynamically generated tool.
type ToolSpec struct {
	// Name is a short identifier used as the script filename (no extension).
	Name string
	// Language is "python3" or "bash".
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
	regexp.MustCompile(`import\s+subprocess`),       // no spawning sub-processes
	regexp.MustCompile(`os\.system`),                 // no os.system calls
	regexp.MustCompile(`__import__`),                 // no dynamic imports
	regexp.MustCompile(`eval\s*\(`),                  // no eval
	regexp.MustCompile(`exec\s*\(`),                  // no exec
	regexp.MustCompile(`open\s*\(['"][/\\\\]`), // no opening absolute paths (allow relative)
	regexp.MustCompile(`socket\.connect`),             // no raw socket connects (use urllib)
	regexp.MustCompile(`rm\s+-rf`),                   // no recursive deletes
	regexp.MustCompile(`/etc/passwd`),                 // no passwd access
	regexp.MustCompile(`/root`),                       // no /root access
}

func validateScript(code string) error {
	for _, pat := range scriptBlockedPatterns {
		if pat.MatchString(code) {
			return fmt.Errorf("generated script contains a blocked pattern: %s", pat.String())
		}
	}
	return nil
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

	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create tool scratch dir: %w", err)
	}

	ext := ".py"
	interp := "python3"
	if strings.EqualFold(spec.Language, "bash") {
		ext = ".sh"
		interp = "bash"
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
		"jwt_probe":      jwtProbeTool,
		"graphql_probe":  graphqlProbeTool,
		"redirect_probe": redirectProbeTool,
		"header_probe":   headerProbeTool,
		"csp_probe":      cspProbeTool,
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
