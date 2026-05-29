package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// sensitiveFileBodyLimit caps the per-response read while probing for exposed
// source-control metadata and configuration files.
const sensitiveFileBodyLimit = 64 * 1024

// sensitiveFileProbe describes one exposed-resource check: the path to fetch
// relative to the target origin and the human-readable description of what an
// exposure means.
type sensitiveFileProbe struct {
	path        string
	title       string
	severity    model.Severity
	description string
	cwe         string
}

// sensitiveFileProbes is the curated set of high-signal "should never be
// publicly reachable" resources. They are intentionally limited to GET-able,
// non-destructive paths. Detection is signature-based (the response body must
// match an expected fingerprint), so single-page apps that serve index.html
// for every path do not produce false positives.
var sensitiveFileProbes = []sensitiveFileProbe{
	{".git/HEAD", "Exposed Git repository (.git/HEAD)", model.SeverityHigh,
		"The .git directory is reachable over HTTP. An attacker can reconstruct the full source tree (and any committed secrets) using the exposed Git objects.", "CWE-527"},
	{".git/config", "Exposed Git config (.git/config)", model.SeverityHigh,
		"The Git configuration file is reachable over HTTP, confirming the .git directory is served publicly and the repository can be dumped.", "CWE-527"},
	{".svn/entries", "Exposed Subversion metadata (.svn/entries)", model.SeverityHigh,
		"Subversion working-copy metadata is reachable over HTTP, allowing source recovery.", "CWE-527"},
	{".svn/wc.db", "Exposed Subversion database (.svn/wc.db)", model.SeverityHigh,
		"The Subversion working-copy SQLite database is reachable over HTTP, allowing full source recovery.", "CWE-527"},
	{".hg/requires", "Exposed Mercurial repository (.hg)", model.SeverityHigh,
		"A Mercurial repository directory is reachable over HTTP, allowing source recovery.", "CWE-527"},
	{".env", "Exposed environment file (.env)", model.SeverityCritical,
		"A dotenv configuration file is reachable over HTTP. These files routinely contain database credentials, API keys, and application secrets.", "CWE-200"},
	{".DS_Store", "Exposed macOS .DS_Store directory index", model.SeverityLow,
		"A macOS .DS_Store file is reachable over HTTP and can be parsed to enumerate otherwise-hidden file and directory names.", "CWE-548"},
	{"composer.lock", "Exposed dependency lockfile (composer.lock)", model.SeverityLow,
		"A PHP dependency lockfile is reachable over HTTP, disclosing exact third-party component versions useful for targeting known CVEs.", "CWE-200"},
	{"WEB-INF/web.xml", "Exposed Java deployment descriptor (web.xml)", model.SeverityHigh,
		"The Java WEB-INF deployment descriptor is reachable over HTTP, disclosing servlet mappings and frequently embedded credentials.", "CWE-200"},
}

// runSensitiveFileProbe is an active probe that checks for publicly exposed
// source-control metadata, dotenv files, and deployment descriptors. Each
// candidate is fetched and the response is validated against a content
// signature so generic catch-all 200 responses are not mistaken for an
// exposure.
func (s *Service) runSensitiveFileProbe(ctx context.Context, input RunInput, _ string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("sensitive-files %s", input.Target),
			Message: fmt.Sprintf("Probing %d source-control / configuration paths for public exposure", len(sensitiveFileProbes)),
		})
	}

	var findings []model.Finding
	for _, probe := range sensitiveFileProbes {
		ref, perr := url.Parse(probe.path)
		if perr != nil {
			continue
		}
		probeURL := base.ResolveReference(ref).String()
		if !scope.IsURLInScope(probeURL, input.Scope) {
			continue
		}
		if err := safety.ValidateOutboundURL(probeURL); err != nil {
			continue
		}
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if rerr != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, derr := s.doRequestWithRetry(ctx, req, input.Options)
		if derr != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, sensitiveFileBodyLimit))
		_ = resp.Body.Close()

		if !sensitiveFileExposed(probe.path, resp.StatusCode, resp.Header.Get("Content-Type"), body) {
			continue
		}

		curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
		findings = append(findings, model.Finding{
			ID:          "sensitive-file-" + hhSlug(probe.path),
			Category:    "information-disclosure",
			Severity:    probe.severity,
			Title:       probe.title,
			Description: probe.description,
			Evidence: fmt.Sprintf("GET %s returned HTTP %d with a matching content signature for %q.",
				probeURL, resp.StatusCode, probe.path),
			Recommendation: "Block access to source-control directories and configuration files at the web server / reverse proxy. " +
				"Never deploy .git/.svn/.hg metadata to production document roots, and store secrets outside the web root.",
			Confidence:    0.9,
			AffectedURL:   probeURL,
			CWE:           probe.cwe,
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"active-scanner", "sensitive-files"},
			ReproductionSteps: []string{
				fmt.Sprintf("Send GET %s", probeURL),
				"Confirm the response returns the file content rather than the application's catch-all page.",
				"For exposed VCS metadata, dump the repository (e.g. git-dumper) to recover source and committed secrets.",
			},
			PoC: curl,
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"path":           probe.path,
				"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
				"curlReproducer": curl,
			},
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// sensitiveFileExposed validates a response against the content fingerprint
// expected for the requested path. It deliberately rejects HTML responses
// (the hallmark of a single-page-app catch-all) and requires a successful
// status code so that soft-404 pages are not reported.
func sensitiveFileExposed(path string, status int, contentType string, body []byte) bool {
	if status != http.StatusOK {
		return false
	}
	text := string(body)
	if strings.TrimSpace(text) == "" {
		return false
	}
	ct := strings.ToLower(contentType)
	// HTML responses are almost always a framework catch-all page, never the
	// raw metadata file we asked for.
	htmlLike := strings.Contains(ct, "text/html") ||
		strings.Contains(strings.ToLower(text), "<!doctype html") ||
		strings.Contains(strings.ToLower(text), "<html")

	switch {
	case strings.HasSuffix(path, ".git/HEAD"):
		return strings.HasPrefix(strings.TrimSpace(text), "ref:") || isHexRef(strings.TrimSpace(text))
	case strings.HasSuffix(path, ".git/config"):
		return strings.Contains(text, "[core]") || strings.Contains(text, "repositoryformatversion")
	case strings.HasSuffix(path, ".svn/entries"):
		return !htmlLike && (strings.Contains(text, "svn://") || strings.Contains(text, "dir") || isNumericFirstLine(text))
	case strings.HasSuffix(path, ".svn/wc.db"):
		return strings.HasPrefix(text, "SQLite format 3")
	case strings.HasSuffix(path, ".hg/requires"):
		return !htmlLike && strings.Contains(text, "revlog")
	case strings.HasSuffix(path, ".env"):
		return !htmlLike && envFileSignature(text)
	case strings.HasSuffix(path, ".DS_Store"):
		return strings.HasPrefix(text, "\x00\x00\x00\x01Bud1") || strings.Contains(text, "Bud1")
	case strings.HasSuffix(path, "composer.lock"):
		return !htmlLike && strings.Contains(text, "\"packages\"") && strings.Contains(text, "\"name\"")
	case strings.HasSuffix(path, "web.xml"):
		return strings.Contains(text, "<web-app") || strings.Contains(text, "<servlet")
	}
	return false
}

// envFileSignature heuristically confirms dotenv content: at least one
// KEY=VALUE line using an uppercase/underscore key, and a hint of a
// security-relevant variable.
func envFileSignature(text string) bool {
	lines := strings.Split(text, "\n")
	kvCount := 0
	sensitiveHint := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !isEnvKey(key) {
			continue
		}
		kvCount++
		upper := strings.ToUpper(key)
		for _, marker := range []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "PASS", "DB_", "DATABASE", "API", "AWS", "PRIVATE"} {
			if strings.Contains(upper, marker) {
				sensitiveHint = true
			}
		}
	}
	return kvCount >= 2 && sensitiveHint
}

// isEnvKey reports whether s looks like a dotenv variable name.
func isEnvKey(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// isHexRef reports whether s is a 40-char hex SHA-1 (a detached-HEAD ref).
func isHexRef(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// isNumericFirstLine reports whether the first line of an .svn/entries file is
// the numeric format version emitted by older Subversion clients.
func isNumericFirstLine(text string) bool {
	first := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	if first == "" || len(first) > 4 {
		return false
	}
	for _, r := range first {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
