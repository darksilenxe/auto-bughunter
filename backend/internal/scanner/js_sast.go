package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// sastSeverityWeight ranks severities so the per-category finding inherits the
// most serious sink it grouped.
func sastSeverityWeight(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// JavaScript SAST (static application security testing)
//
// During reconnaissance the platform already learns which first-party
// JavaScript bundles a target ships (see secrets_in_jsbundle.go). This file
// adds a lightweight static analysis pass over that same captured source:
//
//   1. It scans the code for dangerous sink/source patterns that indicate a
//      likely client-side vulnerability class (DOM XSS, open redirect, code
//      execution, insecure postMessage handling, etc.). Each pattern category
//      it confirms is reported back so the orchestrator can *tailor* its
//      dynamic vulnerability discovery toward those classes.
//   2. It extracts web-application routes referenced from the code (fetch /
//      axios / XHR calls, framework route tables, and API path literals).
//      These routes are confirmed-from-source, so feeding them to the
//      wordlist enumerator lets it probe real endpoints directly instead of
//      brute-forcing the full wordlist — a faster, higher-signal pass.
//
// The analysis is intentionally regex-based and dependency-free: it runs on
// minified bundles, never executes the code, and keeps the false-positive
// rate low by matching documented sink/source shapes rather than broad
// heuristics.

// sastSinkPattern is one named regex describing a dangerous code construct.
// category maps to a finding/vulnerability class so downstream agents can be
// steered toward (or away from) the relevant active probes.
type sastSinkPattern struct {
	id       string
	category string
	severity model.Severity
	cwe      string
	label    string
	pattern  *regexp.Regexp
}

// sastSinkPatterns is the curated list of client-side weakness signatures.
// Each entry targets a well-known, documented dangerous API and is anchored
// enough to avoid matching ordinary code.
var sastSinkPatterns = []sastSinkPattern{
	{
		id:       "dom-xss-innerhtml",
		category: "xss",
		severity: model.SeverityMedium,
		cwe:      "CWE-79",
		label:    "Assignment to innerHTML/outerHTML (potential DOM XSS sink)",
		pattern:  regexp.MustCompile(`\.(?:inner|outer)HTML\s*[+]?=`),
	},
	{
		id:       "dom-xss-document-write",
		category: "xss",
		severity: model.SeverityMedium,
		cwe:      "CWE-79",
		label:    "document.write/writeln call (potential DOM XSS sink)",
		pattern:  regexp.MustCompile(`document\.write(?:ln)?\s*\(`),
	},
	{
		id:       "dom-xss-insert-adjacent",
		category: "xss",
		severity: model.SeverityMedium,
		cwe:      "CWE-79",
		label:    "insertAdjacentHTML call (potential DOM XSS sink)",
		pattern:  regexp.MustCompile(`\.insertAdjacentHTML\s*\(`),
	},
	{
		id:       "dom-xss-dangerously-set",
		category: "xss",
		severity: model.SeverityMedium,
		cwe:      "CWE-79",
		label:    "React dangerouslySetInnerHTML usage (potential DOM XSS sink)",
		pattern:  regexp.MustCompile(`dangerouslySetInnerHTML`),
	},
	{
		id:       "code-exec-eval",
		category: "code-injection",
		severity: model.SeverityHigh,
		cwe:      "CWE-95",
		label:    "Dynamic code execution via eval()",
		pattern:  regexp.MustCompile(`\beval\s*\(`),
	},
	{
		id:       "code-exec-function-ctor",
		category: "code-injection",
		severity: model.SeverityHigh,
		cwe:      "CWE-95",
		label:    "Dynamic code execution via new Function()",
		pattern:  regexp.MustCompile(`\bnew\s+Function\s*\(`),
	},
	{
		id:       "open-redirect-location",
		category: "open-redirect",
		severity: model.SeverityMedium,
		cwe:      "CWE-601",
		label:    "Assignment to location/location.href (potential open redirect / DOM XSS)",
		pattern:  regexp.MustCompile(`(?:window\.|document\.)?location(?:\.href)?\s*=`),
	},
	{
		id:       "insecure-postmessage",
		category: "input-validation",
		severity: model.SeverityMedium,
		cwe:      "CWE-345",
		label:    "postMessage listener (verify origin is validated)",
		pattern:  regexp.MustCompile(`addEventListener\s*\(\s*['"]message['"]`),
	},
	{
		id:       "client-storage-token",
		category: "information-disclosure",
		severity: model.SeverityLow,
		cwe:      "CWE-922",
		label:    "Token/credential stored in localStorage/sessionStorage",
		pattern:  regexp.MustCompile(`(?:local|session)Storage\.setItem\s*\(\s*['"][^'"]*(?:token|jwt|secret|password|api[_-]?key)`),
	},
}

// sastBugCategory is the category used for genuine code-defect findings
// (correctness bugs in the JavaScript itself) as opposed to security sinks.
// It is deliberately excluded from VulnCategories so it never re-targets the
// active vulnerability probes — a latent bug is reported but does not change
// which exploit classes the platform hunts for.
const sastBugCategory = "code-defect"

// sastBugPatterns flag genuine correctness bugs in the analyzed JavaScript.
// These are not security sinks; they are real defects an attacker or auditor
// would consider broken code. Patterns are anchored to keep false positives
// low even on minified bundles.
var sastBugPatterns = []sastSinkPattern{
	{
		id:       "bug-assignment-in-condition",
		category: sastBugCategory,
		severity: model.SeverityLow,
		cwe:      "CWE-481",
		label:    "Assignment (=) inside an if/while condition instead of comparison",
		// `if (x = y)` / `while (a.b = c)` but not `==`, `===`, `<=`, `>=`, `!=`.
		pattern: regexp.MustCompile(`\b(?:if|while)\s*\(\s*[A-Za-z_$][\w$.\[\]]*\s*=\s*[^=]`),
	},
	{
		id:       "bug-empty-catch",
		category: sastBugCategory,
		severity: model.SeverityLow,
		cwe:      "CWE-390",
		label:    "Empty catch block silently swallows errors",
		pattern:  regexp.MustCompile(`catch\s*\([^)]*\)\s*\{\s*\}`),
	},
	{
		id:       "bug-compare-to-nan",
		category: sastBugCategory,
		severity: model.SeverityLow,
		cwe:      "CWE-697",
		label:    "Comparison against NaN is always false (use isNaN/Number.isNaN)",
		pattern:  regexp.MustCompile(`(?:[=!]==?\s*NaN\b|\bNaN\s*[=!]==?)`),
	},
	{
		id:       "bug-debugger-statement",
		category: sastBugCategory,
		severity: model.SeverityLow,
		cwe:      "CWE-489",
		label:    "Leftover debugger statement in shipped code",
		pattern:  regexp.MustCompile(`\bdebugger\s*;`),
	},
}

// sastMaxScripts caps how many script URLs the SAST pass fetches per scan,
// mirroring the secrets sweep budget so scan time stays bounded.
const sastMaxScripts = 8

// sastMaxBytes caps how much of any single script is analyzed.
const sastMaxBytes int64 = 1 << 20

// sastMaxRoutes caps how many code-discovered routes are surfaced so the
// follow-up wordlist pass stays focused.
const sastMaxRoutes = 40

// JSSASTResult is the structured outcome of a JavaScript SAST pass.
type JSSASTResult struct {
	// Findings are the static weaknesses confirmed in the analyzed code.
	Findings []model.Finding
	// Routes are application paths (e.g. "/api/users", "/admin") extracted
	// from the code. They are de-duplicated and sorted.
	Routes []string
	// VulnCategories is the set of vulnerability classes the static pass
	// flagged (e.g. "xss", "code-injection"). The orchestrator uses these to
	// tailor which active probes to prioritize. Empty when nothing was found.
	VulnCategories []string
	// ScriptsAnalyzed counts how many in-scope bundles were actually fetched
	// and analyzed.
	ScriptsAnalyzed int
}

// jsRoutePatterns extract route/endpoint strings referenced from JS source.
// Each pattern captures the path-bearing string literal in group 1.
var jsRoutePatterns = []*regexp.Regexp{
	// fetch("/api/x"), fetch('/api/x', {...})
	regexp.MustCompile(`fetch\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)`),
	// axios.get('/x'), axios.post("/x"), axios({url:'/x'})
	regexp.MustCompile(`axios\.(?:get|post|put|patch|delete|head|options|request)\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)`),
	regexp.MustCompile(`(?:url|baseURL)\s*:\s*['"` + "`" + `]([^'"` + "`" + `]+)`),
	// XMLHttpRequest .open("GET", "/x")
	regexp.MustCompile(`\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"` + "`" + `]([^'"` + "`" + `]+)`),
	// Framework route tables: path: "/x", route("/x")
	regexp.MustCompile(`(?:path|route|endpoint)\s*:\s*['"` + "`" + `]([^'"` + "`" + `]+)`),
	// Bare absolute-path string literals that look like routes/api paths.
	regexp.MustCompile(`['"` + "`" + `](/(?:api|v\d+|graphql|rest|admin|auth|user|users|account|internal)[A-Za-z0-9_\-/.]*)`),
}

// RunJavaScriptSAST fetches the target's HTML, discovers the JavaScript it
// references, and runs the static analysis pass over those bundles. It is the
// exported entrypoint used by the SAST agent during reconnaissance.
//
// When body is empty it fetches the target itself; callers that already hold
// the baseline HTML may pass it via the optional preFetchedBody to avoid an
// extra request.
func (s *Service) RunJavaScriptSAST(ctx context.Context, input RunInput, preFetchedBody string) (JSSASTResult, error) {
	if err := safety.ValidateOutboundURL(input.Target); err != nil {
		return JSSASTResult{}, fmt.Errorf("target blocked by ssrf policy: %w", err)
	}
	if !scope.IsURLInScope(input.Target, input.Scope) {
		return JSSASTResult{}, fmt.Errorf("target is outside configured scan scope")
	}

	body := preFetchedBody
	if strings.TrimSpace(body) == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
		if err != nil {
			return JSSASTResult{}, err
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			if err == nil {
				err = fmt.Errorf("no response from target")
			}
			return JSSASTResult{}, err
		}
		content, _ := io.ReadAll(io.LimitReader(resp.Body, sastMaxBytes))
		_ = resp.Body.Close()
		body = string(content)
	}

	return s.runJavaScriptSAST(ctx, input, body), nil
}

// runJavaScriptSAST captures every in-scope JavaScript bundle referenced from
// the target's HTML and runs the static analysis described above. It returns a
// structured result; the caller decides how to surface findings and how to
// tailor follow-up scanning.
//
// Like the secrets sweep, it is passive: it only reads resources the
// application already publishes and never injects payloads.
func (s *Service) runJavaScriptSAST(ctx context.Context, input RunInput, body string) JSSASTResult {
	result := JSSASTResult{}
	scriptURLs := extractScriptURLs(input.Target, body, input.Scope)
	if len(scriptURLs) == 0 {
		return result
	}
	if len(scriptURLs) > sastMaxScripts {
		scriptURLs = scriptURLs[:sastMaxScripts]
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("js-sast %s", input.Target),
			Message: fmt.Sprintf("Running static analysis over %d in-scope JS bundle(s)", len(scriptURLs)),
		})
	}

	type sinkHit struct {
		scriptURL string
		id        string
		category  string
		severity  model.Severity
		cwe       string
		label     string
		snippet   string
	}
	var hits []sinkHit
	routeSet := map[string]struct{}{}

	for _, scriptURL := range scriptURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			continue
		}
		content, _ := io.ReadAll(io.LimitReader(resp.Body, sastMaxBytes))
		_ = resp.Body.Close()
		if len(content) == 0 {
			continue
		}
		result.ScriptsAnalyzed++
		text := string(content)

		for _, sp := range sastSinkPatterns {
			if loc := sp.pattern.FindStringIndex(text); loc != nil {
				hits = append(hits, sinkHit{
					scriptURL: scriptURL,
					id:        sp.id,
					category:  sp.category,
					severity:  sp.severity,
					cwe:       sp.cwe,
					label:     sp.label,
					snippet:   sastSnippet(text, loc[0], loc[1]),
				})
			}
		}

		// Static correctness checks: surface genuine bugs in the code itself.
		for _, bp := range sastBugPatterns {
			if loc := bp.pattern.FindStringIndex(text); loc != nil {
				hits = append(hits, sinkHit{
					scriptURL: scriptURL,
					id:        bp.id,
					category:  bp.category,
					severity:  bp.severity,
					cwe:       bp.cwe,
					label:     bp.label,
					snippet:   sastSnippet(text, loc[0], loc[1]),
				})
			}
		}

		for _, route := range extractRoutesFromJS(text, input.Target, input.Scope) {
			routeSet[route] = struct{}{}
		}
	}

	result.Routes = sortedKeys(routeSet)
	if len(result.Routes) > sastMaxRoutes {
		result.Routes = result.Routes[:sastMaxRoutes]
	}

	if len(hits) == 0 {
		return result
	}

	// Group hits by category so we emit one focused finding per weakness
	// class and surface the categories for tailoring.
	byCategory := map[string][]sinkHit{}
	for _, h := range hits {
		byCategory[h.category] = append(byCategory[h.category], h)
	}
	categories := make([]string, 0, len(byCategory))
	vulnCategories := make([]string, 0, len(byCategory))
	for cat := range byCategory {
		categories = append(categories, cat)
		// Genuine code defects are reported but excluded from the tailoring
		// signal so they never re-target the active vulnerability probes.
		if cat != sastBugCategory {
			vulnCategories = append(vulnCategories, cat)
		}
	}
	sort.Strings(categories)
	sort.Strings(vulnCategories)
	result.VulnCategories = vulnCategories

	for _, cat := range categories {
		group := byCategory[cat]
		first := group[0]
		evidence := make([]string, 0, len(group))
		highest := model.SeverityInfo
		for _, h := range group {
			evidence = append(evidence, fmt.Sprintf("%s — %s — %q", h.scriptURL, h.label, h.snippet))
			if sastSeverityWeight(h.severity) > sastSeverityWeight(highest) {
				highest = h.severity
			}
		}
		if cat == sastBugCategory {
			result.Findings = append(result.Findings, model.Finding{
				ID:             "js-sast-code-defect",
				Category:       sastBugCategory,
				Severity:       highest,
				Title:          "Static analysis found likely bug(s) in client-side JavaScript",
				Description:    "A static scan of the application's JavaScript bundles matched patterns associated with genuine correctness defects (for example assignment inside a condition, comparison against NaN, an empty catch block, or a leftover debugger statement). These are code-level bugs rather than directly exploitable vulnerabilities, surfaced so they can be triaged and fixed.",
				Evidence:       fmt.Sprintf("Code-defect matches (%d): %s", len(group), strings.Join(limitStrings(evidence, 8), "; ")),
				Recommendation: "Review each flagged location and fix the underlying defect: use == / === for comparisons, validate numbers with Number.isNaN, handle caught errors, and remove debugger statements before shipping.",
				Confidence:     0.6,
				AffectedURL:    first.scriptURL,
				CWE:            first.cwe,
				Sources:        []string{"js-sast"},
				EvidenceFields: map[string]string{
					"validationType": "static-analysis",
					"defectCount":    fmt.Sprintf("%d", len(group)),
					"firstPattern":   first.id,
				},
			})
			continue
		}
		result.Findings = append(result.Findings, model.Finding{
			ID:             "js-sast-" + cat,
			Category:       cat,
			Severity:       highest,
			Title:          fmt.Sprintf("Static analysis flagged %s sink(s) in client-side JavaScript", cat),
			Description:    "A static scan of the application's JavaScript bundles matched a pattern associated with a known client-side weakness class. This is a code-level signal that the corresponding vulnerability may be reachable at runtime; it has been used to prioritize the matching active probes.",
			Evidence:       fmt.Sprintf("Static sink matches (%d): %s", len(group), strings.Join(limitStrings(evidence, 8), "; ")),
			Recommendation: "Review the flagged sinks and confirm untrusted input cannot reach them. Encode/sanitize before DOM insertion, avoid eval/new Function on dynamic input, validate postMessage origins, and never persist secrets in client-side storage.",
			Confidence:     0.6,
			AffectedURL:    first.scriptURL,
			CWE:            first.cwe,
			Sources:        []string{"js-sast"},
			EvidenceFields: map[string]string{
				"validationType": "static-analysis",
				"sinkCount":      fmt.Sprintf("%d", len(group)),
				"firstPattern":   first.id,
			},
		})
	}

	return result
}

// extractRoutesFromJS pulls application route/endpoint paths out of JS source.
// Returned routes are normalized to in-scope, same-origin absolute paths
// (leading "/"). Cross-origin and non-route literals are discarded.
func extractRoutesFromJS(text, target string, scanScope model.ScanScope) []string {
	out := make([]string, 0)
	seen := map[string]struct{}{}
	for _, re := range jsRoutePatterns {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) < 2 {
				continue
			}
			route := normalizeDiscoveredRoute(m[1], target, scanScope)
			if route == "" {
				continue
			}
			if _, ok := seen[route]; ok {
				continue
			}
			seen[route] = struct{}{}
			out = append(out, route)
		}
	}
	sort.Strings(out)
	return out
}

// normalizeDiscoveredRoute validates a raw string captured from JS and, if it
// represents an in-scope same-origin web route, returns its path component
// (e.g. "/api/users"). It returns "" for anything that is not a usable route.
func normalizeDiscoveredRoute(raw, target string, scanScope model.ScanScope) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Ignore template-literal interpolation and obvious non-paths.
	if strings.ContainsAny(raw, "${}<>() ") {
		return ""
	}
	// Absolute URLs: keep only when same-origin/in-scope; reduce to path.
	if strings.Contains(raw, "://") {
		resolved := resolveEndpoint(target, raw)
		if resolved == "" || !sameOrigin(resolved, target) {
			return ""
		}
		return routePathOnly(resolved)
	}
	// Protocol-relative (//host/...) – treat as cross-origin and skip.
	if strings.HasPrefix(raw, "//") {
		return ""
	}
	// Must be an absolute path to be a server route we can probe.
	if !strings.HasPrefix(raw, "/") {
		return ""
	}
	// Skip static asset references; they are not interesting routes.
	if isStaticAssetPath(raw) {
		return ""
	}
	resolved := resolveEndpoint(target, raw)
	if resolved == "" {
		return ""
	}
	if !scope.IsURLInScope(resolved, scanScope) {
		return ""
	}
	return routePathOnly(resolved)
}

var staticAssetExtRe = regexp.MustCompile(`(?i)\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|json|txt|xml|wasm)(?:[?#].*)?$`)

func isStaticAssetPath(p string) bool {
	return staticAssetExtRe.MatchString(p)
}

// routePathOnly returns the cleaned path (with leading slash) of a URL or
// path string, dropping query and fragment.
func routePathOnly(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if idx := strings.Index(s, "://"); idx >= 0 {
		rest := s[idx+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			s = rest[slash:]
		} else {
			s = "/"
		}
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	// Collapse trailing slash (except root) for stable de-duplication.
	if len(s) > 1 {
		s = strings.TrimRight(s, "/")
		if s == "" {
			s = "/"
		}
	}
	return s
}

// sastSnippet returns a short, single-line, redaction-friendly excerpt of the
// source around a matched sink so triagers can locate it.
func sastSnippet(text string, start, end int) string {
	const pad = 24
	lo := start - pad
	if lo < 0 {
		lo = 0
	}
	hi := end + pad
	if hi > len(text) {
		hi = len(text)
	}
	snippet := text[lo:hi]
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.TrimSpace(snippet)
	if len(snippet) > 120 {
		snippet = snippet[:120]
	}
	return snippet
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
