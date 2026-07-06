package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// verboseErrorBodyLimit caps response body reads during error probing.
const verboseErrorBodyLimit = 128 * 1024

// verboseErrorMaxEndpoints caps how many endpoints are probed per scan.
const verboseErrorMaxEndpoints = 8

// errorLeakSignatures are regular-expression patterns that match common
// framework/runtime error output. Each entry has a label and a compiled
// pattern. A match in a 4xx/5xx response body is treated as verbose error
// disclosure.
var errorLeakSignatures = []struct {
	label   string
	pattern *regexp.Regexp
}{
	{"java-stacktrace", regexp.MustCompile(`(?i)at [a-z][a-z0-9_$]*(\.[a-z][a-z0-9_$]*)+\(.*\.java:\d+\)`)},
	{"python-traceback", regexp.MustCompile(`(?i)Traceback \(most recent call last\)`)},
	{"ruby-backtrace", regexp.MustCompile(`(?i)(ActionController|ActionDispatch|ActiveRecord)::[A-Z][a-zA-Z]+Error`)},
	{"php-fatal-error", regexp.MustCompile(`(?i)(Fatal error|Warning|Notice):\s+[A-Za-z].*in\s+/[^ ]+\.php on line \d+`)},
	{"dotnet-exception", regexp.MustCompile(`(?i)(System\.[A-Z][a-zA-Z\.]+Exception|at System\.[A-Z])`)},
	{"django-debug", regexp.MustCompile(`(?i)Django.*debug.*is.*True|Environment.*:.*DEBUG`)},
	{"node-error", regexp.MustCompile(`(?i)Error: .+\n\s+at [A-Z][a-zA-Z]+ \(.+:\d+:\d+\)`)},
	{"internal-path", regexp.MustCompile(`(?i)(/var/www/|/home/[a-z]+/|/srv/|/opt/|C:\\inetpub\\|C:\\Users\\)`)},
	{"db-error-mysql", regexp.MustCompile(`(?i)(MySQL.*error|SQLSTATE\[|You have an error in your SQL syntax)`)},
	{"db-error-postgres", regexp.MustCompile(`(?i)(PostgreSQL.*ERROR|pg_query\(\):.*error)`)},
	{"db-error-mssql", regexp.MustCompile(`(?i)(Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver)`)},
	{"db-error-oracle", regexp.MustCompile(`(?i)(ORA-\d{5}|Oracle.*error)`)},
	{"framework-version", regexp.MustCompile(`(?i)(Laravel \d|Symfony \d|Spring Framework \d|ASP\.NET MVC \d|Rails \d|Express \d)`)},
}

// malformedInputs are the probe payloads used to trigger error conditions.
// They are intentionally non-destructive: truncated values, type mismatches,
// and syntax errors that cause parsers to emit debug output without modifying
// application state.
var malformedInputs = []struct {
	label       string
	method      string
	contentType string
	body        string
	param       string // optional GET param name
}{
	{label: "truncated-json", method: "POST", contentType: "application/json", body: `{"key":"`},
	{label: "invalid-type", method: "POST", contentType: "application/json", body: `{"id": "not-a-number"}`},
	{label: "sql-syntax", method: "GET", param: "id", body: "'"},
	{label: "null-byte", method: "GET", param: "q", body: "test\x00end"},
	{label: "oversized-int", method: "GET", param: "page", body: "99999999999999999999999999999999"},
}

// runVerboseErrorProbe is an active probe covering WSTG-ERRH-01/02. It
// submits a small set of malformed-input payloads to candidate endpoints and
// inspects HTTP 4xx/5xx response bodies for patterns that indicate verbose
// error disclosure: stack traces, internal file paths, database error messages,
// and framework version strings.
//
// Only payloads that are safe (non-destructive) are used. The probe never
// modifies application state beyond causing a parse/type error.
func (s *Service) runVerboseErrorProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, bodyText, input.Scope, verboseErrorMaxEndpoints)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("verbose-error %s", input.Target),
			Message: "Probing for verbose error messages and stack trace disclosure",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if err := safety.ValidateOutboundURL(raw); err != nil {
			continue
		}
		if !scope.IsURLInScope(raw, input.Scope) {
			continue
		}

		base, err := url.Parse(raw)
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}

		for _, probe := range malformedInputs {
			fid := "verbose-error-" + probe.label + "-" + hhSlug(raw)
			if emitted[fid] {
				continue
			}

			var req *http.Request
			if probe.method == "GET" && probe.param != "" {
				q := url.Values{}
				q.Set(probe.param, probe.body)
				probeURL := url.URL{Scheme: base.Scheme, Host: base.Host, Path: base.Path, RawQuery: q.Encode()}
				req, err = http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
			} else if probe.method == "POST" {
				req, err = http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(probe.body))
				if err == nil {
					req.Header.Set("Content-Type", probe.contentType)
				}
			}
			if err != nil || req == nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)

			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			RecordProbedKey(probe.method, req.URL.String(), probe.param)
			if err != nil || resp == nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, verboseErrorBodyLimit))
			respHeader := resp.Header
			_ = resp.Body.Close()

			if resp.StatusCode < 400 {
				continue
			}
			// Phase 1 FP-reduction: binary response bodies (images,
			// PDFs, archives) cannot meaningfully leak framework
			// diagnostics — a regex hit is a byte-pattern coincidence,
			// not a real error page.
			if IsBinaryShape(respHeader) {
				continue
			}

			bodyStr := string(body)
			for _, sig := range errorLeakSignatures {
				if sig.pattern.MatchString(bodyStr) {
					// Phase 1 FP-reduction (base): re-issue the same
					// endpoint with a benign request and confirm the
					// signature does not fire on the clean baseline.
					// This suppresses endpoints that always render a
					// framework error page regardless of input.
					if baselineHasVerboseErrorSignature(ctx, s, input, raw, probe.method, probe.contentType, probe.param, sig.pattern) {
						continue
					}
					excerpt := extractExcerpt(bodyStr, sig.pattern, 200)
					emitted[fid] = true
					findings = append(findings, model.Finding{
						ID:       fid,
						Category: "information-disclosure",
						Severity: model.SeverityMedium,
						Title:    fmt.Sprintf("Verbose error disclosure — %s pattern in HTTP %d response", sig.label, resp.StatusCode),
						Description: fmt.Sprintf(
							"The endpoint %s returned an HTTP %d response containing a %s pattern after receiving a malformed input. "+
								"Verbose error messages disclose implementation details (stack traces, file paths, database engine, "+
								"framework versions) that significantly reduce attacker effort by narrowing the technology surface "+
								"and revealing exploitable code paths.",
							raw, resp.StatusCode, sig.label,
						),
						Evidence: fmt.Sprintf(
							"Probe: %s (%s) → HTTP %d; matched pattern %q; excerpt: %s",
							probe.label, probe.method, resp.StatusCode, sig.label, excerpt,
						),
						Recommendation: "Configure production error handling to return generic error pages without internal details. " +
							"Disable debug mode / detailed error reporting in production (e.g. Django DEBUG=False, " +
							"PHP display_errors=Off, Spring server.error.include-stacktrace=never). " +
							"Log full errors server-side only, never in HTTP responses.",
						Confidence:    0.85,
						AffectedURL:   raw,
						CWE:           "CWE-209",
						OWASPCategory: "A05:2021 - Security Misconfiguration",
						Sources:       []string{"active-scanner", "verbose-error"},
						ReproductionSteps: []string{
							fmt.Sprintf("Send: %s %s", probe.method, raw),
							fmt.Sprintf("Payload: %s (Content-Type: %s)", probe.body, probe.contentType),
							fmt.Sprintf("Observe HTTP %d response body containing %s pattern.", resp.StatusCode, sig.label),
						},
						EvidenceFields: map[string]string{
							"validationType": "active-probe",
							"probeLabel":     probe.label,
							"signatureLabel": sig.label,
							"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
							"excerpt":        excerpt,
							"responseShape":  ClassifyResponseShape(respHeader).String(),
						},
					})
					break // one finding per endpoint+probe is sufficient
				}
			}
		}
	}

	return findings
}

// baselineHasVerboseErrorSignature re-issues the endpoint without any
// malformed payload and returns true when the same error signature
// already fires on the clean baseline (indicating the response is a
// static error page, not payload-triggered disclosure). Any network
// failure is treated as "no baseline signal" so the primary finding is
// not incorrectly suppressed.
func baselineHasVerboseErrorSignature(
	ctx context.Context,
	s *Service,
	input RunInput,
	raw string,
	method string,
	contentType string,
	param string,
	pattern *regexp.Regexp,
) bool {
	base, err := url.Parse(raw)
	if err != nil {
		return false
	}
	var req *http.Request
	if method == "GET" && param != "" {
		q := url.Values{}
		q.Set(param, "abh_benign_baseline")
		probeURL := url.URL{Scheme: base.Scheme, Host: base.Host, Path: base.Path, RawQuery: q.Encode()}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	} else {
		// Baseline for POST probes: send a well-formed empty JSON body
		// so the endpoint responds without triggering a parser error.
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(`{}`))
		if err == nil && contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
	}
	if err != nil || req == nil {
		return false
	}
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, verboseErrorBodyLimit))
	_ = resp.Body.Close()
	return pattern.MatchString(string(body))
}

// extractExcerpt returns a short excerpt (up to maxLen bytes) of the first
// match of pat in text.
func extractExcerpt(text string, pat *regexp.Regexp, maxLen int) string {
	loc := pat.FindStringIndex(text)
	if loc == nil {
		return ""
	}
	start := loc[0]
	if start > 40 {
		start -= 40
	} else {
		start = 0
	}
	end := loc[1] + 120
	if end > len(text) {
		end = len(text)
	}
	excerpt := text[start:end]
	if len(excerpt) > maxLen {
		excerpt = excerpt[:maxLen]
	}
	return strings.TrimSpace(excerpt)
}

// matchVerboseErrors checks body for error-disclosure patterns and returns
// the matched signature labels.  It is extracted for testability.
func matchVerboseErrors(body string) []string {
var matched []string
for _, sig := range errorLeakSignatures {
if sig.pattern.MatchString(body) {
matched = append(matched, sig.label)
}
}
return matched
}
