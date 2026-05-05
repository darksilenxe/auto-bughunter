package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// sqliProbeParams are the parameter names most likely to flow into a SQL
// query when reflected into a web app. These are deliberately
// "filter/lookup"-shaped names to maximise hit rate without poking
// state-mutating identifiers (we still only send GET).
var sqliProbeParams = []string{"id", "user", "uid", "account", "pid", "category", "cat", "item", "page", "sort", "order"}

// sqliBenignPayload is a single-character payload designed to be the *least*
// destructive thing that can still trigger SQL parser errors when
// concatenated unescaped into a query: a stray single quote. It does not
// attempt UNION/OR-1=1/sleep/timing — those are out of scope for an
// error-based probe and risk side effects.
const sqliBenignPayload = "'"

// sqlErrorSignatures are stable substrings that strongly indicate the
// response leaked a server-side database parser error. The list is
// intentionally specific (no generic words like "error" or "syntax") to
// minimise false positives on unrelated app text.
var sqlErrorSignatures = []string{
	// MySQL / MariaDB
	"you have an error in your sql syntax",
	"warning: mysql",
	"mysql_fetch",
	"mysql_num_rows",
	"mysqlclient.",
	"unclosed quotation mark after the character string",
	// PostgreSQL
	"pg_query():",
	"pg_exec():",
	"unterminated quoted string at or near",
	"syntax error at or near \"'\"",
	"postgresql query failed",
	// SQL Server
	"microsoft odbc sql server driver",
	"unclosed quotation mark before the character string",
	"incorrect syntax near",
	"system.data.sqlclient.sqlexception",
	// Oracle
	"ora-00933:",
	"ora-00921:",
	"ora-01756:",
	"oracle error",
	// SQLite
	"sqlite3::",
	"sqlite_error",
	"sqliteexception",
	"unrecognized token:",
	// JDBC / generic
	"java.sql.sqlexception",
	"odbc driver",
}

// sqlErrorSignaturesByDB groups the above signatures by database family so
// that techPrioritizedSQLiSignatures can move the most-likely DB's patterns
// to the front of the matching pass.
var sqlErrorSignaturesByDB = map[string][]string{
	"mysql": {
		"you have an error in your sql syntax",
		"warning: mysql",
		"mysql_fetch",
		"mysql_num_rows",
		"mysqlclient.",
		"unclosed quotation mark after the character string",
	},
	"postgresql": {
		"pg_query():",
		"pg_exec():",
		"unterminated quoted string at or near",
		"syntax error at or near \"'\"",
		"postgresql query failed",
	},
	"mssql": {
		"microsoft odbc sql server driver",
		"unclosed quotation mark before the character string",
		"incorrect syntax near",
		"system.data.sqlclient.sqlexception",
	},
	"oracle": {
		"ora-00933:",
		"ora-00921:",
		"ora-01756:",
		"oracle error",
	},
	"sqlite": {
		"sqlite3::",
		"sqlite_error",
		"sqliteexception",
		"unrecognized token:",
	},
}

// techPrioritizedSQLiSignatures returns the full sqlErrorSignatures list
// reordered so the patterns for the database family most consistent with the
// detected tech stack are checked first. This does not affect probe request
// count (we still send the same payloads) but makes error detection fire
// earlier in the signature scan for the expected DB engine, saving CPU on
// large response bodies.
func techPrioritizedSQLiSignatures(tech TechStack) []string {
	family := sqlDBFamily(tech)
	if family == "" {
		return sqlErrorSignatures
	}
	primary, ok := sqlErrorSignaturesByDB[family]
	if !ok {
		return sqlErrorSignatures
	}
	seen := make(map[string]struct{}, len(sqlErrorSignatures))
	out := make([]string, 0, len(sqlErrorSignatures))
	// Primary DB family first.
	for _, sig := range primary {
		out = append(out, sig)
		seen[sig] = struct{}{}
	}
	// Remaining signatures in their original order.
	for _, sig := range sqlErrorSignatures {
		if _, ok := seen[sig]; !ok {
			out = append(out, sig)
		}
	}
	return out
}

// sqliMaxAttempts caps probe budget per scan. Same rationale as
// xssMaxAttempts.
const sqliMaxAttempts = 12

// runActiveSQLiProbe is an active error-based SQL injection scanner. It
// appends a single benign quote to common ID/lookup parameters across
// runtime-discovered endpoints and looks for stable database-parser error
// signatures in the response. The probe is non-destructive (no UNION, no
// time-based payloads, no boolean blind attempts) and emits at most one
// finding per scan.
func (s *Service) runActiveSQLiProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 10)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-sqli %s", input.Target),
			Message: "Probing for error-based SQL injection via single-quote payload",
		})
	}

	type hit struct {
		url       string
		param     string
		signature string
	}
	var hits []hit
	attempts := 0
	for _, raw := range candidates {
		if attempts >= sqliMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, p := range sqliProbeParams {
			if attempts >= sqliMaxAttempts {
				break
			}
			payloads := []string{sqliBenignPayload}
			if input.Options.WAFBypass {
				payloads = sqliBypassVariants(sqliBenignPayload)
			}
			matched := false
			for _, payload := range payloads {
				if attempts >= sqliMaxAttempts {
					break
				}
				probe := *base
				q := probe.Query()
				// If the parameter already exists, append the breakout to
				// its existing value so we exercise the same code path as
				// the real app (e.g. id=42 -> id=42'); otherwise seed
				// with "1<payload>".
				existing := q.Get(p)
				if existing == "" {
					existing = "1"
				}
				q.Set(p, existing+payload)
				probe.RawQuery = q.Encode()
				probeURL := probe.String()
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				// See active_xss.go for the rationale on omitting the
				// redundant safety check on the constructed URL.
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				attempts++
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				_ = resp.Body.Close()
				if sig := matchSQLErrorSignatureFrom(string(respBody), techPrioritizedSQLiSignatures(input.DetectedTech)); sig != "" {
					hits = append(hits, hit{url: probeURL, param: p, signature: sig})
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, fmt.Sprintf("%s (param=%s, signature=%q)", h.url, h.param, h.signature))
	}

	steps := []string{
		fmt.Sprintf("Send GET %s with the original parameter value followed by a single quote (the probe used %q).", first.url, sqliBenignPayload),
		fmt.Sprintf("Observe a server-side database error signature in the response body — the probe matched %q.", first.signature),
		"Confirm by removing the quote and verifying the error disappears (control request).",
	}
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")

	return []model.Finding{{
		ID:                "active-sqli-error-based",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "Error-based SQL injection: database parser error leaked on tampered parameter",
		Description:       "Appending a single quote to a parameter value caused the application to respond with a database-engine parser error. This indicates the parameter is concatenated unescaped into a SQL statement and is exploitable for SQL injection. Depending on the surrounding query, an attacker may be able to read or modify arbitrary database contents.",
		Evidence:          fmt.Sprintf("Database error signatures observed at: %s", strings.Join(limitStrings(urls, 6), "; ")),
		Recommendation:    "Use parameterised queries / prepared statements at every database call site. Never concatenate untrusted input into SQL. Disable verbose database error pages in production as defense-in-depth.",
		Confidence:        0.9,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-89",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType":  "active-probe",
			"reproStep":       "Replay the listed URL and confirm the database error signature appears in the response",
			"errorSignature":  first.signature,
			"injectedPayload": sqliBenignPayload,
			"curlReproducer":  curl,
		},
	}}
}

// matchSQLErrorSignature returns the first signature substring observed in
// the response body, or "" when none match. Matching is case-insensitive on
// signatures that are inherently case-stable; this avoids the cost of a full
// case-fold of the (potentially large) response body for each pattern.
func matchSQLErrorSignature(body string) string {
	return matchSQLErrorSignatureFrom(body, sqlErrorSignatures)
}

// matchSQLErrorSignatureFrom is the underlying matcher used by both
// matchSQLErrorSignature and runActiveSQLiProbe (which passes in a
// tech-prioritized signature list). It returns the first matching signature
// or "" when none is found.
func matchSQLErrorSignatureFrom(body string, sigs []string) string {
	if body == "" {
		return ""
	}
	lower := strings.ToLower(body)
	for _, sig := range sigs {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}
