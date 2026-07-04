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

// graphqlIntrospectionQuery is the canonical lightweight introspection
// query. Returning the schema (any non-empty `__schema.queryType.name`)
// confirms that introspection is enabled on the endpoint, which is widely
// considered a misconfiguration in production GraphQL deployments because
// it lets attackers map every type, field, and mutation in advance.
const graphqlIntrospectionQuery = `{"query":"{__schema{queryType{name} mutationType{name} types{name}}}"}`

// graphqlEndpointHints are URL-path substrings the probe accepts as
// "looks like a GraphQL endpoint". The list mirrors the static seeds in
// extractRuntimeEndpoints plus a few common framework variants.
var graphqlEndpointHints = []string{"/graphql", "/graph", "/query", "/api/graphql", "/v1/graphql"}

// runActiveGraphQLIntrospectionProbe is an active GraphQL introspection
// scanner. It runs only when the runtime endpoint discovery (or the seed
// list) surfaces a GraphQL-shaped path. For each candidate it POSTs a
// minimal introspection query and confirms a finding when the response
// returns a non-empty `__schema`.
//
// The probe is intentionally read-only (POST with `query` only — no
// `mutation`), and returns at most one finding per scan listing every
// introspection-enabled endpoint observed.
func (s *Service) runActiveGraphQLIntrospectionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 12)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	candidates = filterGraphQLCandidates(candidates)
	if len(candidates) == 0 {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-graphql-introspection %s", input.Target),
			Message: "Probing discovered GraphQL endpoints for enabled introspection",
		})
	}

	type hit struct {
		url string
	}
	var hits []hit
	for _, raw := range candidates {
		probeURL := strings.TrimSpace(raw)
		if probeURL == "" {
			continue
		}
		if !scope.IsURLInScope(probeURL, input.Scope) {
			continue
		}
		// safety.ValidateOutboundURL is intentionally not re-checked here —
		// extractRuntimeEndpoints + SeedRuntimeEndpoints producers are
		// already responsible for SSRF validation upstream.
		if u, err := url.Parse(probeURL); err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL, strings.NewReader(graphqlIntrospectionQuery))
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		// Phase 2 coverage accounting: record this probe key so the
		// surface-gap detector subtracts it from the inventory. Introspection
		// is endpoint-shaped (no per-parameter surface), so no param name.
		RecordProbedKey(http.MethodPost, probeURL, "")
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		respHeader := resp.Header
		_ = resp.Body.Close()
		// Phase 1 shape gate: introspection is defined to return JSON.
		// A non-JSON response (HTML error page, WAF block, static asset)
		// that happens to contain the "__schema" / "querytype" substrings
		// is not evidence of an enabled introspection endpoint. Requiring
		// a JSON-shaped body eliminates that class of false positive.
		if !IsJSONShape(respHeader) {
			continue
		}
		if isGraphQLIntrospectionResponse(string(respBody)) {
			hits = append(hits, hit{url: probeURL})
		}
	}

	if len(hits) == 0 {
		return nil
	}

	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, h.url)
	}
	first := hits[0]
	steps := []string{
		fmt.Sprintf("POST %s with `Content-Type: application/json` and body %s", first.url, graphqlIntrospectionQuery),
		"Inspect the response and confirm `__schema` is populated with type definitions.",
		"Use the returned schema to enumerate every query/mutation/field that may need authorization tightening.",
	}
	curl := buildCurlReproducer(http.MethodPost, first.url, input.AuthProfile, "application/json", graphqlIntrospectionQuery)
	return []model.Finding{{
		ID:                "active-graphql-introspection",
		Category:          "api",
		Severity:          model.SeverityMedium,
		Title:             "GraphQL introspection enabled in production",
		Description:       "The discovered GraphQL endpoint responds to `__schema` introspection queries. While not directly exploitable, an attacker can enumerate every type, query, mutation and field (including hidden admin ones), dramatically reducing the cost of follow-on attacks against authorization, mass-assignment and dangerous mutations.",
		Evidence:          fmt.Sprintf("Introspection responses returned a populated `__schema` for: %s", strings.Join(limitStrings(urls, 6), ", ")),
		Recommendation:    "Disable introspection on production endpoints (e.g. `introspection: false` on Apollo Server, `graphene-django` middleware, or by stripping `__schema`/`__type` from the parsed query). Restrict introspection to authenticated developer accounts where it is truly needed.",
		Confidence:        0.95,
		AffectedURL:       first.url,
		CWE:               "CWE-200",
		OWASPCategory:     "A05:2021 - Security Misconfiguration",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"reproStep":      "POST the introspection query and inspect __schema in the JSON response",
			"endpoint":       first.url,
			"curlReproducer": curl,
			"responseShape":  ShapeJSON.String(),
			"method":         http.MethodPost,
			"url":            first.url,
			"payloadClass":   "graphql-introspection",
			"oracleName":     "active_graphql_introspection",
			"oracleVersion":  "v1",
		},
	}}
}

// filterGraphQLCandidates keeps only the URLs whose path looks like a
// GraphQL endpoint. The scanner deliberately avoids POSTing arbitrary
// JSON to non-GraphQL endpoints because doing so would risk creating
// noise/state on REST endpoints that share the URL space.
func filterGraphQLCandidates(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		lower := strings.ToLower(raw)
		matched := false
		for _, hint := range graphqlEndpointHints {
			if strings.Contains(lower, hint) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

// isGraphQLIntrospectionResponse confirms the body looks like a successful
// introspection response. We accept both:
//   - `"__schema":{...}` shape (unwrapped or under `data`)
//
// We deliberately do not try to JSON-decode here because some GraphQL
// servers prefix the body with a `while(1);` or similar XSSI guard; a
// substring check is robust against that.
func isGraphQLIntrospectionResponse(body string) bool {
	if body == "" {
		return false
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "__schema") {
		return false
	}
	// "queryType":{"name": confirms the schema body is populated rather
	// than `{"data":{"__schema":null}}` or an error envelope mentioning
	// `__schema` in passing.
	return strings.Contains(lower, "querytype")
}
