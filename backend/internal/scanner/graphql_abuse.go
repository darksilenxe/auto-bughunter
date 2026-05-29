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

// graphqlAbuseBodyLimit caps per-response reads for the abuse probe.
const graphqlAbuseBodyLimit = 256 * 1024

// graphqlSuggestionQuery requests a deliberately-misspelled field. A server
// with field suggestions enabled answers with "Did you mean ..." even when
// introspection is disabled, leaking schema details (clairvoyance-style).
const graphqlSuggestionQuery = `{"query":"{ abhNonExistentField__ }"}`

// graphqlAliasQuery requests the same trivial field under several aliases. A
// server that processes all aliases without a complexity/alias limit is
// vulnerable to query amplification / denial of service.
const graphqlAliasQuery = `{"query":"{ a0:__typename a1:__typename a2:__typename a3:__typename a4:__typename }"}`

// graphqlBatchQuery is a 3-element JSON batch of trivial queries. A server that
// answers with a 3-element array processes batched operations, which attackers
// abuse for rate-limit bypass (e.g. credential brute force) and amplification.
const graphqlBatchQuery = `[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]`

// runGraphQLAbuseProbe complements the introspection probe with deeper GraphQL
// abuse checks: field-suggestion schema leakage, alias-based amplification, and
// query batching. All queries are read-only (`__typename` only) and never send
// mutations.
func (s *Service) runGraphQLAbuseProbe(ctx context.Context, input RunInput, body string) []model.Finding {
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
			Command: fmt.Sprintf("graphql-abuse %s", input.Target),
			Message: "Probing GraphQL endpoints for field-suggestion leakage, aliasing and batching",
		})
	}

	var findings []model.Finding
	for _, raw := range candidates {
		probeURL := strings.TrimSpace(raw)
		if probeURL == "" || !scope.IsURLInScope(probeURL, input.Scope) {
			continue
		}
		if u, err := url.Parse(probeURL); err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}

		var vectors []string
		if s.graphqlPost(ctx, input, probeURL, graphqlSuggestionQuery, graphqlFieldSuggestionLeak) {
			vectors = append(vectors, "field-suggestion schema leakage")
		}
		if s.graphqlPost(ctx, input, probeURL, graphqlAliasQuery, graphqlAliasAmplification) {
			vectors = append(vectors, "unrestricted query aliasing (amplification)")
		}
		if s.graphqlPost(ctx, input, probeURL, graphqlBatchQuery, graphqlBatchAccepted) {
			vectors = append(vectors, "query batching enabled (rate-limit bypass / amplification)")
		}
		if len(vectors) == 0 {
			continue
		}

		curl := buildCurlReproducer(http.MethodPost, probeURL, input.AuthProfile, "application/json", graphqlAliasQuery)
		findings = append(findings, model.Finding{
			ID:       "graphql-abuse-" + hhSlug(probeURL),
			Category: "api",
			Severity: model.SeverityMedium,
			Title:    "GraphQL endpoint exposes abuse vectors",
			Description: "The GraphQL endpoint exposes one or more abuse vectors: " + strings.Join(vectors, "; ") + ". " +
				"Field suggestions leak schema details even when introspection is disabled; unrestricted aliasing and batching let an attacker " +
				"amplify a single request into thousands of resolver executions (denial of service) and bypass per-request rate limits used to " +
				"protect authentication endpoints.",
			Evidence:    "Detected abuse vectors: " + strings.Join(vectors, "; "),
			Recommendation: "Disable field suggestions in production, enforce a query-complexity/depth limit, cap or disable aliasing, and reject " +
				"or rate-limit batched operations. Apply authentication-aware rate limiting at the resolver level.",
			Confidence:    0.8,
			AffectedURL:   probeURL,
			CWE:           "CWE-770",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"active-scanner", "graphql-abuse"},
			ReproductionSteps: []string{
				fmt.Sprintf("POST %s with an aliased query: %s", probeURL, graphqlAliasQuery),
				"Confirm all aliases resolve, then scale the alias count to demonstrate amplification.",
				fmt.Sprintf("POST a batched array (%s) and confirm the server returns a multi-element response array.", graphqlBatchQuery),
			},
			PoC: curl,
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"vectors":        strings.Join(vectors, "|"),
				"curlReproducer": curl,
			},
		})
	}
	return findings
}

// graphqlPost POSTs a GraphQL query to the endpoint and applies detect to the
// response body, returning the detector result. Errors yield false.
func (s *Service) graphqlPost(ctx context.Context, input RunInput, probeURL, query string, detect func(string) bool) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL, strings.NewReader(query))
	if err != nil {
		return false
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, graphqlAbuseBodyLimit))
	_ = resp.Body.Close()
	return detect(string(b))
}

// graphqlFieldSuggestionLeak reports whether an error response includes a
// "Did you mean" field suggestion, which discloses schema information.
func graphqlFieldSuggestionLeak(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "did you mean")
}

// graphqlAliasAmplification reports whether the aliased query resolved all
// aliases (a0..a4), confirming aliasing is unrestricted.
func graphqlAliasAmplification(body string) bool {
	for _, alias := range []string{"a0", "a1", "a2", "a3", "a4"} {
		if !strings.Contains(body, "\""+alias+"\"") {
			return false
		}
	}
	return true
}

// graphqlBatchAccepted reports whether a batched request returned a JSON array
// of results (multiple top-level objects), confirming batching is enabled.
func graphqlBatchAccepted(body string) bool {
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "[") {
		return false
	}
	// A processed 3-element batch returns at least two "data"/"__typename"
	// occurrences; require >= 2 to avoid matching a single error array.
	return strings.Count(trimmed, "__typename") >= 2 || strings.Count(trimmed, "\"data\"") >= 2
}
