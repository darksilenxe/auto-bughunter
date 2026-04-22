package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// workflowTransitionPattern matches URL paths that represent state-changing
// business operations. These are high-value targets for business-logic
// authorization and invariant testing: the server must enforce role-based
// access control and input validation on every mutating operation.
//
// The negative lookahead-equivalent here is the word-boundary anchor: the
// keyword must be followed by '/', end-of-string, or '?' so that e.g.
// "/api/orders/12345" (plural "orders") does not match the "order" keyword.
var workflowTransitionPattern = regexp.MustCompile(
	`(?i)/(checkout|payment|order|transfer|approve|submit|cancel|confirm|refund|` +
		`upgrade|subscribe|invite|purchase|transaction|withdraw|deposit|reset|` +
		`activate|deactivate|promote|demote|create|update|edit|delete)(?:/|$|\?)`,
)

// bldMaxEndpoints caps how many transition endpoints the business-logic probe
// will test per scan to bound runtime on large surfaces.
const bldMaxEndpoints = 10

// bldBodyLimit is the per-response read cap used during response inspection.
const bldBodyLimit = 32 * 1024

// tamperPayload bundles a short label, a JSON body with an out-of-range
// business parameter, and the field name for evidence messages.
type tamperPayload struct {
	label string
	body  []byte
	field string
}

// bldTamperPayloads is the set of parameter-tampering probes. Each payload
// targets a common numeric business field with an out-of-range value:
// negative amounts exploit credit/refund logic, zero prices allow free
// purchase, and discount > 100 exploits coupon/discount calculation bugs.
var bldTamperPayloads = []tamperPayload{
	{"negative-amount", []byte(`{"amount":-1}`), "amount"},
	{"zero-price", []byte(`{"price":0}`), "price"},
	{"negative-quantity", []byte(`{"quantity":-1}`), "quantity"},
	{"over-limit-discount", []byte(`{"discount":101}`), "discount"},
	{"negative-total", []byte(`{"total":-0.01}`), "total"},
}

// bldErrorPattern matches server-side error indicators in JSON response bodies.
// A tampered POST that returns 2xx but contains these strings is most likely
// returning a validation error wrapped in an OK envelope (common in older APIs),
// not a true business-logic success, so we do not flag it.
var bldErrorPattern = regexp.MustCompile(
	`(?i)"(error|invalid|rejected|fail(ed)?|not[ _]allowed|forbidden|bad[ _]request)"`,
)

// RunBusinessLogicDiff is an active business-logic probe that extends the
// role-differential approach of RunIDORRoleDiff (which targets read-only,
// ID-bearing endpoints) to state-changing (mutating) operations. It detects
// three classes of business-logic authorization and validation failures:
//
//  1. Unauthenticated access to state-changing operations — an anonymous
//     caller that successfully invokes a POST endpoint that the authenticated
//     baseline also accepts (indicating no session/token requirement).
//
//  2. Cross-role unauthorized mutation — a lower-privileged role that can
//     invoke the same mutating operation as the authenticated baseline,
//     indicating missing function-level access control on write paths.
//
//  3. Parameter tampering — a transition endpoint that accepts numeric
//     business parameters (amount, price, quantity, discount, total) with
//     out-of-range values (negative, zero, >100%) and returns a 2xx
//     response without an error indicator, suggesting the server does not
//     validate business invariants on the input.
//
// The probe respects PassiveOnly and is bounded by bldMaxEndpoints. All
// URLs are scope-checked and safety-validated before being contacted.
func (s *Service) RunBusinessLogicDiff(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	baseline model.ScanAuthProfile,
	roles []model.RoleAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}
	candidates := bldCandidateEndpoints(target, options.SeedRuntimeEndpoints, scanScope)
	if len(candidates) == 0 {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("business-logic-diff %s", target),
			Message: fmt.Sprintf("Probing %d transition endpoints for business-logic authorization failures", len(candidates)),
		})
	}

	var findings []model.Finding

	// Probe 1: Unauthenticated access to state-changing operations.
	// Only meaningful when we have an authenticated baseline to compare against.
	if hasAuthHeaders(baseline) {
		findings = append(findings, s.bldProbeAnonymous(ctx, candidates, baseline, options)...)
	}

	// Probe 2: Cross-role access to state-changing operations.
	// Requires an authenticated baseline plus at least one additional role.
	if hasAuthHeaders(baseline) && len(roles) >= 1 {
		findings = append(findings, s.bldProbeCrossRole(ctx, candidates, baseline, roles, options)...)
	}

	// Probe 3: Parameter tampering on numeric business fields.
	// Runs with the baseline credentials so we avoid confounding with probe 1.
	findings = append(findings, s.bldProbeParameterTamper(ctx, candidates, baseline, options)...)

	return findings
}

// bldProbeAnonymous issues a POST to each transition endpoint first as the
// baseline identity and then as an anonymous caller. When both return 2xx,
// the operation is accessible without authentication and a high-severity
// finding is emitted.
func (s *Service) bldProbeAnonymous(
	ctx context.Context,
	candidates []string,
	baseline model.ScanAuthProfile,
	options model.ScanOptions,
) []model.Finding {
	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		if emitted[ep] {
			continue
		}

		// Confirm the endpoint accepts POST from the authenticated baseline.
		// If it doesn't return 2xx with auth we can't distinguish the anon case.
		baseStatus := s.bldPOST(ctx, ep, nil, baseline, options)
		if baseStatus == 0 || !is2xx(baseStatus) {
			continue
		}

		// Now probe as anonymous (no credentials).
		anonStatus := s.bldPOST(ctx, ep, nil, model.ScanAuthProfile{}, options)
		if anonStatus == 0 || !is2xx(anonStatus) {
			continue
		}

		emitted[ep] = true
		findings = append(findings, bldFinding(
			"bld-anon-state-mutation",
			ep,
			model.SeverityHigh,
			"Unauthenticated access to state-changing operation",
			fmt.Sprintf(
				"POST %s returned HTTP %d for an anonymous (unauthenticated) caller. "+
					"The same endpoint returned HTTP %d for an authenticated baseline caller, "+
					"indicating the operation is accessible without authentication.",
				ep, anonStatus, baseStatus,
			),
			"CWE-306",
			"A01:2021 - Broken Access Control",
			[]string{
				fmt.Sprintf("Send POST %s without any authorization headers.", ep),
				fmt.Sprintf("Observe HTTP %d — the state-changing operation succeeds without authentication.", anonStatus),
				"Verify that the server performed a meaningful state change without requiring a valid session or token.",
			},
			map[string]string{
				"roleA":     "anonymous",
				"roleB":     "authenticated-baseline",
				"baselineStatus": fmt.Sprintf("%d", baseStatus),
				"anonStatus":     fmt.Sprintf("%d", anonStatus),
			},
		))
	}
	return findings
}

// bldProbeCrossRole issues a POST to each transition endpoint as the baseline
// and as each additional role. When both return 2xx, the lower-privileged
// role can invoke a mutating operation that may be restricted by design.
func (s *Service) bldProbeCrossRole(
	ctx context.Context,
	candidates []string,
	baseline model.ScanAuthProfile,
	roles []model.RoleAuthProfile,
	options model.ScanOptions,
) []model.Finding {
	type pairKey struct{ role string }
	emitted := map[pairKey]bool{}
	var findings []model.Finding

	for _, ep := range candidates {
		baseStatus := s.bldPOST(ctx, ep, nil, baseline, options)
		if baseStatus == 0 || !is2xx(baseStatus) {
			continue
		}

		for _, role := range roles {
			roleName := strings.TrimSpace(role.RoleName)
			if roleName == "" || !hasAuthHeaders(role.AuthProfile) {
				continue
			}
			key := pairKey{roleName}
			if emitted[key] {
				continue
			}

			roleStatus := s.bldPOST(ctx, ep, nil, role.AuthProfile, options)
			if roleStatus == 0 || !is2xx(roleStatus) {
				continue
			}

			emitted[key] = true
			findings = append(findings, bldFinding(
				"bld-cross-role-mutation-"+slugRolePair("baseline", roleName),
				ep,
				model.SeverityMedium,
				fmt.Sprintf("Cross-role access to state-changing operation between baseline and %s", roleName),
				fmt.Sprintf(
					"POST %s returned HTTP %d for the baseline identity and HTTP %d for role %q. "+
						"Both identities can invoke this state-changing operation, indicating the server "+
						"may not enforce role-based access control on mutating operations.",
					ep, baseStatus, roleStatus, roleName,
				),
				"CWE-285",
				"A01:2021 - Broken Access Control",
				[]string{
					fmt.Sprintf("Send POST %s with baseline authorization credentials.", ep),
					fmt.Sprintf("Observe HTTP %d response.", baseStatus),
					fmt.Sprintf("Replay POST %s with %q role credentials.", ep, roleName),
					fmt.Sprintf("Observe HTTP %d — both identities received equivalent success responses.", roleStatus),
					"Verify whether the state change is restricted by role design.",
				},
				map[string]string{
					"roleA": "baseline",
					"roleB": roleName,
				},
			))
		}
	}
	return findings
}

// bldProbeParameterTamper issues POST requests with numeric business parameters
// set to out-of-range values. When the server returns 2xx without an error
// indicator, business invariant validation is likely absent.
func (s *Service) bldProbeParameterTamper(
	ctx context.Context,
	candidates []string,
	baseline model.ScanAuthProfile,
	options model.ScanOptions,
) []model.Finding {
	emitted := map[string]bool{}
	var findings []model.Finding

	for _, ep := range candidates {
		if emitted[ep] {
			continue
		}

		for _, payload := range bldTamperPayloads {
			status, body := s.bldPOSTWithBody(ctx, ep, payload.body, baseline, options)
			if status == 0 || !is2xx(status) {
				continue
			}
			if bldErrorPattern.MatchString(string(body)) {
				// Server returned an error message in a 2xx envelope — not a true success.
				continue
			}

			emitted[ep] = true
			findings = append(findings, bldFinding(
				"bld-param-tamper-"+payload.label,
				ep,
				model.SeverityMedium,
				fmt.Sprintf("Business-logic parameter tampering accepted on %q field", payload.field),
				fmt.Sprintf(
					"POST %s with body %s returned HTTP %d without an error indicator. "+
						"The server accepted an out-of-range value for the %q business parameter, "+
						"which may allow price manipulation, negative balance exploitation, or discount abuse.",
					ep, payload.body, status, payload.field,
				),
				"CWE-20",
				"A04:2021 - Insecure Design",
				[]string{
					fmt.Sprintf("Send POST %s with body: %s", ep, payload.body),
					fmt.Sprintf("Observe HTTP %d response without error indication.", status),
					"Verify whether the server performed a state change with the out-of-range value " +
						"(e.g., negative amount credited, discount exceeding 100%% applied, zero-price purchase accepted).",
				},
				map[string]string{
					"tamperField":   payload.field,
					"tamperPayload": string(payload.body),
				},
			))
			break // one finding per endpoint
		}
	}
	return findings
}

// bldPOST issues an authenticated POST to rawURL with an optional body and
// returns the HTTP status code (0 on transport error or scope violation).
func (s *Service) bldPOST(
	ctx context.Context,
	rawURL string,
	body []byte,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) int {
	status, _ := s.bldPOSTWithBody(ctx, rawURL, body, auth, options)
	return status
}

// bldPOSTWithBody issues a POST request and returns the status code plus the
// truncated response body. Both are zero/nil on transport error or safety
// policy violation.
func (s *Service) bldPOSTWithBody(
	ctx context.Context,
	rawURL string,
	body []byte,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) (int, []byte) {
	if err := safety.ValidateOutboundURL(rawURL); err != nil {
		return 0, nil
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bodyReader)
	if err != nil {
		return 0, nil
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	ApplyAuthProfile(req, auth)

	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return 0, nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, bldBodyLimit))
	return resp.StatusCode, respBody
}

// bldFinding constructs a Finding for a business-logic differential result.
func bldFinding(
	id, endpoint string,
	severity model.Severity,
	title, evidence, cwe, owasp string,
	steps []string,
	extraFields map[string]string,
) model.Finding {
	ef := map[string]string{
		"validationType": "active-probe",
		"reproStep":      "Replay the listed request(s) and compare the server response to the reference authenticated response",
	}
	for k, v := range extraFields {
		ef[k] = v
	}

	tags := []string{"business-logic"}
	if roleA, ok := extraFields["roleA"]; ok && roleA != "" {
		tags = append(tags, "role:"+roleA)
	}
	if roleB, ok := extraFields["roleB"]; ok && roleB != "" {
		tags = append(tags, "role:"+roleB)
	}

	return model.Finding{
		ID:       id,
		Category: "access-control",
		Severity: severity,
		Title:    title,
		Description: "The scanner detected a business-logic authorization or validation failure by comparing " +
			"server responses across different identities or by submitting mutated business-critical parameters. " +
			"Business-logic bugs are high-value targets in bug bounty programs because they are not detected " +
			"by standard injection scanners.",
		Evidence:       evidence,
		Recommendation: "Enforce authorization checks and input validation at every state-changing operation. " +
			"Verify that business invariants (non-negative amounts, valid discount ranges, owned-resource checks) " +
			"are validated server-side on every request, independent of client-side enforcement.",
		Confidence:        0.80,
		AffectedURL:       endpoint,
		CWE:               cwe,
		OWASPCategory:     owasp,
		Sources:           []string{"active-scanner", "business-logic-diff"},
		ReproductionSteps: steps,
		BusinessTags:      tags,
		EvidenceFields:    ef,
	}
}

// bldCandidateEndpoints collects candidate transition endpoints from the
// seeded list and a set of well-known paths resolved against the target.
// Only URLs whose paths match workflowTransitionPattern, pass scope checks,
// and pass the safety policy are returned. At most bldMaxEndpoints are returned.
func bldCandidateEndpoints(target string, seeded []string, scanScope model.ScanScope) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	// Well-known transition paths probed on every target regardless of discovery.
	wellKnownPaths := []string{
		"/checkout",
		"/order",
		"/payment",
		"/transfer",
		"/subscribe",
		"/api/checkout",
		"/api/order",
		"/api/payment",
		"/api/transfer",
	}

	all := append([]string{}, seeded...)
	for _, wk := range wellKnownPaths {
		ref, err := url.Parse(wk)
		if err != nil {
			continue
		}
		all = append(all, base.ResolveReference(ref).String())
	}

	out := make([]string, 0, bldMaxEndpoints)
	seen := map[string]struct{}{}
	for _, raw := range all {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		if !workflowTransitionPattern.MatchString(u.Path) {
			continue
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		if !scope.IsURLInScope(raw, scanScope) {
			continue
		}
		if err := safety.ValidateOutboundURL(raw); err != nil {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
		if len(out) >= bldMaxEndpoints {
			break
		}
	}
	sort.Strings(out)
	return out
}
