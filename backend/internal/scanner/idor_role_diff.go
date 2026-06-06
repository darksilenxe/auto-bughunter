package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// idorIDSegment matches path segments that look like opaque object
// identifiers — numeric IDs, UUIDs, or long hex strings. These are the
// endpoints where a Broken Object Level Authorization (BOLA / IDOR) bug
// is most likely to live, because the application has to make an
// authorization decision per object.
var idorIDSegment = regexp.MustCompile(`(?i)/(?:\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})(?:/|$)`)

// idorMaxEndpoints caps how many endpoints the active IDOR probe will
// fetch per role to bound scan time on chatty surfaces.
const idorMaxEndpoints = 8

// idorBodyLimit is the per-response read cap for size comparison. Two
// responses are considered "structurally similar" when their byte counts
// agree to within idorBodyDelta after this truncation.
const (
	idorBodyLimit = 64 * 1024
	idorBodyDelta = 64
)

// IDORProbeProfile is one identity to use when fetching candidate
// endpoints. A nil/zero AuthProfile represents an anonymous request.
type IDORProbeProfile struct {
	RoleName    string
	AuthProfile model.ScanAuthProfile
}

// RunIDORRoleDiff is an active access-control probe. For each candidate
// in-scope endpoint that contains an ID-shaped path segment, it issues a
// GET as every supplied identity (anonymous + each role) and compares the
// resulting status code and body size. It surfaces a finding whenever:
//
//   - Anonymous and any authenticated role both receive a 2xx response of
//     comparable size on an ID-bearing endpoint, indicating the resource
//     is reachable without authentication despite being intended for an
//     authenticated user (Broken Authentication / BOLA).
//
//   - Two distinct roles both receive a 2xx response of comparable size
//     on an ID-bearing endpoint, indicating no access-control gate
//     between roles (cross-role IDOR).
//
// The probe is read-only (HTTP GET) and scope-checks every URL. Endpoints
// are taken from options.SeedRuntimeEndpoints; callers that want runtime
// expansion should populate that field after the baseline crawl.
//
// At most one finding is emitted per (anonymous-vs-role) and per
// (role-vs-role) pair to avoid swamping the report.
func (s *Service) RunIDORRoleDiff(ctx context.Context, target string, scanScope model.ScanScope, options model.ScanOptions, baseline model.ScanAuthProfile, roles []model.RoleAuthProfile, emit func(model.ScanEvent)) []model.Finding {
	if options.PassiveOnly {
		return nil
	}
	candidates := idorCandidateEndpoints(target, options.SeedRuntimeEndpoints, scanScope)
	if len(candidates) == 0 {
		return nil
	}

	identities := []IDORProbeProfile{{RoleName: "anonymous"}}
	if hasAuthHeaders(baseline) {
		identities = append(identities, IDORProbeProfile{RoleName: "baseline", AuthProfile: baseline})
	}
	for _, r := range roles {
		if strings.TrimSpace(r.RoleName) == "" || !hasAuthHeaders(r.AuthProfile) {
			continue
		}
		identities = append(identities, IDORProbeProfile{RoleName: r.RoleName, AuthProfile: r.AuthProfile})
	}
	if len(identities) < 2 {
		// Need at least two perspectives to compare.
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("idor-role-diff %s", target),
			Message: fmt.Sprintf("Probing %d ID-bearing endpoints across %d identities", len(candidates), len(identities)),
		})
	}

	type sample struct {
		status int
		size   int
		ok     bool
	}
	// observations[endpoint][role] = sample
	observations := map[string]map[string]sample{}

	for _, ep := range candidates {
		if !scope.IsURLInScope(ep, scanScope) {
			continue
		}
		observations[ep] = map[string]sample{}
		for _, id := range identities {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, id.AuthProfile)
			resp, err := s.doRequestWithRetry(ctx, req, options)
			if err != nil || resp == nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, idorBodyLimit))
			_ = resp.Body.Close()
			observations[ep][id.RoleName] = sample{
				status: resp.StatusCode,
				size:   len(body),
				ok:     true,
			}
		}
	}

	type pairKey struct{ a, b string }
	emittedPair := map[pairKey]bool{}
	findings := make([]model.Finding, 0)

	endpoints := make([]string, 0, len(observations))
	for ep := range observations {
		endpoints = append(endpoints, ep)
	}
	sort.Strings(endpoints)

	for _, ep := range endpoints {
		samples := observations[ep]
		// Build a sorted list of (role, sample) for stable iteration.
		roleNames := make([]string, 0, len(samples))
		for r := range samples {
			roleNames = append(roleNames, r)
		}
		sort.Strings(roleNames)

		for i := 0; i < len(roleNames); i++ {
			ra := roleNames[i]
			sa := samples[ra]
			if !sa.ok || !is2xx(sa.status) {
				continue
			}
			for j := i + 1; j < len(roleNames); j++ {
				rb := roleNames[j]
				sb := samples[rb]
				if !sb.ok || !is2xx(sb.status) {
					continue
				}
				if abs(sa.size-sb.size) > idorBodyDelta {
					continue
				}
				// Three-way differential: when comparing two authenticated
				// roles, skip the pair if the endpoint is fully public
				// (anonymous also receives 2xx). An endpoint reachable
				// without any credentials is not an IDOR finding between
				// specific roles — it is an unauthenticated-access issue
				// which the anonymous-vs-role check below already surfaces.
				neitherIsAnon := ra != "anonymous" && rb != "anonymous"
				if neitherIsAnon {
					if anonSample, ok := samples["anonymous"]; ok && anonSample.ok && is2xx(anonSample.status) {
						continue
					}
				}
				key := pairKey{a: ra, b: rb}
				if emittedPair[key] {
					continue
				}
				emittedPair[key] = true
				findings = append(findings, buildIDORFinding(ep, ra, rb, sa.status, sa.size))
			}
		}
	}

	return findings
}

func buildIDORFinding(endpoint, roleA, roleB string, status, size int) model.Finding {
	id := "idor-role-diff-" + slugRolePair(roleA, roleB)
	severity := model.SeverityMedium
	title := fmt.Sprintf("Access-control parity between %s and %s on ID-bearing endpoint", roleA, roleB)
	if roleA == "anonymous" || roleB == "anonymous" {
		// Anonymous reaching an authenticated resource is strictly worse.
		severity = model.SeverityHigh
		title = fmt.Sprintf("Anonymous and authenticated (%s) receive equivalent response on ID-bearing endpoint", otherRole(roleA, roleB))
	}
	steps := []string{
		fmt.Sprintf("Send GET %s as %s and observe status %d (%d bytes).", endpoint, roleA, status, size),
		fmt.Sprintf("Send GET %s as %s and observe an equivalent status %d response (within %d bytes).", endpoint, roleB, status, idorBodyDelta),
		"Confirm both identities receive the same authoritative resource representation, then verify the data exposed is intended to require the higher-privilege role.",
	}
	return model.Finding{
		ID:                id,
		Category:          "access-control",
		Severity:          severity,
		Title:             title,
		Description:       "Two different identities received equivalent successful responses (matching status code and near-identical body length) on an endpoint whose path contains an opaque object identifier. This is the classic Broken Object Level Authorization (BOLA / IDOR) signature: the server failed to enforce that the requesting identity is authorised for the referenced object.",
		Evidence:          fmt.Sprintf("Endpoint %s returned status %d with ~%d bytes for both %q and %q.", endpoint, status, size, roleA, roleB),
		Recommendation:    "Enforce per-object authorization at every endpoint that accepts an object identifier: verify that the authenticated principal is permitted to access the referenced object before returning data. Authorization decisions belong server-side and must not rely on client-supplied role hints.",
		Confidence:        0.85,
		AffectedURL:       endpoint,
		CWE:               "CWE-639",
		OWASPCategory:     "A01:2021 - Broken Access Control",
		Sources:           []string{"active-scanner", "role-diff"},
		ReproductionSteps: steps,
		BusinessTags: []string{
			"role:" + roleA,
			"role:" + roleB,
		},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"reproStep":      "Replay the endpoint as both identities and compare responses",
			"roleA":          roleA,
			"roleB":          roleB,
			"status":         fmt.Sprintf("%d", status),
		},
	}
}

func idorCandidateEndpoints(target string, seeded []string, scanScope model.ScanScope) []string {
	candidates := append([]string{target}, seeded...)
	out := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		if !idorIDSegment.MatchString(u.Path) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		if !scope.IsURLInScope(raw, scanScope) {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
		if len(out) >= idorMaxEndpoints {
			break
		}
	}
	return out
}

func hasAuthHeaders(p model.ScanAuthProfile) bool {
	if len(p.Headers) > 0 || len(p.Cookies) > 0 {
		return true
	}
	if p.BasicAuthUsername != "" || p.BasicAuthPassword != "" {
		return true
	}
	return false
}

func is2xx(code int) bool { return code >= 200 && code < 300 }

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func otherRole(a, b string) string {
	if a == "anonymous" {
		return b
	}
	return a
}

func slugRolePair(a, b string) string {
	pair := []string{strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))}
	sort.Strings(pair)
	clean := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			} else {
				b.WriteRune('-')
			}
		}
		return strings.Trim(b.String(), "-")
	}
	return clean(pair[0]) + "-vs-" + clean(pair[1])
}
