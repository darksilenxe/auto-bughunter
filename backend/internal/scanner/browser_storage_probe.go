package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"

	"github.com/chromedp/chromedp"
)

// browserStorageMaxEndpoints caps how many pages the probe visits.
const browserStorageMaxEndpoints = 4

// storageCollectJS collects all localStorage, sessionStorage, and IndexedDB
// database names from the current page context.
const storageCollectJS = `
(function() {
  var result = {localStorage: {}, sessionStorage: {}, indexedDB: []};
  try {
    for (var i = 0; i < localStorage.length; i++) {
      var k = localStorage.key(i);
      result.localStorage[k] = localStorage.getItem(k);
    }
  } catch(e) {}
  try {
    for (var i = 0; i < sessionStorage.length; i++) {
      var k = sessionStorage.key(i);
      result.sessionStorage[k] = sessionStorage.getItem(k);
    }
  } catch(e) {}
  try {
    indexedDB.databases().then(function(dbs) {
      result.indexedDB = dbs.map(function(d) { return d.name; });
    });
  } catch(e) {}
  return JSON.stringify(result);
})()
`

// sensitiveStorageKeyPatterns are key name patterns that suggest the storage
// entry contains sensitive data (tokens, credentials, PII).
//
// Bare generic terms like "key", "user", "email", and "address" were removed
// from this list: real-world apps routinely persist non-sensitive UI state
// under keys such as "cache_key", "user_theme", "contact_email", or
// "ip_address", and flagging every one of those as a security finding was a
// significant source of false positives during deterministic (non-AI)
// scanning. The remaining patterns target names that are only ever used for
// authentication/credential material or clearly regulated PII.
var sensitiveStorageKeyPatterns = []string{
	"token", "auth", "session", "access_token", "id_token", "refresh_token",
	"jwt", "bearer", "password", "passwd", "secret", "api_key", "apikey",
	"private_key", "credential", "cookie", "ssn", "dob",
	"payment", "card", "ccnum", "cvv",
}

// jwtStructurePattern matches the three dot-separated base64url segments of
// an actual JSON Web Token (header.payload.signature). A bare "eyJ" prefix
// check previously matched *any* base64-encoded JSON blob (any base64'd
// `{"...` string starts with "eyJ"), which produced frequent false positives
// for non-token data. Requiring the full three-segment structure confirms
// the value is plausibly a real JWT before it is reported as High severity.
var jwtStructurePattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}`)

// apiKeyPrefixPattern matches well-known API key/token prefixes followed by
// a plausibly long opaque identifier, to avoid flagging short/incidental
// substrings that merely happen to contain the prefix text.
var apiKeyPrefixPattern = regexp.MustCompile(`(?:sk-|ghp_|xox[baprs]-)[A-Za-z0-9_-]{10,}`)

// RunBrowserStorageProbe is an active probe covering WSTG-CLNT-12. It uses the
// headless Chromium instance to enumerate localStorage, sessionStorage, and
// IndexedDB databases after page load and optionally after authentication.
//
// Findings are raised when:
//   - A storage key name matches a sensitive pattern (token, auth, session, etc.)
//   - A storage value matches a known sensitive value pattern (JWT, API key prefix)
//
// This detects anti-patterns such as storing JWTs or credentials in localStorage
// (which is accessible to any same-origin JavaScript, making them vulnerable to
// XSS exfiltration).
func (s *Service) RunBrowserStorageProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(target, "", scanScope, browserStorageMaxEndpoints)
	if len(options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{target}
	}
	seen := map[string]struct{}{}
	var deduped []string
	for _, c := range candidates {
		if _, ok := seen[c]; ok {
			continue
		}
		if !scope.IsURLInScope(c, scanScope) {
			continue
		}
		seen[c] = struct{}{}
		deduped = append(deduped, c)
		if len(deduped) >= browserStorageMaxEndpoints {
			break
		}
	}
	candidates = deduped

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("browser-storage %s", target),
			Message: fmt.Sprintf("Probing %d pages for sensitive data in localStorage/sessionStorage", len(candidates)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		storageJSON, err := s.collectBrowserStorageJSON(ctx, ep)
		if err != nil || strings.TrimSpace(storageJSON) == "" {
			continue
		}

		storageFindings := analyzeStorageJSON(ep, storageJSON, emitted)
		for _, finding := range storageFindings {
			if !RequiresUnconditionalVerification(finding.Severity) {
				findings = append(findings, finding)
				continue
			}
			emittedFinding, ok := s.verifyBrowserStorageFinding(ctx, ep, finding)
			if ok {
				findings = append(findings, emittedFinding)
			}
		}
	}

	return findings
}

func (s *Service) collectBrowserStorageJSON(ctx context.Context, ep string) (string, error) {
	taskCtx, taskCancel := chromedpContext(ctx)
	defer taskCancel()
	var storageJSON string
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(ep),
		chromedp.Evaluate(storageCollectJS, &storageJSON),
	)
	return storageJSON, err
}

func (s *Service) verifyBrowserStorageFinding(ctx context.Context, ep string, finding model.Finding) (model.Finding, bool) {
	pattern := browserStorageReplayPattern(finding)
	if pattern == "" {
		return finding, true
	}
	out := SubmitVerifiedFinding(ctx, VerifyCandidate{
		Finding: finding,
		Signals: []EvidenceSignal{EvidenceSinkObserved},
		PoCReplay: func(rctx context.Context) (bool, string, error) {
			replayedJSON, err := s.collectBrowserStorageJSON(rctx, ep)
			if err != nil {
				return false, "", err
			}
			matched := browserStorageReplayMatches(replayedJSON, pattern)
			return matched, fmt.Sprintf("storage replay on %s reproduced %s", ep, pattern), nil
		},
		ProbeName: "browser-storage-probe",
	})
	if out.Suppressed {
		return model.Finding{}, false
	}
	return out.EmittedFinding, true
}

// analyzeStorageJSON inspects the collected storage JSON for sensitive keys
// and values and returns any findings.
func analyzeStorageJSON(ep, storageJSON string, emitted map[string]bool) []model.Finding {
	var findings []model.Finding
	lower := strings.ToLower(storageJSON)

	// Check key names.
	for _, pattern := range sensitiveStorageKeyPatterns {
		fid := "browser-storage-key-" + pattern + "-" + hhSlug(ep)
		if emitted[fid] {
			continue
		}
		if strings.Contains(lower, `"`+pattern+`"`) || strings.Contains(lower, `"`+pattern+`_`) ||
			strings.Contains(lower, `_`+pattern+`"`) {
			emitted[fid] = true
			findings = append(findings, model.Finding{
				ID:       fid,
				Category: "client-side",
				Severity: model.SeverityMedium,
				Title:    fmt.Sprintf("Sensitive data in browser storage — key matches %q pattern", pattern),
				Description: fmt.Sprintf(
					"The page %s stores data in localStorage or sessionStorage under a key matching "+
						"the sensitive pattern %q. localStorage data is accessible to any same-origin "+
						"JavaScript, meaning a single XSS vulnerability can exfiltrate all stored tokens, "+
						"credentials, and session identifiers. Sensitive authentication data should be "+
						"stored in HttpOnly cookies, not localStorage/sessionStorage.",
					ep, pattern,
				),
				Evidence: fmt.Sprintf("Storage key matching %q pattern detected at %s", pattern, ep),
				Recommendation: "Do not store authentication tokens, JWTs, or session identifiers in " +
					"localStorage or sessionStorage. Use HttpOnly, Secure, SameSite=Strict cookies for " +
					"session management. For SPAs, use in-memory storage (JavaScript closure) for " +
					"short-lived tokens and refresh via secure cookies.",
				Confidence:    0.75,
				AffectedURL:   ep,
				CWE:           "CWE-312",
				OWASPCategory: "A02:2021 - Cryptographic Failures",
				Sources:       []string{"active-scanner", "browser-storage", "headless-browser"},
				ReproductionSteps: []string{
					fmt.Sprintf("Open %s in a browser after logging in.", ep),
					"Open DevTools → Application → Local Storage / Session Storage.",
					fmt.Sprintf("Observe key matching %q containing sensitive data.", pattern),
				},
				BusinessTags: []string{"browser-storage", "client-side", "sensitive-data"},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"keyPattern":     pattern,
					"pageURL":        ep,
				},
			})
		}
	}

	// Check values. Each check requires a structural match (not just a bare
	// substring) so that incidental prefix collisions in unrelated base64 or
	// opaque strings are not reported as high-confidence credential leaks.
	type valueCheck struct {
		id      string
		label   string
		matched string
	}
	var valueChecks []valueCheck
	if loc := jwtStructurePattern.FindString(storageJSON); loc != "" {
		valueChecks = append(valueChecks, valueCheck{id: "jwt", label: "JWT (header.payload.signature)", matched: loc})
	}
	if loc := apiKeyPrefixPattern.FindString(storageJSON); loc != "" {
		valueChecks = append(valueChecks, valueCheck{id: "api-key", label: "API key/token", matched: loc})
	}
	if idx := strings.Index(storageJSON, "Bearer "); idx != -1 {
		rest := strings.TrimSpace(storageJSON[idx+len("Bearer "):])
		if end := strings.IndexAny(rest, `"',}`); end >= 12 {
			valueChecks = append(valueChecks, valueCheck{id: "bearer", label: "OAuth bearer token", matched: "Bearer " + rest[:end]})
		}
	}

	for _, chk := range valueChecks {
		fid := "browser-storage-value-" + chk.id + "-" + hhSlug(ep)
		if emitted[fid] {
			continue
		}
		emitted[fid] = true
		findings = append(findings, model.Finding{
			ID:       fid,
			Category: "client-side",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("High-confidence sensitive value in browser storage — %s detected", chk.label),
			Description: fmt.Sprintf(
				"The page %s stores a value in localStorage or sessionStorage that structurally matches "+
					"a %s, strongly suggesting an authentication token is stored in client-side storage. "+
					"This is directly exploitable by any XSS vulnerability on the same origin.",
				ep, chk.label,
			),
			Evidence: fmt.Sprintf("Storage value matching %s structure detected at %s", chk.label, ep),
			Recommendation: "Move authentication tokens from localStorage to HttpOnly cookies. " +
				"If localStorage must be used for non-authentication data, ensure all pages on " +
				"the origin have a strict CSP to prevent XSS exfiltration.",
			Confidence:    0.82,
			AffectedURL:   ep,
			CWE:           "CWE-312",
			OWASPCategory: "A02:2021 - Cryptographic Failures",
			Sources:       []string{"active-scanner", "browser-storage", "headless-browser"},
			ReproductionSteps: []string{
				fmt.Sprintf("Open %s in a browser after logging in.", ep),
				"Open DevTools → Application → Local Storage / Session Storage.",
				fmt.Sprintf("Observe the %s value.", chk.label),
			},
			BusinessTags: []string{"browser-storage", "jwt", "client-side"},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"valuePattern":   chk.label,
				"pageURL":        ep,
			},
		})
	}

	return findings
}

func browserStorageReplayPattern(f model.Finding) string {
	return strings.TrimSpace(f.EvidenceFields["valuePattern"])
}

func browserStorageReplayMatches(storageJSON, pattern string) bool {
	switch strings.TrimSpace(pattern) {
	case "JWT (header.payload.signature)":
		return jwtStructurePattern.FindString(storageJSON) != ""
	case "API key/token":
		return apiKeyPrefixPattern.FindString(storageJSON) != ""
	case "OAuth bearer token":
		idx := strings.Index(storageJSON, "Bearer ")
		if idx == -1 {
			return false
		}
		rest := strings.TrimSpace(storageJSON[idx+len("Bearer "):])
		if end := strings.IndexAny(rest, `"',}`); end >= 12 {
			return true
		}
	}
	return false
}
