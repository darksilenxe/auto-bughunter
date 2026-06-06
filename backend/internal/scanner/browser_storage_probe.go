package scanner

import (
	"context"
	"fmt"
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
var sensitiveStorageKeyPatterns = []string{
	"token", "auth", "session", "access_token", "id_token", "refresh_token",
	"jwt", "bearer", "password", "passwd", "secret", "key", "credential",
	"cookie", "user", "email", "phone", "ssn", "dob", "address",
	"payment", "card", "ccnum", "cvv",
}

// sensitiveStorageValuePatterns are patterns in storage *values* that suggest
// sensitive content (e.g. JWT format, base64-encoded blobs).
var sensitiveStorageValuePatterns = []string{
	"eyJ",     // base64-encoded JSON (JWT header)
	"Bearer ", // OAuth bearer token
	"sk-",     // API key prefixes
	"ghp_",    // GitHub PAT
	"xox",     // Slack token
}

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
		taskCtx, taskCancel := chromedpContext(ctx)
		var storageJSON string

		err := chromedp.Run(taskCtx,
			chromedp.Navigate(ep),
			chromedp.Evaluate(storageCollectJS, &storageJSON),
		)
		taskCancel()

		if err != nil || strings.TrimSpace(storageJSON) == "" {
			continue
		}

		storageFindings := analyzeStorageJSON(ep, storageJSON, emitted)
		findings = append(findings, storageFindings...)
	}

	return findings
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
				Evidence:    fmt.Sprintf("Storage key matching %q pattern detected at %s", pattern, ep),
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

	// Check values.
	for _, pattern := range sensitiveStorageValuePatterns {
		fid := "browser-storage-value-" + strings.ReplaceAll(pattern, " ", "_") + "-" + hhSlug(ep)
		if emitted[fid] {
			continue
		}
		if strings.Contains(storageJSON, pattern) {
			emitted[fid] = true
			findings = append(findings, model.Finding{
				ID:       fid,
				Category: "client-side",
				Severity: model.SeverityHigh,
				Title:    fmt.Sprintf("High-confidence sensitive value in browser storage — matches %q prefix", pattern),
				Description: fmt.Sprintf(
					"The page %s stores a value in localStorage or sessionStorage that matches the "+
						"%q prefix pattern, strongly suggesting a JWT, API key, or authentication token "+
						"is stored in client-side storage. This is directly exploitable by any XSS "+
						"vulnerability on the same origin.",
					ep, pattern,
				),
				Evidence:    fmt.Sprintf("Storage value matching prefix %q detected at %s", pattern, ep),
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
					fmt.Sprintf("Observe value starting with %q.", pattern),
				},
				BusinessTags: []string{"browser-storage", "jwt", "client-side"},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"valuePattern":   pattern,
					"pageURL":        ep,
				},
			})
		}
	}

	return findings
}
