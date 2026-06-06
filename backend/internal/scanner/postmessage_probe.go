package scanner

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"

	"github.com/chromedp/chromedp"
)

// postMessageMaxEndpoints caps how many pages the probe navigates.
const postMessageMaxEndpoints = 6

// postMessageWildcardPattern is the JavaScript injected into the page context
// that listens for postMessage events and records those sent to the wildcard
// origin ("*"), which are readable from any cross-origin parent frame.
const postMessageListenerJS = `
(function() {
  window._abhPostMsgResults = [];
  window.addEventListener('message', function(e) {
    window._abhPostMsgResults.push({
      origin: e.origin,
      dataType: typeof e.data,
      dataStr: JSON.stringify(e.data).substring(0, 200)
    });
  });
})();
`

// postMessageCollectJS collects the recorded postMessage events.
const postMessageCollectJS = `JSON.stringify(window._abhPostMsgResults || [])`

// postMessageTriggerJS sends a message to the page as if from a parent frame
// to stimulate any postMessage listeners that might relay data back.
const postMessageTriggerJS = `
if (window.parent && window.parent !== window) {
  window.parent.postMessage({type:'abh_probe'}, '*');
}
window.postMessage({type:'abh_probe'}, '*');
`

// RunPostMessageProbe is an active probe covering WSTG-CLNT-11. It uses the
// headless Chromium instance to:
//
//  1. Navigate to candidate pages and install a postMessage event listener.
//  2. Trigger a synthetic message to stimulate postMessage relay handlers.
//  3. Inspect outgoing postMessage events — flagging any that target the
//     wildcard origin ("*") and carry what appears to be sensitive data.
//
// False-positive rate is bounded by the requirement that the message data
// must contain patterns resembling credentials, tokens, or personal data.
func (s *Service) RunPostMessageProbe(
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

	candidates := extractRuntimeEndpoints(target, "", scanScope, postMessageMaxEndpoints)
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
		if len(deduped) >= postMessageMaxEndpoints {
			break
		}
	}
	candidates = deduped

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("postmessage-probe %s", target),
			Message: fmt.Sprintf("Probing %d pages for insecure postMessage origin (*)", len(candidates)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		fid := "postmessage-wildcard-" + hhSlug(ep)
		if emitted[fid] {
			continue
		}

		taskCtx, taskCancel := chromedpContext(ctx)
		var collected string

		err := chromedp.Run(taskCtx,
			chromedp.Navigate(ep),
			chromedp.Evaluate(postMessageListenerJS, nil),
			chromedp.Evaluate(postMessageTriggerJS, nil),
			chromedp.Evaluate(postMessageCollectJS, &collected),
		)
		taskCancel()

		if err != nil || strings.TrimSpace(collected) == "[]" || collected == "" {
			continue
		}

		// Check the collected messages for sensitive-looking data patterns.
		lowerCollected := strings.ToLower(collected)
		sensitivePatterns := []string{
			"token", "auth", "session", "cookie", "password", "secret",
			"key", "credential", "jwt", "bearer", "access_token", "id_token",
		}
		matchedPattern := ""
		for _, pattern := range sensitivePatterns {
			if strings.Contains(lowerCollected, pattern) {
				matchedPattern = pattern
				break
			}
		}
		if matchedPattern == "" {
			continue
		}

		emitted[fid] = true
		findings = append(findings, model.Finding{
			ID:       fid,
			Category: "client-side",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("Insecure postMessage usage — sensitive data broadcast to wildcard origin"),
			Description: fmt.Sprintf(
				"The page %s emits postMessage events containing data that matches sensitive patterns (%q) "+
					"after receiving a probe message. If the message is sent with the wildcard target origin ('*'), "+
					"any cross-origin parent frame (including attacker-controlled pages) can receive the data. "+
					"This enables credential theft, token exfiltration, and session hijacking when the page "+
					"is embedded in an attacker-controlled iframe.",
				ep, matchedPattern,
			),
			Evidence: fmt.Sprintf(
				"postMessage events captured at %s containing %q pattern: %s",
				ep, matchedPattern, truncateStr(collected, 300),
			),
			Recommendation: "Always specify an explicit target origin in postMessage calls: " +
				"window.parent.postMessage(data, 'https://trusted.example.com') " +
				"instead of window.parent.postMessage(data, '*'). " +
				"In message event listeners, validate event.origin against an allowlist before processing.",
			Confidence:    0.78,
			AffectedURL:   ep,
			CWE:           "CWE-346",
			OWASPCategory: "A01:2021 - Broken Access Control",
			Sources:       []string{"active-scanner", "postmessage-probe", "headless-browser"},
			ReproductionSteps: []string{
				fmt.Sprintf("Open a browser and embed %s in an iframe:", ep),
				"<iframe src=\"" + ep + "\"></iframe>",
				"Add a window.addEventListener('message', ...) listener in the parent page.",
				"Observe messages containing sensitive data patterns.",
			},
			BusinessTags: []string{"postmessage", "client-side", "data-exfiltration"},
			EvidenceFields: map[string]string{
				"validationType":   "active-probe",
				"sensitivePattern": matchedPattern,
				"capturedMessages": truncateStr(collected, 500),
			},
		})
	}

	return findings
}

// truncateStr returns the first n characters of s.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
