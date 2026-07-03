package scanner

import (
	"context"
	"encoding/json"
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

type postMessageEvent struct {
	Origin   string `json:"origin"`
	DataType string `json:"dataType"`
	DataStr  string `json:"dataStr"`
}

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
	sensitivePatterns := []string{
		"token", "auth", "session", "cookie", "password", "secret",
		"key", "credential", "jwt", "bearer", "access_token", "id_token",
	}

	for _, ep := range candidates {
		fid := "postmessage-wildcard-" + hhSlug(ep)
		if emitted[fid] {
			continue
		}

		collected, err := s.collectPostMessageEvents(ctx, ep)
		if err != nil || strings.TrimSpace(collected) == "[]" || collected == "" {
			continue
		}
		matchedPattern, matchedContext, ok := classifyPostMessageLeak(collected, sensitivePatterns)
		if !ok {
			continue
		}

		finding := model.Finding{
			ID:       fid,
			Category: "client-side",
			Severity: model.SeverityHigh,
			Title:    "Insecure postMessage usage — sensitive data broadcast to wildcard origin",
			Description: fmt.Sprintf(
				"The page %s emits postMessage events containing data that matches sensitive patterns (%q) "+
					"after receiving a probe message. If the message is sent with the wildcard target origin ('*'), "+
					"any cross-origin parent frame (including attacker-controlled pages) can receive the data. "+
					"This enables credential theft, token exfiltration, and session hijacking when the page "+
					"is embedded in an attacker-controlled iframe.",
				ep, matchedPattern,
			),
			Evidence: fmt.Sprintf(
				"postMessage events captured at %s containing actionable %q data in %s context: %s",
				ep, matchedPattern, matchedContext, truncateStr(collected, 300),
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
				"messageContext":   matchedContext,
			},
		}
		out := SubmitVerifiedFinding(ctx, VerifyCandidate{
			Finding: finding,
			Signals: []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved},
			PoCReplay: func(rctx context.Context) (bool, string, error) {
				replayed, err := s.collectPostMessageEvents(rctx, ep)
				if err != nil {
					return false, "", err
				}
				pattern, contextLabel, ok := classifyPostMessageLeak(replayed, sensitivePatterns)
				return ok && pattern == matchedPattern, fmt.Sprintf("postMessage replay on %s -> %s in %s", ep, pattern, contextLabel), nil
			},
			ProbeName: "postmessage-probe",
		})
		if out.Suppressed {
			continue
		}
		emitted[fid] = true
		findings = append(findings, out.EmittedFinding)
	}

	return findings
}

func (s *Service) collectPostMessageEvents(ctx context.Context, ep string) (string, error) {
	taskCtx, taskCancel := chromedpContext(ctx)
	defer taskCancel()
	var collected string
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(ep),
		chromedp.Evaluate(postMessageListenerJS, nil),
		chromedp.Evaluate(postMessageTriggerJS, nil),
		chromedp.Evaluate(postMessageCollectJS, &collected),
	)
	return collected, err
}

func classifyPostMessageLeak(collected string, sensitivePatterns []string) (string, string, bool) {
	var events []postMessageEvent
	if err := json.Unmarshal([]byte(collected), &events); err != nil {
		lowerCollected := strings.ToLower(collected)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(lowerCollected, pattern) && !postMessageOriginEchoHeuristic(lowerCollected, pattern) {
				return pattern, "message-data", true
			}
		}
		return "", "", false
	}
	for _, event := range events {
		for _, pattern := range sensitivePatterns {
			if contextLabel, ok := classifyPostMessageEvent(event, pattern); ok {
				return pattern, contextLabel, true
			}
		}
	}
	return "", "", false
}

func classifyPostMessageEvent(event postMessageEvent, pattern string) (string, bool) {
	if pattern == "" {
		return "", false
	}
	lowerData := strings.ToLower(event.DataStr)
	if !strings.Contains(lowerData, pattern) {
		return "", false
	}
	var decoded any
	if err := json.Unmarshal([]byte(event.DataStr), &decoded); err == nil {
		if postMessageJSONHasActionablePattern(decoded, pattern, "") {
			return "message-data", true
		}
		return "", false
	}
	if postMessageOriginEchoHeuristic(lowerData, pattern) {
		return "", false
	}
	return "message-data", true
}

func postMessageJSONHasActionablePattern(v any, pattern, path string) bool {
	switch value := v.(type) {
	case map[string]any:
		for key, nested := range value {
			nextPath := path + "/" + strings.ToLower(key)
			if strings.Contains(strings.ToLower(key), pattern) && !postMessageOriginLikePath(nextPath) {
				return true
			}
			if postMessageJSONHasActionablePattern(nested, pattern, nextPath) {
				return true
			}
		}
	case []any:
		for _, nested := range value {
			if postMessageJSONHasActionablePattern(nested, pattern, path) {
				return true
			}
		}
	case string:
		lower := strings.ToLower(value)
		if strings.Contains(lower, pattern) && !postMessageOriginLikePath(path) && !postMessageLooksLikeOriginValue(lower) {
			return true
		}
	}
	return false
}

func postMessageOriginLikePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "origin") || strings.Contains(lower, "allowed_origin") || strings.Contains(lower, "targetorigin") || strings.Contains(lower, "sourceorigin")
}

func postMessageLooksLikeOriginValue(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//")
}

func postMessageOriginEchoHeuristic(lowerData, pattern string) bool {
	idx := strings.Index(lowerData, pattern)
	if idx == -1 {
		return false
	}
	start := idx - 32
	if start < 0 {
		start = 0
	}
	end := idx + len(pattern) + 32
	if end > len(lowerData) {
		end = len(lowerData)
	}
	window := lowerData[start:end]
	return strings.Contains(window, "origin") && postMessageLooksLikeOriginValue(strings.Trim(lowerData, `"`))
}

// truncateStr returns the first n characters of s.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
