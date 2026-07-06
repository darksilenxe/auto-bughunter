package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

var websocketURLPattern = regexp.MustCompile(`(?i)new\s+WebSocket\(\s*["']([^"']+)["']|\b(wss?://[^"'\s<]+)`)

func (s *Service) runWebSocketProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := websocketCandidates(input.Target, body)
	for _, seeded := range input.Options.SeedRuntimeEndpoints {
		lower := strings.ToLower(seeded)
		if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
			candidates = append(candidates, seeded)
		}
	}
	candidates = dedupeStrings(candidates)
	for _, wsTarget := range candidates {
		handshakeURL := websocketToHTTP(input.Target, wsTarget)
		if handshakeURL == "" || !scope.IsURLInScope(handshakeURL, input.Scope) {
			continue
		}
		RecordProbedKey(http.MethodGet, handshakeURL, "")
		status, _, headers, ok := s.websocketHandshake(ctx, input, handshakeURL, true, true, "https://evil.example.com")
		if ok && isValidWebSocketUpgrade(status, headers) {
			ctrlStatus, _, ctrlHeaders, ctrlOK := s.websocketHandshake(ctx, input, handshakeURL, true, false, "")
			if ctrlOK && isValidWebSocketUpgrade(ctrlStatus, ctrlHeaders) {
				continue
			}
			finding := model.Finding{
				ID:                "cswsh-detected",
				Category:          "websocket",
				Severity:          model.SeverityHigh,
				Title:             "Cross-site WebSocket hijacking (CSWSH) risk",
				Description:       "The WebSocket endpoint completed an upgrade handshake even when the Origin header was set to an attacker-controlled site, indicating missing or ineffective origin validation.",
				Evidence:          fmt.Sprintf("GET %s with Origin: https://evil.example.com returned HTTP %d and Upgrade headers (%s)", handshakeURL, status, cacheHeaderSummary(headers)),
				Recommendation:    "Validate the Origin header against an allowlist before upgrading WebSocket requests and require authentication on the handshake path.",
				Confidence:        0.86,
				AffectedURL:       handshakeURL,
				CWE:               "CWE-1385",
				OWASPCategory:     "A01:2021 - Broken Access Control",
				Sources:           []string{"active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("Send a WebSocket upgrade request to %s with Origin: https://evil.example.com", handshakeURL), "Observe the 101 Switching Protocols response."},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"controlStatus":  fmt.Sprintf("%d", ctrlStatus),
				},
			}
			emitted, ok := s.submitWebSocketFinding(ctx, finding, func(rctx context.Context) (bool, string, error) {
				replayStatus, _, replayHeaders, replayOK := s.websocketHandshake(rctx, input, handshakeURL, true, true, "https://evil.example.com")
				return replayOK && isValidWebSocketUpgrade(replayStatus, replayHeaders), fmt.Sprintf("evil-origin upgrade replay -> HTTP %d (%s)", replayStatus, cacheHeaderSummary(replayHeaders)), nil
			}, []EvidenceSignal{EvidenceHeaderDelta, EvidenceSinkObserved})
			if ok {
				return []model.Finding{emitted}
			}
		}
		if hasAnyAuthMaterial(input.AuthProfile) {
			status, _, headers, ok = s.websocketHandshake(ctx, input, handshakeURL, false, true, "")
			if ok && isValidWebSocketUpgrade(status, headers) {
				ctrlStatus, _, ctrlHeaders, ctrlOK := s.websocketHandshake(ctx, input, handshakeURL, false, false, "")
				if ctrlOK && isValidWebSocketUpgrade(ctrlStatus, ctrlHeaders) {
					continue
				}
				finding := model.Finding{
					ID:             "websocket-no-auth",
					Category:       "websocket",
					Severity:       model.SeverityHigh,
					Title:          "WebSocket endpoint upgraded without authentication",
					Description:    "The WebSocket endpoint accepted an unauthenticated upgrade handshake, indicating the channel may be reachable without session enforcement.",
					Evidence:       fmt.Sprintf("Unauthenticated GET %s returned HTTP 101 Switching Protocols", handshakeURL),
					Recommendation: "Require authentication on the handshake request and fail closed before establishing WebSocket sessions.",
					Confidence:     0.8,
					AffectedURL:    handshakeURL,
					CWE:            "CWE-1385",
					OWASPCategory:  "A01:2021 - Broken Access Control",
					Sources:        []string{"active-scanner"},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"controlStatus":  fmt.Sprintf("%d", ctrlStatus),
					},
				}
				emitted, ok := s.submitWebSocketFinding(ctx, finding, func(rctx context.Context) (bool, string, error) {
					replayStatus, _, replayHeaders, replayOK := s.websocketHandshake(rctx, input, handshakeURL, false, true, "")
					return replayOK && isValidWebSocketUpgrade(replayStatus, replayHeaders), fmt.Sprintf("unauthenticated upgrade replay -> HTTP %d (%s)", replayStatus, cacheHeaderSummary(replayHeaders)), nil
				}, []EvidenceSignal{EvidenceHeaderDelta, EvidenceSinkObserved})
				if ok {
					return []model.Finding{emitted}
				}
			}
		}
	}
	return nil
}

func (s *Service) submitWebSocketFinding(ctx context.Context, finding model.Finding, replay PoCReplayFunc, signals []EvidenceSignal) (model.Finding, bool) {
	out := SubmitVerifiedFinding(ctx, VerifyCandidate{
		Finding:   finding,
		Signals:   signals,
		PoCReplay: replay,
		ProbeName: "websocket-probe",
	})
	if out.Suppressed {
		return model.Finding{}, false
	}
	return out.EmittedFinding, true
}

func isValidWebSocketUpgrade(status int, headers http.Header) bool {
	if status != http.StatusSwitchingProtocols {
		return false
	}
	return strings.Contains(strings.ToLower(headers.Get("Connection")), "upgrade") && strings.EqualFold(strings.TrimSpace(headers.Get("Upgrade")), "websocket")
}

func (s *Service) websocketHandshake(ctx context.Context, input RunInput, raw string, authenticated, upgrade bool, origin string) (int, []byte, http.Header, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, nil, nil, false
	}
	if authenticated {
		ApplyAuthProfile(req, input.AuthProfile)
	}
	if upgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
	}
	if strings.TrimSpace(origin) != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return 0, nil, nil, false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		return resp.StatusCode, nil, resp.Header, true
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	return resp.StatusCode, body, resp.Header, true
}

func websocketCandidates(target, body string) []string {
	matches := websocketURLPattern.FindAllStringSubmatch(body, -1)
	var out []string
	for _, match := range matches {
		for _, candidate := range match[1:] {
			if strings.TrimSpace(candidate) != "" {
				out = append(out, candidate)
			}
		}
	}
	lower := strings.ToLower(body)
	if len(out) == 0 && (strings.Contains(lower, "socket.io") || strings.Contains(lower, "ws://") || strings.Contains(lower, "wss://") || strings.Contains(lower, "new websocket")) {
		out = append(out, target)
	}
	if len(out) == 0 {
		out = append(out, target)
	}
	return dedupeStrings(out)
}

func websocketToHTTP(baseTarget, wsTarget string) string {
	wsTarget = strings.TrimSpace(wsTarget)
	if wsTarget == "" {
		return ""
	}
	if strings.HasPrefix(wsTarget, "ws://") {
		return "http://" + strings.TrimPrefix(wsTarget, "ws://")
	}
	if strings.HasPrefix(wsTarget, "wss://") {
		return "https://" + strings.TrimPrefix(wsTarget, "wss://")
	}
	if strings.HasPrefix(wsTarget, "http://") || strings.HasPrefix(wsTarget, "https://") {
		return wsTarget
	}
	return resolveEndpoint(baseTarget, wsTarget)
}
