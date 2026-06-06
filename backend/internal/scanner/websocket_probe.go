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
	for _, wsTarget := range candidates {
		handshakeURL := websocketToHTTP(input.Target, wsTarget)
		if handshakeURL == "" || !scope.IsURLInScope(handshakeURL, input.Scope) {
			continue
		}
		status, _, headers, ok := s.websocketHandshake(ctx, input, handshakeURL, true)
		if ok && status == http.StatusSwitchingProtocols {
			return []model.Finding{{
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
				EvidenceFields:    map[string]string{"validationType": "active-probe"},
			}}
		}
		if hasAnyAuthMaterial(input.AuthProfile) {
			status, _, _, ok = s.websocketHandshake(ctx, input, handshakeURL, false)
			if ok && status == http.StatusSwitchingProtocols {
				return []model.Finding{{
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
				}}
			}
		}
	}
	return nil
}

func (s *Service) websocketHandshake(ctx context.Context, input RunInput, raw string, authenticated bool) (int, []byte, http.Header, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, nil, nil, false
	}
	if authenticated {
		ApplyAuthProfile(req, input.AuthProfile)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Origin", "https://evil.example.com")
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
