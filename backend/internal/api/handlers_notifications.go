package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scanner"
)

func (s *Server) notifyFindings(job *model.ScanJob) {
	if job == nil {
		return
	}
	if s.webhookURL == "" && s.slackWebhook == "" {
		return
	}
	type noteFinding struct {
		ID         string         `json:"id"`
		Title      string         `json:"title"`
		Severity   model.Severity `json:"severity"`
		Confidence float64        `json:"confidence"`
		Drift      string         `json:"driftStatus,omitempty"`
	}
	selected := make([]noteFinding, 0)
	for _, f := range job.Findings {
		if f.Confidence < s.notifyMinConf {
			continue
		}
		if strings.ToLower(strings.TrimSpace(f.DriftStatus)) != "new" && strings.ToLower(strings.TrimSpace(f.DriftStatus)) != "changed" {
			continue
		}
		selected = append(selected, noteFinding{
			ID:         f.ID,
			Title:      f.Title,
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Drift:      f.DriftStatus,
		})
	}
	if len(selected) == 0 {
		return
	}
	payload := map[string]any{
		"scanId":    job.ID,
		"target":    job.Target,
		"findings":  selected,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	sendWebhookJSON(s.webhookURL, payload)
	if s.slackWebhook != "" {
		lines := []string{fmt.Sprintf("*auto-bughunter:* %d high-confidence drift finding(s) on `%s`", len(selected), job.Target)}
		for _, item := range selected {
			lines = append(lines, fmt.Sprintf("• [%s] %s (%.2f)", strings.ToUpper(string(item.Severity)), item.Title, item.Confidence))
		}
		sendWebhookJSON(s.slackWebhook, map[string]string{"text": strings.Join(limitStrings(lines, 12), "\n")})
	}
}

// notifyNoisyProbes fires a "noisy probe" alert (Wave 1 Phase B) when any
// probe in the global ProbeOutcomeLedger is auto-throttled. Called after
// analyst triage actions update the ledger. The alert is sent at most once per
// throttle event (the ledger records ThrottledAt so duplicates are skipped by
// comparing against the last notified set in the server state).
func (s *Server) notifyNoisyProbes() {
	if s.webhookURL == "" && s.slackWebhook == "" {
		return
	}
	entries := scanner.GlobalProbeOutcomeLedger().AllProbeHealth()
	var noisy []scanner.ProbeHealthEntry
	for _, e := range entries {
		if e.Throttled {
			noisy = append(noisy, e)
		}
	}
	if len(noisy) == 0 {
		return
	}
	type noisyProbeNote struct {
		ProbeKey       string  `json:"probeKey"`
		RollingFPRate  float64 `json:"rollingFpRate"`
		RollingWindow  int     `json:"rollingWindow"`
		ThrottleReason string  `json:"throttleReason"`
	}
	notes := make([]noisyProbeNote, 0, len(noisy))
	for _, e := range noisy {
		notes = append(notes, noisyProbeNote{
			ProbeKey:       e.ProbeKey,
			RollingFPRate:  e.RollingFPRate,
			RollingWindow:  e.RollingWindow,
			ThrottleReason: e.ThrottleReason,
		})
	}
	payload := map[string]any{
		"alertType": "noisy-probe-throttled",
		"probes":    notes,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	sendWebhookJSON(s.webhookURL, payload)
	if s.slackWebhook != "" {
		lines := []string{fmt.Sprintf(":warning: *auto-bughunter noisy-probe alert:* %d probe(s) auto-throttled", len(noisy))}
		for _, n := range notes {
			lines = append(lines, fmt.Sprintf("• `%s` — rolling FP rate %.0f%% (%d samples)", n.ProbeKey, n.RollingFPRate*100, n.RollingWindow))
		}
		sendWebhookJSON(s.slackWebhook, map[string]string{"text": strings.Join(limitStrings(lines, 10), "\n")})
	}
}

// notifyCoverageDelta fires a coverage-delta drift alert (Wave 2 Phase C)
// when new attack-surface areas appear in the latest scan's CoverageMap that
// were absent from the previous scan. Sent via webhook and Slack if configured.
func (s *Server) notifyCoverageDelta(target string, newAreas []string) {
	if s.webhookURL == "" && s.slackWebhook == "" {
		return
	}
	if len(newAreas) == 0 {
		return
	}
	payload := map[string]any{
		"type":      "coverage_delta",
		"target":    target,
		"newAreas":  newAreas,
		"count":     len(newAreas),
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	sendWebhookJSON(s.webhookURL, payload)
	if s.slackWebhook != "" {
		text := fmt.Sprintf(":new: *auto-bughunter coverage-delta alert:* %d new attack-surface area(s) on `%s`", len(newAreas), target)
		sendWebhookJSON(s.slackWebhook, map[string]string{"text": text})
	}
}

func sendWebhookJSON(target string, payload any) {
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Transport: safety.NewSafeTransport(),
		Timeout:   5 * time.Second,
		CheckRedirect: func(redirReq *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if err := safety.ValidateOutboundURL(redirReq.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked by outbound safety policy for %q: %w", redirReq.URL.String(), err)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func hostFromTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func diffAssets(previous, current []model.ScanAsset) []string {
	prev := map[string]struct{}{}
	for _, a := range previous {
		prev[a.AssetType+"|"+a.AssetKey] = struct{}{}
	}
	newOnes := make([]string, 0)
	for _, a := range current {
		k := a.AssetType + "|" + a.AssetKey
		if _, ok := prev[k]; ok {
			continue
		}
		newOnes = append(newOnes, k)
	}
	sort.Strings(newOnes)
	return newOnes
}
