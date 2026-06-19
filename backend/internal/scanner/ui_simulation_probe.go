package scanner

import (
	"context"
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/toolclient"
)

// uiSimulationMaxPages is the default page budget for the simulation probe.
const uiSimulationMaxPages = 8

// RunUISimulationProbe sends the target to the UI-simulation sidecar, which
// drives a headless Chromium browser to simulate human interaction: it
// navigates all discoverable pages, clicks tabs, buttons and nav elements,
// fills forms with realistic dummy data, and collects every network request
// generated during the session.
//
// The returned findings surface coverage metadata and newly discovered
// endpoints.  The caller should feed those endpoints back into the scan
// session so subsequent active probes can exercise them.
//
// This is a best-effort integration: when the service is unavailable the
// caller receives an empty slice (no error surfaced).
func (s *Service) RunUISimulationProbe(
	ctx context.Context,
	input RunInput,
) ([]model.Finding, []DiscoveredEndpoint) {
	if !s.cfg.EnableUISimulation {
		return nil, nil
	}

	client := toolclient.NewUISimulationClient()
	if !client.IsAvailable(ctx) {
		return nil, nil
	}

	// Build login steps from the scan auth profile if provided.
	// ScanAuthLoginStep uses Value for navigate URLs (action=="navigate")
	// and for typed values (action=="type"); the sidecar LoginStep has a
	// dedicated URL field so we promote Value → URL for navigate actions.
	loginSteps := make([]toolclient.LoginStep, 0, len(input.AuthProfile.LoginSteps))
	for _, ls := range input.AuthProfile.LoginSteps {
		step := toolclient.LoginStep{
			Action:   ls.Action,
			Selector: ls.Selector,
			Value:    ls.Value,
		}
		if ls.Action == "navigate" {
			step.URL = ls.Value
			step.Value = ""
		}
		loginSteps = append(loginSteps, step)
	}

	// Build cookie string from auth profile.
	cookiePairs := make([]string, 0, len(input.AuthProfile.Cookies))
	for k, v := range input.AuthProfile.Cookies {
		cookiePairs = append(cookiePairs, k+"="+v)
	}

	// Build extra headers map.
	headers := make(map[string]string, len(input.AuthProfile.Headers))
	for k, v := range input.AuthProfile.Headers {
		headers[k] = v
	}

	timeoutSecs := int(s.cfg.IntegrationTimeout.Seconds())
	if timeoutSecs <= 0 {
		timeoutSecs = 120
	}

	req := toolclient.UISimulationRequest{
		Target:     input.Target,
		LoginSteps: loginSteps,
		Cookies:    strings.Join(cookiePairs, "; "),
		Headers:    headers,
		UserAgent:  input.AuthProfile.UserAgent,
		MaxPages:   uiSimulationMaxPages,
		MaxDepth:   2,
		Timeout:    timeoutSecs,
	}

	result, err := client.Simulate(ctx, req)
	if err != nil || result == nil {
		return nil, nil
	}

	// Map discovered endpoints back to the scanner's DiscoveredEndpoint type.
	discovered := make([]DiscoveredEndpoint, 0, len(result.DiscoveredEndpoints))
	for _, ep := range result.DiscoveredEndpoints {
		if strings.TrimSpace(ep.URL) == "" {
			continue
		}
		method := strings.TrimSpace(ep.Method)
		if method == "" {
			method = "GET"
		}
		discovered = append(discovered, DiscoveredEndpoint{URL: ep.URL, Method: method})
	}

	// Build findings from the simulation summary.
	findings := []model.Finding{
		{
			ID:       "ui-simulation-coverage",
			Category: "discovery",
			Severity: model.SeverityInfo,
			Title:    "UI simulation crawl completed",
			Description: "A headless browser session simulated human interaction across the target " +
				"application: clicking navigation elements, tabs, and buttons, and filling forms " +
				"with realistic data to surface dynamic endpoints and JavaScript-driven features.",
			Evidence: fmt.Sprintf(
				"pagesVisited=%d clicksPerformed=%d formsFilled=%d endpointsDiscovered=%d timedOut=%v",
				result.PagesVisited, result.ClicksPerformed, result.FormsFilled,
				len(result.DiscoveredEndpoints), result.TimedOut,
			),
			Recommendation: "Review the discovered dynamic endpoints for missing authentication, " +
				"injection sinks, and access-control gaps.",
		},
	}

	if len(discovered) > 0 {
		urls := make([]string, 0, len(discovered))
		for _, ep := range discovered {
			urls = append(urls, ep.Method+":"+ep.URL)
		}
		findings = append(findings, model.Finding{
			ID:       "ui-simulation-endpoints",
			Category: "discovery",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("UI simulation discovered %d dynamic endpoints", len(discovered)),
			Description: "Network requests captured during the human-simulation session revealed " +
				"additional API and resource endpoints not visible in the static HTML.",
			Evidence:       strings.Join(urls, ", "),
			Recommendation: "Test each discovered endpoint for broken access control, injection, and information disclosure.",
		})
	}

	if result.FormsFilled > 0 {
		findings = append(findings, model.Finding{
			ID:       "ui-simulation-forms",
			Category: "discovery",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("UI simulation interacted with %d form(s)", result.FormsFilled),
			Description: "The simulation filled form fields with realistic dummy data to trigger " +
				"client-side validation routines and expose hidden XHR calls.",
			Evidence:       fmt.Sprintf("formsFilled=%d", result.FormsFilled),
			Recommendation: "Ensure all form submission endpoints validate input server-side and apply appropriate rate limiting.",
		})
	}

	if result.TimedOut {
		findings = append(findings, model.Finding{
			ID:       "ui-simulation-timeout",
			Category: "coverage",
			Severity: model.SeverityInfo,
			Title:    "UI simulation session timed out before completing full coverage",
			Description: "The simulation budget expired before all pages could be visited. " +
				"Some features may not have been exercised.",
			Evidence:       fmt.Sprintf("pagesVisited=%d", result.PagesVisited),
			Recommendation: "Increase the UI_SIMULATION_TIMEOUT or reduce max_pages to ensure full coverage within budget.",
		})
	}

	return findings, discovered
}
