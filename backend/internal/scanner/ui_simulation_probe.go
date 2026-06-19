package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

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

// uiSimulationMaxOrigins caps the number of parallel simulation agents so the
// scan budget doesn't explode for targets with hundreds of discovered endpoints.
const uiSimulationMaxOrigins = 8

// RunUISimulationAgents collects all unique in-scope origins reachable from the
// scan target (base URL, SeedRuntimeEndpoints, and all endpoints already
// discovered by earlier integration phases) and spawns one simulation agent per
// origin in parallel.  The combined findings and discovered endpoints from all
// agents are returned to the caller.
//
// This turns the UI simulation from a single-target crawl into a full-scope
// agentic sweep: every distinct application entry point (dashboard, admin panel,
// API playground, etc.) is exercised by its own headless browser session.
func (s *Service) RunUISimulationAgents(
	ctx context.Context,
	input RunInput,
	state *integrationState,
) ([]model.Finding, []DiscoveredEndpoint) {
	if !s.cfg.EnableUISimulation {
		return nil, nil
	}

	client := toolclient.NewUISimulationClient()
	if !client.IsAvailable(ctx) {
		return nil, nil
	}

	// Collect unique origins to simulate.
	origins := uiSimulationCollectOrigins(input, state)

	type agentResult struct {
		findings  []model.Finding
		endpoints []DiscoveredEndpoint
	}
	resultCh := make(chan agentResult, len(origins))

	var wg sync.WaitGroup
	for i, origin := range origins {
		if i >= uiSimulationMaxOrigins {
			break
		}
		wg.Add(1)
		go func(targetOrigin string) {
			defer wg.Done()
			// Build a per-origin RunInput derived from the original.
			originInput := input
			originInput.Target = targetOrigin
			f, ep := s.RunUISimulationProbe(ctx, originInput)
			resultCh <- agentResult{findings: f, endpoints: ep}
		}(origin)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	seenFinding := map[string]bool{}
	seenEP := map[string]bool{}
	var allFindings []model.Finding
	var allEndpoints []DiscoveredEndpoint

	for res := range resultCh {
		for _, f := range res.findings {
			if !seenFinding[f.ID+"|"+f.AffectedURL] {
				seenFinding[f.ID+"|"+f.AffectedURL] = true
				allFindings = append(allFindings, f)
			}
		}
		for _, ep := range res.endpoints {
			key := ep.Method + "|" + ep.URL
			if !seenEP[key] {
				seenEP[key] = true
				allEndpoints = append(allEndpoints, ep)
			}
		}
	}

	if len(origins) > 1 {
		allFindings = append(allFindings, model.Finding{
			ID:       "ui-simulation-multi-origin",
			Category: "discovery",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("UI simulation ran %d parallel agents across %d origin(s)", len(origins), len(origins)),
			Description: "The UI simulation ran one independent headless browser agent per unique " +
				"in-scope application origin so that every distinct entry point receives " +
				"full human-behaviour simulation coverage.",
			Evidence: fmt.Sprintf("origins=%s totalEndpointsDiscovered=%d",
				strings.Join(origins, ", "), len(allEndpoints)),
			Recommendation: "Review the per-origin crawl findings below for missing authentication, " +
				"injection sinks, and access-control gaps.",
		})
	}

	return allFindings, allEndpoints
}

// uiSimulationCollectOrigins returns deduplicated, in-scope origin URLs for
// the simulation agents.  An "origin" is scheme+host — all paths under the same
// host are crawled by the same agent starting from the root.
func uiSimulationCollectOrigins(input RunInput, state *integrationState) []string {
	seen := map[string]struct{}{}
	var origins []string

	addOrigin := func(rawURL string) {
		u, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil || u.Host == "" {
			return
		}
		origin := u.Scheme + "://" + u.Host
		if _, ok := seen[origin]; ok {
			return
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}

	// 1. Base target (always first).
	addOrigin(input.Target)

	// 2. Explicit seeds provided by the user.
	for _, seed := range input.Options.SeedRuntimeEndpoints {
		addOrigin(seed)
	}

	// 3. Endpoints discovered by earlier phases (katana, gau, ffuf, etc.).
	if state != nil {
		state.mu.Lock()
		eps := append([]string(nil), state.DiscoveredEndpoints...)
		state.mu.Unlock()
		for _, ep := range eps {
			addOrigin(ep)
		}
	}

	return origins
}
