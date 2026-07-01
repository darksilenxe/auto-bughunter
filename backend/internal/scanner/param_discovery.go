package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"auto-bughunter/backend/internal/model"
)

// param_discovery is a lightweight Arjun-style hidden-parameter miner:
// for a given target URL it sends the request with a small built-in
// wordlist of extra parameter names (each carrying a unique marker
// value) and reports back the names whose markers are reflected in the
// response body. Confirmed names are added to SurfaceInventory under
// SurfaceSourceParamDiscover so downstream probes can fuzz them.
//
// The module deliberately keeps its own request budget (independent of
// the per-probe budgets) so it never overwhelms the target when many
// candidate endpoints are queued. Callers pass the shared HTTP client
// via *Service so proxy recording, retries, and auth still apply.

// ParamDiscoveryWordlist is the built-in wordlist of "usually-hidden"
// parameter names that Arjun-style scanners have found to be the most
// productive across public bug bounty data sets. It is small on
// purpose — hidden-parameter mining is a coverage aid, not the
// authoritative parameter oracle.
var ParamDiscoveryWordlist = []string{
	// generic
	"debug", "test", "admin", "verbose", "trace", "mode", "env",
	// auth / identity
	"user", "userid", "uid", "role", "impersonate", "token", "apikey",
	// data selection
	"id", "ref", "key", "hash", "type", "status", "page", "limit",
	// callbacks / SSRF surface
	"callback", "url", "next", "return", "redirect", "target", "dest",
	// file surface
	"file", "path", "dir", "template", "include", "cmd",
	// feature flags
	"feature", "flag", "beta", "preview", "override",
}

// ParamDiscoveryCandidate is a single mined-parameter hit.
type ParamDiscoveryCandidate struct {
	URL       string
	Parameter string
	// Reflected marker: when non-empty the parameter's value was
	// echoed verbatim in the response body, which is strong evidence
	// the server-side handler read it.
	MarkerReflected bool
	// StatusDelta: absolute HTTP status difference from the
	// baseline. Non-zero indicates the server took a different
	// code path when the parameter was present.
	StatusDelta int
}

// paramDiscoveryCounters tracks process-wide param-discovery metrics
// surfaced to AutomationMetrics.Extra.
type paramDiscoveryCounters struct {
	candidates atomic.Uint64
	confirmed  atomic.Uint64
}

var globalParamDiscovery = &paramDiscoveryCounters{}

// ParamDiscoveryMetrics is a snapshot for AutomationMetrics.Extra.
type ParamDiscoveryMetrics struct {
	Candidates uint64 `json:"candidates"`
	Confirmed  uint64 `json:"confirmed"`
}

// GetParamDiscoveryMetrics returns a snapshot of the process-wide
// param-discovery counters.
func GetParamDiscoveryMetrics() ParamDiscoveryMetrics {
	return ParamDiscoveryMetrics{
		Candidates: globalParamDiscovery.candidates.Load(),
		Confirmed:  globalParamDiscovery.confirmed.Load(),
	}
}

// ResetParamDiscoveryMetrics resets the process-wide counters.
// Intended for tests.
func ResetParamDiscoveryMetrics() {
	globalParamDiscovery.candidates.Store(0)
	globalParamDiscovery.confirmed.Store(0)
}

// DiscoverHiddenParams sends the target URL once as a control baseline
// and then once per wordlist entry, each with a distinct marker value,
// and returns the parameters whose marker was reflected back or whose
// status code differed from the baseline.
//
// The number of network requests issued is len(wordlist)+1, capped at
// budget when budget > 0. Callers should keep budget small (single
// digits per endpoint) so miner cost stays bounded across the scan.
//
// The function respects the ambient context deadline and returns
// partial results when the deadline fires. When s is nil or the target
// URL is unparseable it returns nil, nil.
func (s *Service) DiscoverHiddenParams(ctx context.Context, target string, wordlist []string, budget int) ([]ParamDiscoveryCandidate, error) {
	if s == nil {
		return nil, nil
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if len(wordlist) == 0 {
		wordlist = ParamDiscoveryWordlist
	}
	if budget <= 0 {
		budget = len(wordlist) + 1
	}

	// 1) Baseline.
	baselineStatus, baselineBody, err := s.discoverParamsFetch(ctx, target)
	if err != nil {
		return nil, err
	}
	// If baseline already contains any marker prefix we use, bail out
	// so we don't false-positive on echoes of arbitrary text.
	if strings.Contains(baselineBody, paramDiscoveryMarkerPrefix) {
		return nil, nil
	}

	// 2) Per-param probes.
	sent := 1
	var results []ParamDiscoveryCandidate
	for _, name := range wordlist {
		if sent >= budget {
			break
		}
		if ctx.Err() != nil {
			break
		}
		p := strings.ToLower(strings.TrimSpace(name))
		if p == "" {
			continue
		}
		marker := paramDiscoveryMarker(p)
		probeURL, err := buildParamProbeURL(u, p, marker)
		if err != nil {
			continue
		}
		status, body, err := s.discoverParamsFetch(ctx, probeURL)
		sent++
		if err != nil {
			continue
		}
		globalParamDiscovery.candidates.Add(1)
		reflected := strings.Contains(body, marker)
		statusDelta := absInt(status - baselineStatus)
		if !reflected && statusDelta == 0 {
			continue
		}
		globalParamDiscovery.confirmed.Add(1)
		results = append(results, ParamDiscoveryCandidate{
			URL:             target,
			Parameter:       p,
			MarkerReflected: reflected,
			StatusDelta:     statusDelta,
		})
	}
	return results, nil
}

const paramDiscoveryMarkerPrefix = "abhpd-"

// paramDiscoveryMarker returns a deterministic per-parameter marker so
// tests can predict what the miner sends without having to snoop
// randomness. Format: `abhpd-<param>-marker`.
func paramDiscoveryMarker(param string) string {
	return paramDiscoveryMarkerPrefix + param + "-marker"
}

// buildParamProbeURL adds ?param=marker to the target URL. When param
// already exists as a query key on the target we preserve the existing
// value and add the marker as a second value so the same code path is
// exercised.
func buildParamProbeURL(u *url.URL, param, marker string) (string, error) {
	if u == nil {
		return "", fmt.Errorf("nil url")
	}
	probe := *u
	q := probe.Query()
	if q.Get(param) != "" {
		q.Add(param, marker)
	} else {
		q.Set(param, marker)
	}
	probe.RawQuery = q.Encode()
	return probe.String(), nil
}

func (s *Service) discoverParamsFetch(ctx context.Context, target string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := s.doRequestWithRetry(ctx, req, model.ScanOptions{})
	if err != nil || resp == nil {
		if err == nil {
			err = fmt.Errorf("nil response")
		}
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp.StatusCode, string(body), nil
}
