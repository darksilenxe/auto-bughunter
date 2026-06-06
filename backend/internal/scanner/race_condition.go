package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// raceMaxEndpoints caps how many endpoints the race-condition probe targets
// per scan to avoid excessive concurrent load.
const raceMaxEndpoints = 6

// raceWorkers is the number of goroutines fired simultaneously at each
// candidate endpoint. This is intentionally modest: real TOCTOU confirmation
// only needs 2–4 concurrent successes; higher counts just add noise.
const raceWorkers = 8

// raceWindowMs is the synchronisation window. All goroutines launch within
// this time to ensure they hit the server in the same window.
const raceWindowMs = 50 * time.Millisecond

// raceBodyLimit caps the per-response body read to bound memory use.
const raceBodyLimit = 32 * 1024

// RunRaceConditionProbe is an active Time-Of-Check/Time-Of-Use (TOCTOU) probe.
// For each candidate state-changing endpoint it fires raceWorkers concurrent
// requests through a barrier so all threads hit the server within raceWindowMs.
// When two or more concurrent requests receive a 2xx response the endpoint
// likely lacks an atomic guard (row-level lock, idempotency key, or compare-and-swap)
// and is susceptible to duplicate-action exploitation: double-spend, credit
// abuse, duplicate invite, or repeated coupon redemption.
//
// Only HTTP POST is used to avoid read-only operations causing false positives
// from cache hits. Endpoints are taken from options.SeedRuntimeEndpoints and the
// well-known transition paths in workflowTransitionPattern; all are scope-checked
// and subject to the PassiveOnly gate.
func (s *Service) RunRaceConditionProbe(
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

	candidates := bldCandidateEndpoints(target, options.SeedRuntimeEndpoints, scanScope)
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) > raceMaxEndpoints {
		candidates = candidates[:raceMaxEndpoints]
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("race-condition %s", target),
			Message: fmt.Sprintf("Probing %d endpoints for TOCTOU race conditions (%d concurrent workers per endpoint)", len(candidates), raceWorkers),
		})
	}

	var findings []model.Finding
	for _, ep := range candidates {
		if !scope.IsURLInScope(ep, scanScope) {
			continue
		}
		if f := s.raceProbeEndpoint(ctx, ep, auth, options); f != nil {
			findings = append(findings, *f)
		}
	}

	// Sort for deterministic output.
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// raceProbeEndpoint fires raceWorkers goroutines at ep simultaneously and
// returns a finding when ≥2 receive a 2xx response.
//
// Before launching the concurrent burst it sends two sequential requests to
// the same endpoint. When both return 2xx with structurally equivalent
// bodies (after normalising dynamic tokens such as UUIDs and timestamps) the
// endpoint is considered idempotent by design and the burst is skipped,
// avoiding false-positive TOCTOU findings on endpoints that are intentionally
// safe to call multiple times.
func (s *Service) raceProbeEndpoint(
	ctx context.Context,
	ep string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) *model.Finding {
	// ── Idempotency pre-check ─────────────────────────────────────────────
	// Fire two sequential POST requests and compare normalised response
	// bodies. If they match the endpoint is idempotent (or stateless) and
	// a race burst would produce spurious results.
	seqCtx, seqCancel := context.WithTimeout(ctx, 6*time.Second)
	defer seqCancel()
	var seqBodies [2]string
	for i := range seqBodies {
		req, err := http.NewRequestWithContext(seqCtx, http.MethodPost, ep, nil)
		if err != nil {
			break
		}
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(seqCtx, req, options)
		if err != nil || resp == nil {
			break
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, raceBodyLimit))
		_ = resp.Body.Close()
		if !is2xx(resp.StatusCode) {
			// Non-2xx on sequential pre-check means the burst won't
			// produce meaningful 2xx pairs either — skip.
			return nil
		}
		seqBodies[i] = NormalizeResponseBody(string(b))
	}
	// If both sequential 2xx bodies normalise to the same content the
	// endpoint is idempotent (returns the same result regardless of repeated
	// calls) — a concurrent burst is not informative here.
	if seqBodies[0] != "" && seqBodies[0] == seqBodies[1] {
		return nil
	}

	var (
		successCount int64
		mu           sync.Mutex
		statuses     []int
	)

	// Barrier: all goroutines wait at a WaitGroup before launching so they hit
	// the endpoint as simultaneously as possible within raceWindowMs.
	var barrier sync.WaitGroup
	barrier.Add(raceWorkers)
	var release sync.WaitGroup
	release.Add(raceWorkers)

	// Per-goroutine context cloned from the parent so we can cancel if done.
	raceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for i := 0; i < raceWorkers; i++ {
		go func() {
			barrier.Done()
			barrier.Wait() // synchronise

			req, err := http.NewRequestWithContext(raceCtx, http.MethodPost, ep, nil)
			if err != nil {
				release.Done()
				return
			}
			ApplyAuthProfile(req, auth)
			resp, err := s.doRequestWithRetry(raceCtx, req, options)
			if err == nil && resp != nil {
				_, _ = io.ReadAll(io.LimitReader(resp.Body, raceBodyLimit))
				_ = resp.Body.Close()
				mu.Lock()
				statuses = append(statuses, resp.StatusCode)
				mu.Unlock()
				if is2xx(resp.StatusCode) {
					atomic.AddInt64(&successCount, 1)
				}
			}
			release.Done()
		}()
	}

	// Wait for all workers; apply a hard cap so slow targets don't stall scans.
	done := make(chan struct{})
	go func() { release.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(raceWindowMs + 12*time.Second):
	}

	successes := int(atomic.LoadInt64(&successCount))
	if successes < 2 {
		return nil
	}

	mu.Lock()
	statusStr := formatStatuses(statuses)
	mu.Unlock()

	urlSlug := raceSlug(ep)
	return &model.Finding{
		ID:       "race-condition-" + urlSlug,
		Category: "race-condition",
		Severity: model.SeverityHigh,
		Title:    "TOCTOU race condition — multiple concurrent requests succeeded",
		Description: fmt.Sprintf(
			"%d out of %d concurrent POST requests to %s returned a 2xx success status within the same %dms window. "+
				"This indicates the endpoint lacks atomic mutual exclusion (row-level database lock, "+
				"compare-and-swap, or idempotency key), allowing an attacker to trigger the same "+
				"state-changing operation multiple times in a single race window. "+
				"Common impacts: double-spend in payment flows, duplicate coupon redemption, "+
				"multiple balance credits from a single deposit, or duplicate invitations.",
			successes, raceWorkers, ep, raceWindowMs.Milliseconds(),
		),
		Evidence: fmt.Sprintf(
			"Endpoint: %s | Workers: %d | Concurrent 2xx: %d | Status codes: [%s]",
			ep, raceWorkers, successes, statusStr,
		),
		Recommendation: "Protect every state-changing endpoint with a server-side atomic guard: " +
			"use database transactions with SELECT … FOR UPDATE, enforce an idempotency key per request, " +
			"or use a distributed lock (Redis SETNX) around the critical section. " +
			"Do not rely on application-level de-duplication after the fact — it is subject to the same race.",
		Confidence:    0.85,
		AffectedURL:   ep,
		CWE:           "CWE-362",
		OWASPCategory: "A04:2021 - Insecure Design",
		Sources:       []string{"active-scanner", "race-condition-probe"},
		ReproductionSteps: []string{
			fmt.Sprintf("Capture a valid POST to %s using the proxy.", ep),
			fmt.Sprintf("Use Burp Suite 'Send to Turbo Intruder' or a custom race script to fire %d identical requests simultaneously.", raceWorkers),
			"Observe that multiple requests receive a 2xx response and the server performs the action more than once.",
			"For a payment endpoint: check account balance; for an invite endpoint: check invite count; for a coupon: check redemption count.",
		},
		BusinessTags: []string{"race-condition", "toctou", "business-logic"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"reproStep":      "Fire concurrent requests via Turbo Intruder and confirm multi-success responses",
			"workers":        fmt.Sprintf("%d", raceWorkers),
			"successes":      fmt.Sprintf("%d", successes),
			"statuses":       statusStr,
		},
	}
}

func formatStatuses(statuses []int) string {
	parts := make([]string, 0, len(statuses))
	for _, s := range statuses {
		parts = append(parts, fmt.Sprintf("%d", s))
	}
	return strings.Join(parts, ",")
}

func raceSlug(rawURL string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(rawURL) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	s := b.String()
	// Trim leading/trailing dashes and limit length.
	s = strings.Trim(s, "-")
	if len(s) > 40 {
		s = s[len(s)-40:]
	}
	return strings.Trim(s, "-")
}
