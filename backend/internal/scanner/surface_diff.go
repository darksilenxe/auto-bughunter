package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// surfaceSnapshotFetchTimeout is the per-request timeout for surface probing.
// Kept short to avoid stalling the main scan.
const surfaceSnapshotFetchTimeout = 5 * time.Second

// surfaceSnapshotPathCap is the maximum number of JS bundles hashed per snapshot.
// Prevents over-fetching on bundle-heavy SPAs.
const surfaceSnapshotPathCap = 8

// surfaceKnownPaths lists the well-known resource paths hashed on every
// snapshot. Changes to these resources indicate schema additions, endpoint
// removals, or changed crawl-exclusion rules.
var surfaceKnownPaths = []string{
	"/robots.txt",
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/openapi.json",
	"/openapi.yaml",
	"/swagger.json",
	"/api-docs",
}

// surfaceJSSrcPattern extracts <script src="..."> paths from HTML bodies.
var surfaceJSSrcPattern = regexp.MustCompile(`(?i)<script[^>]+\bsrc=["']([^"']+\.js[^"']*)["']`)

// TakeSurfaceSnapshot collects a lightweight fingerprint of the target's
// public attack surface: SHA-256 hashes of robots.txt, sitemap.xml, OpenAPI
// documents, and discovered JS bundle URLs from the already-fetched page body.
// Errors during individual fetches are silently ignored; a partial snapshot is
// still useful for drift detection.
func (s *Service) TakeSurfaceSnapshot(
	ctx context.Context,
	target string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
	bodyText string,
) *model.SurfaceSnapshot {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	snap := &model.SurfaceSnapshot{
		TakenAt:        time.Now().UTC(),
		JSBundleHashes: map[string]string{},
	}

	// Hash the well-known surface resource paths.
	for _, path := range surfaceKnownPaths {
		ref, err := url.Parse(path)
		if err != nil {
			continue
		}
		fullURL := base.ResolveReference(ref).String()
		hash := s.surfaceHashURL(ctx, fullURL, auth, options)
		if hash == "" {
			continue
		}
		switch path {
		case "/robots.txt":
			snap.RobotsTxtHash = hash
		case "/sitemap.xml", "/sitemap_index.xml":
			if snap.SitemapHash == "" {
				snap.SitemapHash = hash
			}
		default:
			// OpenAPI / Swagger documents.
			if snap.OpenAPIHash == "" {
				snap.OpenAPIHash = hash
			}
		}
	}

	// Extract JS bundle URLs from the already-fetched page body and hash each.
	for _, m := range surfaceJSSrcPattern.FindAllStringSubmatch(bodyText, -1) {
		if len(m) < 2 {
			continue
		}
		ref, err := url.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		bundleURL := base.ResolveReference(ref).String()
		if _, seen := snap.JSBundleHashes[bundleURL]; seen {
			continue
		}
		if len(snap.JSBundleHashes) >= surfaceSnapshotPathCap {
			break
		}
		if hash := s.surfaceHashURL(ctx, bundleURL, auth, options); hash != "" {
			snap.JSBundleHashes[bundleURL] = hash
		}
	}

	snap.EndpointCount = len(options.SeedRuntimeEndpoints)
	return snap
}

// surfaceHashURL fetches rawURL and returns the hex-encoded SHA-256 of the
// response body. Returns an empty string on transport error, 404, or 403.
func (s *Service) surfaceHashURL(
	ctx context.Context,
	rawURL string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) string {
	fetchCtx, cancel := context.WithTimeout(ctx, surfaceSnapshotFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	ApplyAuthProfile(req, auth)

	resp, err := s.doRequestWithRetry(fetchCtx, req, options)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return ""
	}

	h := sha256.New()
	// 256KB is sufficient to detect content changes in schema/sitemap/robots
	// documents while keeping memory usage bounded during bulk snapshotting.
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 256*1024)); err != nil {
		// A truncated read produces a hash that's stable but not derivable
		// from the full body. Returning empty signals "no usable hash" so the
		// surface-diff probe doesn't claim the resource is unchanged when we
		// actually couldn't read it.
		log.Printf("surface_diff: read body for %s: %v", rawURL, err)
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// RunSurfaceDiffProbe compares a freshly collected surface snapshot against
// the prior snapshot stored in persistedState and emits findings for detected
// drift (new JS bundles, changed resource hashes, updated API schema).
//
// On the first scan (no prior snapshot) the probe collects a baseline and
// returns it without emitting any findings — nothing to diff against yet.
// On subsequent scans the diff informs which changed endpoints should be
// prioritised for immediate re-testing.
func (s *Service) RunSurfaceDiffProbe(
	ctx context.Context,
	target string,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	bodyText string,
	prior *model.SurfaceSnapshot,
	emit func(model.ScanEvent),
) ([]model.Finding, *model.SurfaceSnapshot) {
	if options.PassiveOnly {
		return nil, nil
	}

	current := s.TakeSurfaceSnapshot(ctx, target, auth, options, bodyText)
	if current == nil {
		return nil, nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("surface-diff %s", target),
			Message: "Comparing surface snapshot for drift",
		})
	}

	// First scan — establish baseline only.
	if prior == nil {
		return nil, current
	}

	drifts := surfaceDiff(prior, current)
	if len(drifts) == 0 {
		return nil, current
	}

	f := model.Finding{
		ID:       "surface-drift-detected",
		Category: "monitoring",
		Severity: model.SeverityInfo,
		Title:    fmt.Sprintf("Target surface drift detected (%d change(s))", len(drifts)),
		Description: "Comparing the current scan surface fingerprint against the previous " +
			"snapshot reveals changes in JS bundles, API schema documents, robots.txt, or " +
			"sitemap. Surface drift indicates the application has been updated since the " +
			"last scan; changed or new surface elements are high-priority re-test targets " +
			"because vulnerabilities in new code are most likely to be unreported.",
		Evidence: strings.Join(drifts, "; "),
		Recommendation: "Prioritise active testing of the changed or newly added endpoints " +
			"and JS bundles listed above. Feed the changed URLs into SeedRuntimeEndpoints " +
			"for the next targeted scan to ensure new attack surface receives full probe coverage.",
		Confidence:  0.95,
		DriftStatus: "changed",
		Sources:     []string{"surface-diff"},
		EvidenceFields: map[string]string{
			"validationType": "safe-observation",
			"reproStep":      "Compare prior and current surface snapshots; re-test changed endpoints",
			"driftCount":     fmt.Sprintf("%d", len(drifts)),
		},
	}
	return []model.Finding{f}, current
}

// surfaceDiff returns a sorted, human-readable list of surface changes between
// two snapshots. An empty slice means no drift was detected.
func surfaceDiff(prior, current *model.SurfaceSnapshot) []string {
	var drifts []string

	if prior.RobotsTxtHash != "" && current.RobotsTxtHash != "" &&
		prior.RobotsTxtHash != current.RobotsTxtHash {
		drifts = append(drifts, "robots.txt changed")
	}
	if prior.SitemapHash != "" && current.SitemapHash != "" &&
		prior.SitemapHash != current.SitemapHash {
		drifts = append(drifts, "sitemap.xml changed")
	}
	if prior.OpenAPIHash != "" && current.OpenAPIHash != "" &&
		prior.OpenAPIHash != current.OpenAPIHash {
		drifts = append(drifts, "OpenAPI/Swagger schema changed")
	}

	for bundleURL, currentHash := range current.JSBundleHashes {
		if priorHash, existed := prior.JSBundleHashes[bundleURL]; !existed {
			drifts = append(drifts, fmt.Sprintf("new JS bundle: %s", bundleURL))
		} else if priorHash != currentHash {
			drifts = append(drifts, fmt.Sprintf("JS bundle changed: %s", bundleURL))
		}
	}

	sort.Strings(drifts)
	return drifts
}
