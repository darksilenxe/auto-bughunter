package scanner

import (
	"context"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestSurfaceDiff_DetectsRobotsTxtChange(t *testing.T) {
	prior := &model.SurfaceSnapshot{TakenAt: time.Now(), RobotsTxtHash: "aaa"}
	current := &model.SurfaceSnapshot{TakenAt: time.Now(), RobotsTxtHash: "bbb", JSBundleHashes: map[string]string{}}
	drifts := surfaceDiff(prior, current)
	if len(drifts) == 0 {
		t.Fatal("expected robots.txt drift")
	}
	found := false
	for _, d := range drifts {
		if d == "robots.txt changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'robots.txt changed' in drifts, got: %v", drifts)
	}
}

func TestSurfaceDiff_DetectsNewJSBundle(t *testing.T) {
	prior := &model.SurfaceSnapshot{
		TakenAt:        time.Now(),
		JSBundleHashes: map[string]string{},
	}
	current := &model.SurfaceSnapshot{
		TakenAt: time.Now(),
		JSBundleHashes: map[string]string{
			"https://example.com/app.abc123.js": "deadbeef",
		},
	}
	drifts := surfaceDiff(prior, current)
	found := false
	for _, d := range drifts {
		if d == "new JS bundle: https://example.com/app.abc123.js" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected new JS bundle drift, got: %v", drifts)
	}
}

func TestSurfaceDiff_DetectsChangedJSBundle(t *testing.T) {
	bundleURL := "https://example.com/main.js"
	prior := &model.SurfaceSnapshot{
		TakenAt:        time.Now(),
		JSBundleHashes: map[string]string{bundleURL: "hash1"},
	}
	current := &model.SurfaceSnapshot{
		TakenAt:        time.Now(),
		JSBundleHashes: map[string]string{bundleURL: "hash2"},
	}
	drifts := surfaceDiff(prior, current)
	found := false
	for _, d := range drifts {
		if d == "JS bundle changed: "+bundleURL {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected JS bundle changed drift, got: %v", drifts)
	}
}

func TestSurfaceDiff_NoDriftWhenIdentical(t *testing.T) {
	snap := &model.SurfaceSnapshot{
		TakenAt:        time.Now(),
		RobotsTxtHash:  "abc",
		SitemapHash:    "def",
		OpenAPIHash:    "ghi",
		JSBundleHashes: map[string]string{"https://example.com/app.js": "jkl"},
	}
	drifts := surfaceDiff(snap, snap)
	if len(drifts) != 0 {
		t.Fatalf("expected no drift when snapshots are identical, got: %v", drifts)
	}
}

func TestSurfaceDiff_DetectsOpenAPIChange(t *testing.T) {
	prior := &model.SurfaceSnapshot{TakenAt: time.Now(), OpenAPIHash: "v1hash", JSBundleHashes: map[string]string{}}
	current := &model.SurfaceSnapshot{TakenAt: time.Now(), OpenAPIHash: "v2hash", JSBundleHashes: map[string]string{}}
	drifts := surfaceDiff(prior, current)
	found := false
	for _, d := range drifts {
		if d == "OpenAPI/Swagger schema changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected OpenAPI schema change in drifts, got: %v", drifts)
	}
}

func TestRunSurfaceDiffProbe_PassiveOnly(t *testing.T) {
	svc := NewService(Config{})
	findings, snap := svc.RunSurfaceDiffProbe(
		context.TODO(),
		"https://example.com",
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		"",
		nil,
		nil,
	)
	if findings != nil || snap != nil {
		t.Fatalf("expected nil findings and snapshot in passive-only mode, got: findings=%v snap=%v", findings, snap)
	}
}

func TestRunSurfaceDiffProbe_FirstScanNoDiff(t *testing.T) {
	// Surface diff probe with nil prior snapshot (first scan) should return
	// nil findings and a new snapshot (baseline) but not flag drift.
	svc := NewService(Config{})
	findings, _ := svc.RunSurfaceDiffProbe(
		context.Background(),
		"https://example.com",
		model.ScanOptions{},
		model.ScanAuthProfile{},
		"",
		nil, // no prior snapshot
		nil,
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings on first scan (nil prior), got: %+v", findings)
	}
}
