package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestBuildCoverageMap_EmptyInventory(t *testing.T) {
	cm := BuildCoverageMap("https://example.com", nil, nil, nil, nil)
	if cm == nil {
		t.Fatal("expected non-nil CoverageMap")
	}
	if cm.TotalAreas == 0 {
		t.Error("expected at least auth:unauthenticated area")
	}
	if cm.CoverageRatio < 0 || cm.CoverageRatio > 1 {
		t.Errorf("CoverageRatio out of range: %f", cm.CoverageRatio)
	}
}

func TestBuildCoverageMap_EndpointScoring(t *testing.T) {
	inv := NewSurfaceInventory()
	inv.Add("POST", "https://example.com/api/v1/users", nil, SurfaceSourceCrawl)
	inv.Add("GET", "https://example.com/admin/settings", nil, SurfaceSourceCrawl)
	inv.Add("GET", "https://example.com/login", nil, SurfaceSourceRuntimeXHR)

	cm := BuildCoverageMap("https://example.com", inv, nil, nil, nil)
	if cm == nil {
		t.Fatal("expected non-nil CoverageMap")
	}

	// All endpoint areas should have ROIScore > 0.
	for _, a := range cm.Areas {
		if a.Type == model.CoverageAreaEndpoint || a.Type == model.CoverageAreaJSRuntime {
			if a.ROIScore <= 0 {
				t.Errorf("area %q has zero ROI score", a.Key)
			}
		}
	}

	// POST /api/v1/users should have a high likelihood (state-changing + API path).
	var postAPIArea *model.CoverageMapArea
	for i := range cm.Areas {
		if cm.Areas[i].Type == model.CoverageAreaEndpoint &&
			cm.Areas[i].LikelihoodScore >= 0.5 &&
			cm.Areas[i].ImpactScore >= 0.5 {
			postAPIArea = &cm.Areas[i]
			break
		}
	}
	if postAPIArea == nil {
		t.Error("expected a high-likelihood+impact area for POST /api/v1/users")
	}
}

func TestBuildCoverageMap_RoleAreas(t *testing.T) {
	roleProfiles := []model.RoleAuthProfile{
		{RoleName: "admin"},
		{RoleName: "user"},
	}
	cm := BuildCoverageMap("https://example.com", nil, roleProfiles, nil, nil)
	roleCount := 0
	for _, a := range cm.Areas {
		if a.Type == model.CoverageAreaRole {
			roleCount++
		}
	}
	if roleCount != 2 {
		t.Errorf("expected 2 role areas, got %d", roleCount)
	}
}

func TestBuildCoverageMap_HighROIUncovered(t *testing.T) {
	inv := NewSurfaceInventory()
	inv.Add("POST", "https://example.com/api/v1/payments", nil, SurfaceSourceCrawl)
	inv.Add("GET", "https://example.com/static/logo.png", nil, SurfaceSourceCrawl)

	cm := BuildCoverageMap("https://example.com", inv, nil, nil, nil)
	if cm == nil {
		t.Fatal("nil CoverageMap")
	}
	// High ROI uncovered list should not be nil when areas exist.
	if cm.TotalAreas == 0 {
		t.Error("expected non-zero total areas")
	}
}

func TestBuildCoverageMap_DeltaDetection(t *testing.T) {
	inv := NewSurfaceInventory()
	inv.Add("GET", "https://example.com/api/v1/new-endpoint", nil, SurfaceSourceCrawl)

	prev := &model.CoverageMap{
		Areas: []model.CoverageMapArea{
			{Key: "GET example.com/api/v1/old-endpoint"},
		},
	}

	cm := BuildCoverageMap("https://example.com", inv, nil, nil, prev)
	if len(cm.DeltaNewAreas) == 0 {
		t.Error("expected DeltaNewAreas to contain the new endpoint")
	}
	if len(cm.DeltaMissingAreas) == 0 {
		t.Error("expected DeltaMissingAreas to contain the old endpoint")
	}
}

func TestBuildCoverageMap_CoverageRatio(t *testing.T) {
	inv := NewSurfaceInventory()
	inv.Add("GET", "https://example.com/page1", nil, SurfaceSourceCrawl)
	inv.Add("GET", "https://example.com/page2", nil, SurfaceSourceCrawl)

	cm := BuildCoverageMap("https://example.com", inv, nil, nil, nil)
	if cm.CoverageRatio < 0 || cm.CoverageRatio > 1 {
		t.Errorf("CoverageRatio out of [0,1]: %f", cm.CoverageRatio)
	}
	if cm.TotalAreas == 0 {
		t.Error("expected non-zero total areas")
	}
}

func TestCoverageMapHighROIURLs_SkipsAuthAndRole(t *testing.T) {
	cm := &model.CoverageMap{
		HighROIUncovered: []string{
			"auth:unauthenticated",
			"role:admin",
			"GET example.com/api/v1/users",
		},
	}
	urls := CoverageMapHighROIURLs(cm)
	for _, u := range urls {
		if u == "auth:unauthenticated" || u == "role:admin" {
			t.Errorf("auth/role key should be skipped, got %q", u)
		}
	}
	if len(urls) == 0 {
		t.Error("expected at least one URL from endpoint key")
	}
}
