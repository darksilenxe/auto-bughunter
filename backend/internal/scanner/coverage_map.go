package scanner

import (
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// BuildCoverageMap aggregates the per-scan SurfaceInventory, the global probed
// keys registry, authenticated role profiles, and the previous scan's coverage
// map (for delta tracking) into a structured CoverageMap artifact.
//
// The map is attached to the ScanJob at scan completion and is also consumed
// by the adaptive probe agent to prioritise remaining budget on high-ROI
// uncovered areas.
//
// Scoring:
//
//	LikelihoodScore — estimated probability that this area is vulnerable.
//	    Base: 0.3 for all endpoints.
//	    +0.3 if the HTTP method is state-changing (POST/PUT/PATCH/DELETE).
//	    +0.2 if discovered from JS-runtime XHR interception (dynamic surface).
//	    +0.1 if the path contains auth-adjacent terms (/auth, /login, /admin…).
//
//	ImpactScore — estimated business impact.
//	    Base: 0.3.
//	    +0.3 for admin/privileged paths.
//	    +0.2 for API paths (/api/, /v1/, /graphql).
//	    +0.1 for state-changing HTTP methods.
//
//	ROIScore = LikelihoodScore × ImpactScore.
func BuildCoverageMap(
	target string,
	inv *SurfaceInventory,
	roleProfiles []model.RoleAuthProfile,
	findings []model.Finding,
	prev *model.CoverageMap,
) *model.CoverageMap {
	if inv == nil {
		inv = NewSurfaceInventory()
	}

	// Build a count of findings per surface key for the FindingCount field.
	findingsByKey := make(map[string]int)
	for _, f := range findings {
		if f.AffectedURL == "" {
			continue
		}
		k := strings.ToLower(strings.TrimRight(f.AffectedURL, "/"))
		findingsByKey[k]++
	}

	areas := make([]model.CoverageMapArea, 0)

	// Auth-state areas: one per distinct role profile + unauthenticated.
	authStates := []string{"unauthenticated"}
	for _, rp := range roleProfiles {
		if rp.RoleName != "" {
			authStates = append(authStates, rp.RoleName)
		}
	}
	for _, state := range authStates {
		key := "auth:" + state
		areas = append(areas, model.CoverageMapArea{
			Type:            model.CoverageAreaAuthState,
			Key:             key,
			Source:          "config",
			LikelihoodScore: 0.5,
			ImpactScore:     impactForAuthState(state),
			ROIScore:        0.5 * impactForAuthState(state),
			Probed:          true, // auth states are always "entered" (config-driven)
		})
	}

	// Role areas: one per distinct role (for IDOR coverage).
	for _, rp := range roleProfiles {
		if rp.RoleName == "" {
			continue
		}
		key := "role:" + rp.RoleName
		// A role is considered probed when multiple auth profiles were configured
		// and IDOR role-diff probes ran. We approximate this as true when >1 role
		// was configured (the role-diff probe always runs in that case).
		roleProbed := len(roleProfiles) > 1
		areas = append(areas, model.CoverageMapArea{
			Type:            model.CoverageAreaRole,
			Key:             key,
			Source:          "config",
			LikelihoodScore: 0.4,
			ImpactScore:     0.6,
			ROIScore:        0.24,
			Probed:          roleProbed,
		})
	}

	// Endpoint and JS-runtime areas from inventory.
	entries := inv.Snapshot()
	for _, e := range entries {
		inventoryKey := e.Key() // SHA1-based key used for probed-set lookup
		// Human-readable key for the coverage map: "METHOD host/path"
		areaKey := strings.ToUpper(e.Method) + " " + strings.TrimRight(e.Host+e.Path, "/")
		if areaKey == " " {
			areaKey = e.URL
		}
		_, probed := globalProbedKeys.keys.Load(inventoryKey)

		areaType := model.CoverageAreaEndpoint
		src := ""
		if len(e.Sources) > 0 {
			src = string(e.Sources[0])
			for _, s := range e.Sources {
				if s == SurfaceSourceRuntimeXHR {
					areaType = model.CoverageAreaJSRuntime
					src = string(s)
					break
				}
			}
		}

		likelihood := likelihoodForEntry(e)
		impact := impactForEntry(e)
		roi := likelihood * impact

		fk := strings.ToLower(strings.TrimRight(e.URL, "/"))
		fc := findingsByKey[fk]

		areas = append(areas, model.CoverageMapArea{
			Type:            areaType,
			Key:             areaKey,
			Source:          src,
			LikelihoodScore: likelihood,
			ImpactScore:     impact,
			ROIScore:        roi,
			Probed:          probed,
			FindingCount:    fc,
		})
	}

	// Deduplicate by key (last writer wins — inventory deduplication should
	// have already taken care of this but guard defensively).
	seen := make(map[string]int, len(areas))
	deduped := make([]model.CoverageMapArea, 0, len(areas))
	for _, a := range areas {
		if idx, exists := seen[a.Key]; exists {
			// Keep the one that is probed, or higher ROI.
			if a.Probed && !deduped[idx].Probed {
				deduped[idx] = a
			} else if a.ROIScore > deduped[idx].ROIScore && !deduped[idx].Probed {
				deduped[idx] = a
			}
			continue
		}
		seen[a.Key] = len(deduped)
		deduped = append(deduped, a)
	}
	areas = deduped

	// Sort: probed first, then by ROI descending.
	sort.SliceStable(areas, func(i, j int) bool {
		if areas[i].Probed != areas[j].Probed {
			return areas[i].Probed // probed first
		}
		return areas[i].ROIScore > areas[j].ROIScore
	})

	totalAreas := len(areas)
	probedAreas := 0
	for _, a := range areas {
		if a.Probed {
			probedAreas++
		}
	}
	coverageRatio := 0.0
	if totalAreas > 0 {
		coverageRatio = float64(probedAreas) / float64(totalAreas)
	}

	// Top uncovered high-ROI areas (up to 20).
	highROI := make([]string, 0, 20)
	for _, a := range areas {
		if !a.Probed && a.ROIScore > 0 {
			highROI = append(highROI, a.Key)
			if len(highROI) >= 20 {
				break
			}
		}
	}

	// Delta: compare against previous coverage map.
	deltaNew := []string{}
	deltaMissing := []string{}
	if prev != nil {
		prevKeys := make(map[string]struct{}, len(prev.Areas))
		for _, pa := range prev.Areas {
			prevKeys[pa.Key] = struct{}{}
		}
		curKeys := make(map[string]struct{}, len(areas))
		for _, ca := range areas {
			curKeys[ca.Key] = struct{}{}
			if _, ok := prevKeys[ca.Key]; !ok {
				deltaNew = append(deltaNew, ca.Key)
			}
		}
		for _, pa := range prev.Areas {
			if _, ok := curKeys[pa.Key]; !ok {
				deltaMissing = append(deltaMissing, pa.Key)
			}
		}
	}

	return &model.CoverageMap{
		GeneratedAt:       time.Now().UTC(),
		Target:            target,
		Areas:             areas,
		TotalAreas:        totalAreas,
		ProbedAreas:       probedAreas,
		CoverageRatio:     coverageRatio,
		HighROIUncovered:  highROI,
		DeltaNewAreas:     deltaNew,
		DeltaMissingAreas: deltaMissing,
	}
}

// CoverageMapHighROIURLs returns the URL strings from HighROIUncovered areas
// so callers (e.g. the adaptive probe agent) can issue additional requests.
// Keys have the human-readable format "METHOD host/path"; this function strips
// the method prefix and reconstructs a best-effort https:// URL from the key.
// Auth/role keys ("auth:…", "role:…") are skipped — they are not directly
// request-able URLs.
func CoverageMapHighROIURLs(cm *model.CoverageMap) []string {
	if cm == nil {
		return nil
	}
	out := make([]string, 0, len(cm.HighROIUncovered))
	for _, k := range cm.HighROIUncovered {
		if strings.HasPrefix(k, "auth:") || strings.HasPrefix(k, "role:") {
			continue
		}
		// Key format: "METHOD host/path"
		parts := strings.SplitN(k, " ", 2)
		if len(parts) == 2 {
			hostPath := parts[1]
			if strings.HasPrefix(hostPath, "http://") || strings.HasPrefix(hostPath, "https://") {
				out = append(out, hostPath)
			} else {
				out = append(out, "https://"+hostPath)
			}
		}
	}
	return out
}

// likelihoodForEntry estimates the probability that a SurfaceEntry contains a
// vulnerability based on its HTTP method and source.
func likelihoodForEntry(e SurfaceEntry) float64 {
	score := 0.3
	method := strings.ToUpper(strings.TrimSpace(e.Method))
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		score += 0.3
	}
	for _, s := range e.Sources {
		if s == SurfaceSourceRuntimeXHR {
			score += 0.2
			break
		}
	}
	lower := strings.ToLower(e.URL)
	for _, hint := range []string{"/auth", "/login", "/admin", "/user", "/account", "/password", "/reset"} {
		if strings.Contains(lower, hint) {
			score += 0.1
			break
		}
	}
	if score > 1 {
		score = 1
	}
	return score
}

// impactForEntry estimates the business impact if a vulnerability is found at
// this SurfaceEntry.
func impactForEntry(e SurfaceEntry) float64 {
	score := 0.3
	lower := strings.ToLower(e.URL)
	for _, hint := range []string{"/admin", "/superuser", "/internal", "/management"} {
		if strings.Contains(lower, hint) {
			score += 0.3
			break
		}
	}
	for _, hint := range []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"} {
		if strings.Contains(lower, hint) {
			score += 0.2
			break
		}
	}
	method := strings.ToUpper(strings.TrimSpace(e.Method))
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		score += 0.1
	}
	if score > 1 {
		score = 1
	}
	return score
}

// impactForAuthState returns the estimated impact score for a given auth state
// string. Admin/privileged states carry higher impact.
func impactForAuthState(state string) float64 {
	lower := strings.ToLower(state)
	for _, hint := range []string{"admin", "superuser", "root", "operator", "manager"} {
		if strings.Contains(lower, hint) {
			return 0.9
		}
	}
	if lower == "unauthenticated" {
		return 0.5
	}
	return 0.6
}
