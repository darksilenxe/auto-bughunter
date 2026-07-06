package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRunGapReQueuePass_NoOpCases verifies the fast paths that must not
// issue any HTTP traffic: PassiveOnly scans, an empty gap list, and gaps
// whose URLs were already part of the first-pass SeedRuntimeEndpoints
// (so the second pass would be pure duplicate work).
func TestRunGapReQueuePass_NoOpCases(t *testing.T) {
	svc := NewService(Config{})
	base := RunInput{Target: "https://example.test/"}

	t.Run("passive_only", func(t *testing.T) {
		input := base
		input.Options.PassiveOnly = true
		gaps := []SurfaceGap{{Reason: SurfaceGapUnprobed, Entry: SurfaceEntry{URL: "https://example.test/api/new"}}}
		if got := svc.runGapReQueuePass(context.Background(), input, "", gaps); got != nil {
			t.Fatalf("expected nil findings for PassiveOnly, got %v", got)
		}
	})

	t.Run("no_gaps", func(t *testing.T) {
		if got := svc.runGapReQueuePass(context.Background(), base, "", nil); got != nil {
			t.Fatalf("expected nil findings for empty gap list, got %v", got)
		}
	})

	t.Run("already_seeded", func(t *testing.T) {
		input := base
		input.Options.SeedRuntimeEndpoints = []string{"https://example.test/api/known"}
		gaps := []SurfaceGap{{Reason: SurfaceGapUnprobed, Entry: SurfaceEntry{URL: "https://example.test/api/known"}}}
		if got := svc.runGapReQueuePass(context.Background(), input, "", gaps); got != nil {
			t.Fatalf("expected nil findings when the gap URL was already seeded, got %v", got)
		}
	})
}

// TestRunGapReQueuePass_ReprobesNewGapURL verifies the additive second
// pass: a gap URL that was never part of SeedRuntimeEndpoints must get
// re-probed (RecordProbedKey advances) and any resulting finding must be
// annotated so it's traceable back to the gap-requeue pass.
func TestRunGapReQueuePass_ReprobesNewGapURL(t *testing.T) {
	ResetSurfaceCoverageMetrics()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	svc := NewService(Config{})
	input := RunInput{Target: srv.URL, Session: NewScanSession()}
	gapURL := srv.URL + "/api/gapped"
	gaps := []SurfaceGap{{Reason: SurfaceGapUnprobed, Entry: SurfaceEntry{URL: gapURL}}}

	findings := svc.runGapReQueuePass(context.Background(), input, "", gaps)

	if m := GetSurfaceCoverageMetrics(); m.ProbedTotal == 0 {
		t.Fatalf("expected the re-queued gap URL to be probed (ProbedTotal advanced)")
	}
	for _, f := range findings {
		if !strings.Contains(f.Description, "gap-requeue") {
			t.Fatalf("expected gap-requeue annotation in finding description, got %q", f.Description)
		}
	}
}

// TestSelectHighROIGaps_BudgetsGapReQueue is a smoke test ensuring the
// budget constant caps how many gaps runGapReQueuePass will act on, so
// a very large unprobed inventory cannot blow up scan duration.
func TestSelectHighROIGaps_BudgetsGapReQueue(t *testing.T) {
	var gaps []SurfaceGap
	for i := 0; i < gapReQueueBudget*3; i++ {
		gaps = append(gaps, SurfaceGap{
			Reason: SurfaceGapUnprobed,
			Entry:  SurfaceEntry{URL: fmt.Sprintf("https://example.test/api/%d", i)},
		})
	}
	top := SelectHighROIGaps(gaps, gapReQueueBudget)
	if len(top) != gapReQueueBudget {
		t.Fatalf("expected %d gaps selected, got %d", gapReQueueBudget, len(top))
	}
}
