package scanner

import (
	"testing"
	"time"
)

func TestProbeOutcomeLedger_RecordAndStats(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()

	// No data yet.
	_, ok := l.ProbeStats("missing")
	if ok {
		t.Fatal("expected ProbeStats to return false for unknown probe")
	}

	// Record some outcomes.
	l.RecordOutcome("xss_probe", OutcomeTP)
	l.RecordOutcome("xss_probe", OutcomeTP)
	l.RecordOutcome("xss_probe", OutcomeFP)

	entry, ok := l.ProbeStats("xss_probe")
	if !ok {
		t.Fatal("expected ProbeStats to return true")
	}
	if entry.TP != 2 || entry.FP != 1 {
		t.Fatalf("expected TP=2 FP=1, got TP=%d FP=%d", entry.TP, entry.FP)
	}
	if entry.TotalLabelled != 3 {
		t.Fatalf("expected TotalLabelled=3, got %d", entry.TotalLabelled)
	}
	if entry.LifetimeFPRate < 0.32 || entry.LifetimeFPRate > 0.34 {
		t.Fatalf("expected LifetimeFPRate ~0.33, got %f", entry.LifetimeFPRate)
	}
}

func TestProbeOutcomeLedger_AutoThrottle_TriggersAboveThreshold(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.ThrottleMinSamples = 5
	l.ThrottleFPThreshold = 0.30
	l.ThrottleWindowSize = 10

	// Not enough samples yet — must not throttle.
	for i := 0; i < 4; i++ {
		l.RecordOutcome("noisy", OutcomeFP)
	}
	if l.IsThrottled("noisy") {
		t.Fatal("should not be throttled before minSamples")
	}

	// 5th FP crosses both minSamples and threshold.
	l.RecordOutcome("noisy", OutcomeFP)
	if !l.IsThrottled("noisy") {
		t.Fatal("expected probe to be throttled after 5 FPs")
	}

	entry, _ := l.ProbeStats("noisy")
	if !entry.Throttled {
		t.Fatal("ProbeHealthEntry should mark Throttled=true")
	}
	if entry.ThrottleReason == "" {
		t.Fatal("ThrottleReason should be set")
	}
}

func TestProbeOutcomeLedger_AutoThrottle_UnthrottlesWhenRateDrops(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.ThrottleMinSamples = 5
	l.ThrottleFPThreshold = 0.30
	l.ThrottleWindowSize = 10

	// Trigger throttle.
	for i := 0; i < 5; i++ {
		l.RecordOutcome("probe", OutcomeFP)
	}
	if !l.IsThrottled("probe") {
		t.Fatal("expected throttle after 5 FPs")
	}

	// Add enough TPs to push rolling FP rate below threshold.
	for i := 0; i < 20; i++ {
		l.RecordOutcome("probe", OutcomeTP)
	}
	if l.IsThrottled("probe") {
		t.Fatal("probe should be un-throttled after rate drops below threshold")
	}
}

func TestProbeOutcomeLedger_RecordThrottleDecision(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.ThrottleMinSamples = 2
	l.ThrottleFPThreshold = 0.30
	l.ThrottleWindowSize = 10

	l.RecordOutcome("p", OutcomeFP)
	l.RecordOutcome("p", OutcomeFP)
	if !l.IsThrottled("p") {
		t.Fatal("expected throttle")
	}
	l.RecordThrottleDecision("p")
	l.RecordThrottleDecision("p")

	entry, _ := l.ProbeStats("p")
	if entry.ThrottleDecisions != 2 {
		t.Fatalf("expected ThrottleDecisions=2, got %d", entry.ThrottleDecisions)
	}
}

func TestProbeOutcomeLedger_FNDoesNotCountAsTP(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.RecordOutcome("p", OutcomeFN)
	entry, _ := l.ProbeStats("p")
	if entry.TP != 0 || entry.FP != 0 || entry.FN != 1 {
		t.Fatalf("unexpected counts: %+v", entry)
	}
}

func TestProbeOutcomeLedger_AllProbeHealthSortedByFPRate(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.ThrottleMinSamples = 1
	l.ThrottleWindowSize = 50

	// probe_a: 1 FP out of 3 total = 33% FP rate
	l.RecordOutcome("probe_a", OutcomeTP)
	l.RecordOutcome("probe_a", OutcomeTP)
	l.RecordOutcome("probe_a", OutcomeFP)

	// probe_b: 3 FP out of 4 total = 75% FP rate
	l.RecordOutcome("probe_b", OutcomeTP)
	l.RecordOutcome("probe_b", OutcomeFP)
	l.RecordOutcome("probe_b", OutcomeFP)
	l.RecordOutcome("probe_b", OutcomeFP)

	// probe_c: 0 FP = 0% FP rate
	l.RecordOutcome("probe_c", OutcomeTP)

	entries := l.AllProbeHealth()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// First entry should have highest rolling FP rate (probe_b at 75%).
	if entries[0].ProbeKey != "probe_b" {
		t.Fatalf("expected probe_b first (highest FP rate ~75%%), got %s (rate=%f)", entries[0].ProbeKey, entries[0].RollingFPRate)
	}
	// Last entry should have zero FP rate (probe_c).
	if entries[len(entries)-1].ProbeKey != "probe_c" {
		t.Fatalf("expected probe_c last (0%% FP rate), got %s (rate=%f)", entries[len(entries)-1].ProbeKey, entries[len(entries)-1].RollingFPRate)
	}
}

func TestProbeOutcomeLedger_SnapshotAndRestore(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.ThrottleMinSamples = 2
	l.ThrottleFPThreshold = 0.30
	l.ThrottleWindowSize = 10

	l.RecordOutcome("x", OutcomeTP)
	l.RecordOutcome("x", OutcomeFP)
	l.RecordOutcome("x", OutcomeFN)

	snap := l.Snapshot()
	if len(snap.Entries) != 1 {
		t.Fatalf("expected 1 entry in snapshot, got %d", len(snap.Entries))
	}

	l2 := NewProbeOutcomeLedger()
	l2.RestoreSnapshot(snap)
	entry, ok := l2.ProbeStats("x")
	if !ok {
		t.Fatal("expected restored entry")
	}
	if entry.TP != 1 || entry.FP != 1 || entry.FN != 1 {
		t.Fatalf("unexpected restored counts: %+v", entry)
	}
}

func TestProbeOutcomeLedger_OutcomeWeights_Default(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	tp, fp, fn := l.OutcomeWeights("unknown")
	if tp != 0.33 || fp != 0.33 || fn != 0.33 {
		t.Fatalf("expected equal default weights, got tp=%f fp=%f fn=%f", tp, fp, fn)
	}
}

func TestProbeOutcomeLedger_OutcomeWeights_WithData(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.RecordOutcome("sqli", OutcomeTP)
	l.RecordOutcome("sqli", OutcomeTP)
	l.RecordOutcome("sqli", OutcomeFP)
	// 2 TP, 1 FP, 0 FN — total 3
	tp, fp, fn := l.OutcomeWeights("sqli")
	if tp < 0.65 || tp > 0.67 {
		t.Fatalf("expected tp ~0.67, got %f", tp)
	}
	if fp < 0.32 || fp > 0.34 {
		t.Fatalf("expected fp ~0.33, got %f", fp)
	}
	if fn != 0 {
		t.Fatalf("expected fn=0, got %f", fn)
	}
}

func TestProbeOutcomeLedger_WindowRollsCorrectly(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	l.ThrottleWindowSize = 5
	l.ThrottleMinSamples = 5
	l.ThrottleFPThreshold = 0.30

	// Fill with TPs first so FP rate starts low.
	for i := 0; i < 20; i++ {
		l.RecordOutcome("w", OutcomeTP)
	}
	if l.IsThrottled("w") {
		t.Fatal("should not be throttled with only TPs")
	}

	// Add 5 FPs — after window rolls they become 100% of the 5-entry window.
	for i := 0; i < 5; i++ {
		l.RecordOutcome("w", OutcomeFP)
	}
	if !l.IsThrottled("w") {
		t.Fatal("probe should be throttled once window is all FPs")
	}
}

func TestProbeOutcomeLedger_LastUpdatedSet(t *testing.T) {
	t.Parallel()
	l := NewProbeOutcomeLedger()
	before := time.Now().Add(-time.Second)
	l.RecordOutcome("probe", OutcomeTP)
	entry, _ := l.ProbeStats("probe")
	if !entry.LastUpdated.After(before) {
		t.Fatalf("expected LastUpdated to be after test start, got %v", entry.LastUpdated)
	}
}
