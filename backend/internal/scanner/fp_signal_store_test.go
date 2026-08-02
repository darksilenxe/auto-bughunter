package scanner

import (
	"testing"
)

func TestFPSignalStore_Record_FPRate(t *testing.T) {
	t.Parallel()
	store := NewFPSignalStore()

	const probe = "test_probe"
	const rawURL = "https://example.com/api/v1?q=1"
	const rawURL2 = "https://example.com/api/v1?q=2" // same pattern after normalisation

	// Not enough samples yet.
	rate, samples := store.FPRate(probe, rawURL, 5)
	if rate != 0 || samples != 0 {
		t.Fatalf("expected (0,0) before minSamples, got (%v,%v)", rate, samples)
	}

	// Record 3 suppressed, 2 verified (total 5).
	store.Record(probe, rawURL, true)
	store.Record(probe, rawURL, true)
	store.Record(probe, rawURL, true)
	store.Record(probe, rawURL2, false) // different query string, same pattern
	store.Record(probe, rawURL2, false) // same

	rate, samples = store.FPRate(probe, rawURL, 5)
	if samples != 5 {
		t.Fatalf("expected 5 samples, got %d", samples)
	}
	// 3 suppressed of 5 fired = 0.6
	if rate < 0.59 || rate > 0.61 {
		t.Fatalf("expected FP rate ~0.6, got %v", rate)
	}
}

func TestFPSignalStore_Record_Zero(t *testing.T) {
	t.Parallel()
	store := NewFPSignalStore()
	// Record 5 verified (no suppressions).
	for i := 0; i < 5; i++ {
		store.Record("probe_x", "https://target.com/page", false)
	}
	rate, samples := store.FPRate("probe_x", "https://target.com/page", 5)
	if samples != 5 {
		t.Fatalf("expected 5 samples, got %d", samples)
	}
	if rate != 0 {
		t.Fatalf("expected FP rate 0, got %v", rate)
	}
}

func TestFPSignalStore_AllRecords(t *testing.T) {
	t.Parallel()
	store := NewFPSignalStore()
	store.Record("p1", "https://a.com/x", true)
	store.Record("p2", "https://b.com/y", false)
	recs := store.AllRecords()
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
}

func TestURLPattern(t *testing.T) {
	t.Parallel()
	cases := []struct{ raw, want string }{
		{"https://example.com/api?q=1", "example.com/api"},
		{"https://example.com/api?q=2", "example.com/api"},
		{"https://EXAMPLE.COM/Path", "example.com/Path"},
		{"not-a-url", "not-a-url"},
		{"", ""},
	}
	for _, tc := range cases {
		got := urlPattern(tc.raw)
		if got != tc.want {
			t.Errorf("urlPattern(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestFPSignalStore_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	store := NewFPSignalStore()
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				store.Record("p", "https://x.com/y", j%2 == 0)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	_, samples := store.FPRate("p", "https://x.com/y", 1)
	if samples != 200 {
		t.Fatalf("expected 200 samples, got %d", samples)
	}
}
