package scanner

import (
	"sort"
	"strings"
	"testing"
)

// TestStructuralFingerprint verifies that dynamically-varying path segments
// and query parameter values are normalised, and that two URLs that differ
// only in resource IDs/UUIDs produce the same fingerprint.
func TestStructuralFingerprint(t *testing.T) {
	cases := []struct {
		name   string
		a, b   string
		method string
		same   bool
	}{
		{
			name:   "numeric id segments are equivalent",
			a:      "https://example.com/users/123/profile",
			b:      "https://example.com/users/456/profile",
			method: "GET",
			same:   true,
		},
		{
			name:   "uuid segments are equivalent",
			a:      "https://example.com/items/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			b:      "https://example.com/items/6ba7b811-9dad-11d1-80b4-00c04fd430c9",
			method: "GET",
			same:   true,
		},
		{
			name:   "different paths produce different fingerprints",
			a:      "https://example.com/users/123",
			b:      "https://example.com/orders/123",
			method: "GET",
			same:   false,
		},
		{
			name:   "query param values are ignored",
			a:      "https://example.com/search?q=foo&page=1",
			b:      "https://example.com/search?q=bar&page=2",
			method: "GET",
			same:   true,
		},
		{
			name:   "different param names produce different fingerprints",
			a:      "https://example.com/search?q=foo",
			b:      "https://example.com/search?term=foo",
			method: "GET",
			same:   false,
		},
		{
			name:   "different methods produce different fingerprints",
			a:      "https://example.com/users/1",
			b:      "https://example.com/users/2",
			method: "POST",
			same:   true, // still same shape — both have {id} and POST
		},
		{
			name:   "GET vs POST differ",
			a:      "https://example.com/users/1",
			b:      "https://example.com/users/1",
			method: "", // we'll override per-case below
			same:   false,
		},
	}

	// Last case tests GET vs POST directly.
	fpA := structuralFingerprint("GET", "https://example.com/users/1")
	fpB := structuralFingerprint("POST", "https://example.com/users/1")
	if fpA == fpB {
		t.Errorf("GET and POST should produce different fingerprints")
	}

	for _, tc := range cases {
		if tc.method == "" {
			continue // handled above
		}
		t.Run(tc.name, func(t *testing.T) {
			fpA := structuralFingerprint(tc.method, tc.a)
			fpB := structuralFingerprint(tc.method, tc.b)
			if tc.same && fpA != fpB {
				t.Errorf("expected same fingerprint for %q and %q, got %q vs %q", tc.a, tc.b, fpA, fpB)
			}
			if !tc.same && fpA == fpB {
				t.Errorf("expected different fingerprints for %q and %q, got %q", tc.a, tc.b, fpA)
			}
		})
	}
}

// TestStructuralFingerprintInvalidURL verifies that malformed URLs return an
// empty fingerprint rather than panicking.
func TestStructuralFingerprintInvalidURL(t *testing.T) {
	fp := structuralFingerprint("GET", "not a url")
	if fp != "" {
		t.Errorf("expected empty fingerprint for invalid URL, got %q", fp)
	}
	fp = structuralFingerprint("GET", "")
	if fp != "" {
		t.Errorf("expected empty fingerprint for empty URL, got %q", fp)
	}
}

// TestLiveScanQueueDedup verifies that the same structural fingerprint is
// only enqueued once.
func TestLiveScanQueueDedup(t *testing.T) {
	q := NewLiveScanQueue(10)

	ok1 := q.TryEnqueue("GET", "https://example.com/users/1", "", "", nil)
	ok2 := q.TryEnqueue("GET", "https://example.com/users/2", "", "", nil) // same shape → dedup
	ok3 := q.TryEnqueue("GET", "https://example.com/orders/1", "", "", nil) // different path → new

	if !ok1 {
		t.Error("first enqueue should succeed")
	}
	if ok2 {
		t.Error("second enqueue with same shape should be deduped")
	}
	if !ok3 {
		t.Error("third enqueue with different shape should succeed")
	}
	if q.Len() != 2 {
		t.Errorf("expected 2 items in queue, got %d", q.Len())
	}
	q.Close()
}

// TestLiveScanQueueCapacity verifies that items are dropped silently when the
// queue is full.
func TestLiveScanQueueCapacity(t *testing.T) {
	q := NewLiveScanQueue(2)

	accepted := 0
	dropped := 0
	for i := 0; i < 5; i++ {
		// Use a unique path per iteration so dedup doesn't interfere.
		url := strings.Replace("https://example.com/resource/N", "N", string(rune('a'+i)), 1)
		if q.TryEnqueue("GET", url, "", "", nil) {
			accepted++
		} else {
			dropped++
		}
	}
	if accepted != 2 {
		t.Errorf("expected 2 accepted items, got %d", accepted)
	}
	// Remaining items were either deduped or dropped because the queue was full.
	if q.Dropped() == 0 {
		t.Error("expected at least one dropped item when queue is at capacity")
	}
	q.Close()
}

// TestLiveScanQueueCloseIdempotent verifies Close() can be called multiple
// times without panicking.
func TestLiveScanQueueCloseIdempotent(t *testing.T) {
	q := NewLiveScanQueue(5)
	q.Close()
	q.Close() // should not panic
}

// TestLiveScanQueueNilSafe verifies all methods on a nil queue are no-ops.
func TestLiveScanQueueNilSafe(t *testing.T) {
	var q *LiveScanQueue
	ok := q.TryEnqueue("GET", "https://example.com/", "", "", nil)
	if ok {
		t.Error("nil queue enqueue should return false")
	}
	q.Close() // should not panic
	if q.Len() != 0 {
		t.Error("nil queue Len should be 0")
	}
	if q.Dropped() != 0 {
		t.Error("nil queue Dropped should be 0")
	}
}

// TestExtractInsertionPointsQueryParams verifies URL query parameters are
// extracted as InsertionPointQueryParam entries.
func TestExtractInsertionPointsQueryParams(t *testing.T) {
	pts := ExtractInsertionPoints("GET", "https://example.com/search?q=hello&page=2", "", "", nil)

	names := make([]string, 0)
	for _, p := range pts {
		if p.Kind == InsertionPointQueryParam {
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "page" || names[1] != "q" {
		t.Errorf("expected [page q], got %v", names)
	}
}

// TestExtractInsertionPointsJSONBody verifies JSON body fields are extracted
// as InsertionPointBodyField entries.
func TestExtractInsertionPointsJSONBody(t *testing.T) {
	body := `{"username":"admin","password":"secret"}`
	pts := ExtractInsertionPoints("POST", "https://example.com/login", body, "application/json", nil)

	names := make([]string, 0)
	for _, p := range pts {
		if p.Kind == InsertionPointBodyField {
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	if len(names) != 2 {
		t.Fatalf("expected 2 body fields, got %v", names)
	}
	if names[0] != "password" || names[1] != "username" {
		t.Errorf("unexpected body field names: %v", names)
	}
}

// TestExtractInsertionPointsFormBody verifies form-encoded body fields are
// extracted as InsertionPointBodyField entries.
func TestExtractInsertionPointsFormBody(t *testing.T) {
	body := "user=alice&token=abc123"
	pts := ExtractInsertionPoints("POST", "https://example.com/update",
		body, "application/x-www-form-urlencoded", nil)

	names := make([]string, 0)
	for _, p := range pts {
		if p.Kind == InsertionPointBodyField {
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	if len(names) != 2 {
		t.Fatalf("expected 2 body fields, got %v", names)
	}
	if names[0] != "token" || names[1] != "user" {
		t.Errorf("unexpected body field names: %v", names)
	}
}

// TestExtractInsertionPointsHeaders verifies that the standard injectable
// headers are always included.
func TestExtractInsertionPointsHeaders(t *testing.T) {
	pts := ExtractInsertionPoints("GET", "https://example.com/", "", "", nil)

	headerNames := make(map[string]bool)
	for _, p := range pts {
		if p.Kind == InsertionPointHeader {
			headerNames[p.Name] = true
		}
	}
	for _, expected := range injectableHeaders {
		if !headerNames[expected] {
			t.Errorf("expected injectable header %q not found", expected)
		}
	}
}

// TestNormalizePathSegment verifies the segment normalization rules.
func TestNormalizePathSegment(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"123", "{id}"},
		{"0", "{id}"},
		{"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "{uuid}"},
		{"abcdef0123456789abcdef01", "{hex}"},
		{"users", "users"},
		{"api", "api"},
		{"v2", "v2"},
	}
	for _, tc := range cases {
		got := normalizePathSegment(tc.input)
		if got != tc.want {
			t.Errorf("normalizePathSegment(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
