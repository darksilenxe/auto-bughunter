package proxy

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestServerScopeDefaultsToCaptureEverything(t *testing.T) {
	s := NewServer(nil)
	if !s.InScope("https://example.com/anything") {
		t.Fatalf("expected default (empty) scope to allow all URLs")
	}
}

func TestServerScopeIncludeHostsRestrictsCapture(t *testing.T) {
	s := NewServer(nil)
	s.SetScope(model.ScanScope{IncludeHosts: []string{"example.com", "*.example.com"}})

	if !s.InScope("https://example.com/path") {
		t.Fatalf("expected example.com to be in scope")
	}
	if !s.InScope("https://api.example.com/path") {
		t.Fatalf("expected api.example.com to match *.example.com wildcard")
	}
	if s.InScope("https://evil.test/path") {
		t.Fatalf("expected evil.test to be out of scope")
	}
}

func TestServerScopeExcludeHostsBlocksCapture(t *testing.T) {
	s := NewServer(nil)
	s.SetScope(model.ScanScope{ExcludeHosts: []string{"*.internal.example.com"}})

	if s.InScope("https://admin.internal.example.com/path") {
		t.Fatalf("expected excluded host to be out of scope")
	}
	if !s.InScope("https://example.com/path") {
		t.Fatalf("expected non-excluded host to remain in scope")
	}
}

func TestServerScopeExcludePathsBlocksCapture(t *testing.T) {
	s := NewServer(nil)
	s.SetScope(model.ScanScope{ExcludePaths: []string{"/logout", "/admin"}})

	if s.InScope("https://example.com/admin/settings") {
		t.Fatalf("expected excluded path to be out of scope")
	}
	if !s.InScope("https://example.com/dashboard") {
		t.Fatalf("expected non-excluded path to remain in scope")
	}
}

func TestServerScopeGetSetRoundTrip(t *testing.T) {
	s := NewServer(nil)
	rules := model.ScanScope{IncludeHosts: []string{"example.com"}, ExcludePaths: []string{"/logout"}}
	s.SetScope(rules)

	got := s.Scope()
	if len(got.IncludeHosts) != 1 || got.IncludeHosts[0] != "example.com" {
		t.Fatalf("expected IncludeHosts to round-trip, got %+v", got)
	}
	if len(got.ExcludePaths) != 1 || got.ExcludePaths[0] != "/logout" {
		t.Fatalf("expected ExcludePaths to round-trip, got %+v", got)
	}
}
