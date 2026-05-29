package agent

import "testing"

func TestSASTDiscoveredRoutes_DedupesAcrossHistory(t *testing.T) {
	history := []AgentOutput{
		{AgentName: "reconnaissance", Metadata: map[string]string{"discovered_routes": "/ignored"}},
		{AgentName: "js_sast", Metadata: map[string]string{"discovered_routes": "/api/users,/admin"}},
		{AgentName: "js_sast", Metadata: map[string]string{"discovered_routes": "/admin,/api/orders"}},
		{AgentName: "js_sast", Metadata: nil},
	}
	got := sastDiscoveredRoutes(history)
	want := map[string]bool{"/api/users": true, "/admin": true, "/api/orders": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d routes, got %d: %v", len(want), len(got), got)
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("unexpected route %q (only js_sast routes expected)", r)
		}
	}
}

func TestSASTDiscoveredRoutes_EmptyWhenNoSASTHistory(t *testing.T) {
	history := []AgentOutput{
		{AgentName: "reconnaissance", Metadata: map[string]string{"resolved_ips": "1.2.3.4"}},
	}
	if got := sastDiscoveredRoutes(history); len(got) != 0 {
		t.Fatalf("expected no routes, got %v", got)
	}
}
