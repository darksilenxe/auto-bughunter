package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestSeedRuntimeEndpointsFromSessionMergesDiscoveredURLs(t *testing.T) {
	session := NewScanSession()
	session.AddDiscoveredEndpoint(DiscoveredEndpoint{URL: "https://example.com/api/users", Method: "GET"})
	session.AddDiscoveredEndpoint(DiscoveredEndpoint{URL: "https://example.com/api/orders", Method: "POST"})
	session.AddDiscoveredEndpoint(DiscoveredEndpoint{URL: "https://example.com/api/orders", Method: "GET"})

	input := RunInput{
		Session: session,
		Options: model.ScanOptions{
			SeedRuntimeEndpoints: []string{"https://example.com/api/users"},
		},
	}

	seedRuntimeEndpointsFromSession(&input)

	got := map[string]bool{}
	for _, endpoint := range input.Options.SeedRuntimeEndpoints {
		got[endpoint] = true
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 unique seeded endpoints, got %d (%v)", len(got), input.Options.SeedRuntimeEndpoints)
	}
	for _, want := range []string{
		"https://example.com/api/users",
		"https://example.com/api/orders",
	} {
		if !got[want] {
			t.Fatalf("expected seeded endpoint %s, got %v", want, input.Options.SeedRuntimeEndpoints)
		}
	}
}
