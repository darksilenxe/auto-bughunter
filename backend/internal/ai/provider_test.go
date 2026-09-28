package ai

import "testing"

func TestDetectProvider_StrixUsesOpenAICompatibility(t *testing.T) {
	if got := DetectProvider("https://strix.example/v1", ""); got != ProviderOpenAI {
		t.Fatalf("DetectProvider(Strix) = %q, want %q", got, ProviderOpenAI)
	}
}

func TestShouldCallProviderFor_StrixWithoutAPIKey(t *testing.T) {
	if !shouldCallProviderFor("https://strix.example/v1", "") {
		t.Fatal("expected Strix base URL to enable provider calls without requiring an OpenAI API key")
	}
}
