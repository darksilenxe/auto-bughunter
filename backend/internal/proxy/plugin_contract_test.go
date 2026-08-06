package proxy

import "testing"

func TestValidateInterceptPluginManifest(t *testing.T) {
	err := ValidateInterceptPluginManifest(InterceptPluginManifest{
		Name:       "demo",
		Version:    "1.0.0",
		APIVersion: InterceptPluginAPIVersion,
		Endpoint:   "http://plugin:9000",
	})
	if err != nil {
		t.Fatalf("expected valid manifest, got %v", err)
	}
}

func TestValidateInterceptPluginManifest_VersionMismatch(t *testing.T) {
	err := ValidateInterceptPluginManifest(InterceptPluginManifest{
		Name:       "demo",
		Version:    "1.0.0",
		APIVersion: "v2",
		Endpoint:   "http://plugin:9000",
	})
	if err == nil {
		t.Fatal("expected version mismatch error")
	}
}

func TestValidateInterceptPluginSet_NoPluginBaseline(t *testing.T) {
	if err := ValidateInterceptPluginSet(nil); err != nil {
		t.Fatalf("expected nil set to pass no-plugin baseline, got %v", err)
	}
}
