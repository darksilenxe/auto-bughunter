package proxy

import (
	"fmt"
	"strings"
)

// InterceptPluginAPIVersion is the current host/plugin API contract version.
const InterceptPluginAPIVersion = "v1"

// InterceptPluginManifest declares a plugin's host contract and capability set.
type InterceptPluginManifest struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	APIVersion   string   `json:"apiVersion"`
	Capabilities []string `json:"capabilities,omitempty"`
	Hooks        []string `json:"hooks,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
}

// ValidateInterceptPluginManifest enforces contract compatibility for plugin
// loading and compatibility test harnesses.
func ValidateInterceptPluginManifest(m InterceptPluginManifest) error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("manifest.name is required")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("manifest.version is required")
	}
	if strings.TrimSpace(m.Endpoint) == "" {
		return fmt.Errorf("manifest.endpoint is required")
	}
	if strings.TrimSpace(m.APIVersion) != InterceptPluginAPIVersion {
		return fmt.Errorf("unsupported plugin apiVersion %q (supported: %s)", m.APIVersion, InterceptPluginAPIVersion)
	}
	return nil
}

// ValidateInterceptPluginSet validates a whole plugin set; empty sets are valid
// to preserve baseline no-plugin behavior in compatibility harness runs.
func ValidateInterceptPluginSet(manifests []InterceptPluginManifest) error {
	for _, m := range manifests {
		if err := ValidateInterceptPluginManifest(m); err != nil {
			return err
		}
	}
	return nil
}
