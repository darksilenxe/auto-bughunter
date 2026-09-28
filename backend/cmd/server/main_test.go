package main

import "testing"

func TestResolveAIConfigFromEnv_DefaultAIConfig(t *testing.T) {
	t.Setenv("USE_STRIX_SERVICE", "false")
	t.Setenv("USE_STRIX_DECISIONS_ONLY", "false")
	t.Setenv("AI_API_BASE", "https://api.openai.example/v1")
	t.Setenv("AI_API_KEY", "openai-key")
	t.Setenv("AI_MODEL", "gpt-test")
	t.Setenv("AI_CODING_API_BASE", "https://planner.example/v1")
	t.Setenv("AI_CODING_API_KEY", "planner-key")
	t.Setenv("AI_CODING_MODEL", "planner-model")
	t.Setenv("AI_FAST_API_BASE", "https://fast.example/v1")
	t.Setenv("AI_FAST_API_KEY", "fast-key")
	t.Setenv("AI_FAST_MODEL", "fast-model")

	cfg := resolveAIConfigFromEnv()

	if cfg.BaseURL != "https://api.openai.example/v1" || cfg.APIKey != "openai-key" || cfg.Model != "gpt-test" {
		t.Fatalf("primary config = %+v", cfg)
	}
	if cfg.CodingBaseURL != "https://planner.example/v1" || cfg.CodingAPIKey != "planner-key" || cfg.CodingModel != "planner-model" {
		t.Fatalf("coding config = %+v", cfg)
	}
	if cfg.FastBaseURL != "https://fast.example/v1" || cfg.FastAPIKey != "fast-key" || cfg.FastModel != "fast-model" {
		t.Fatalf("fast config = %+v", cfg)
	}
}

func TestResolveAIConfigFromEnv_StrixOverrides(t *testing.T) {
	t.Setenv("USE_STRIX_SERVICE", "true")
	t.Setenv("USE_STRIX_DECISIONS_ONLY", "false")
	t.Setenv("AI_API_BASE", "https://api.openai.example/v1")
	t.Setenv("AI_API_KEY", "openai-key")
	t.Setenv("AI_MODEL", "gpt-test")
	t.Setenv("STRIX_API_BASE", "https://strix.example/v1")
	t.Setenv("STRIX_API_KEY", "strix-key")
	t.Setenv("STRIX_MODEL", "strix-main")
	t.Setenv("STRIX_CODING_MODEL", "strix-planner")
	t.Setenv("STRIX_FAST_API_BASE", "https://strix-fast.example/v1")
	t.Setenv("STRIX_FAST_API_KEY", "strix-fast-key")
	t.Setenv("STRIX_FAST_MODEL", "strix-fast")

	cfg := resolveAIConfigFromEnv()

	if cfg.BaseURL != "https://strix.example/v1" || cfg.APIKey != "strix-key" || cfg.Model != "strix-main" {
		t.Fatalf("primary config = %+v", cfg)
	}
	if cfg.CodingBaseURL != "https://strix.example/v1" || cfg.CodingAPIKey != "strix-key" || cfg.CodingModel != "strix-planner" {
		t.Fatalf("coding config = %+v", cfg)
	}
	if cfg.FastBaseURL != "https://strix-fast.example/v1" || cfg.FastAPIKey != "strix-fast-key" || cfg.FastModel != "strix-fast" {
		t.Fatalf("fast config = %+v", cfg)
	}
}

func TestResolveAIConfigFromEnv_StrixPrimaryFallbacksForOtherLanes(t *testing.T) {
	t.Setenv("USE_STRIX_SERVICE", "true")
	t.Setenv("USE_STRIX_DECISIONS_ONLY", "false")
	t.Setenv("AI_API_BASE", "https://api.openai.example/v1")
	t.Setenv("AI_API_KEY", "openai-key")
	t.Setenv("AI_MODEL", "gpt-test")
	t.Setenv("AI_CODING_MODEL", "planner-model")
	t.Setenv("AI_FAST_MODEL", "fast-model")
	t.Setenv("STRIX_API_BASE", "https://strix.example/v1")
	t.Setenv("STRIX_API_KEY", "strix-key")
	t.Setenv("STRIX_MODEL", "strix-main")

	cfg := resolveAIConfigFromEnv()

	if cfg.CodingBaseURL != "https://strix.example/v1" || cfg.CodingAPIKey != "strix-key" || cfg.CodingModel != "strix-main" {
		t.Fatalf("coding fallback = %+v", cfg)
	}
	if cfg.FastBaseURL != "https://strix.example/v1" || cfg.FastAPIKey != "strix-key" || cfg.FastModel != "strix-main" {
		t.Fatalf("fast fallback = %+v", cfg)
	}
}

func TestResolveAIConfigFromEnv_StrixDecisionsOnlyLeavesPrimaryOnAIConfig(t *testing.T) {
	t.Setenv("USE_STRIX_SERVICE", "false")
	t.Setenv("USE_STRIX_DECISIONS_ONLY", "true")
	t.Setenv("AI_API_BASE", "https://api.openai.example/v1")
	t.Setenv("AI_API_KEY", "openai-key")
	t.Setenv("AI_MODEL", "gpt-test")
	t.Setenv("STRIX_API_BASE", "https://strix.example/v1")
	t.Setenv("STRIX_API_KEY", "strix-key")
	t.Setenv("STRIX_MODEL", "strix-main")

	cfg := resolveAIConfigFromEnv()

	if cfg.BaseURL != "https://api.openai.example/v1" || cfg.APIKey != "openai-key" || cfg.Model != "gpt-test" {
		t.Fatalf("primary config = %+v", cfg)
	}
	if cfg.CodingBaseURL != "https://strix.example/v1" || cfg.CodingAPIKey != "strix-key" || cfg.CodingModel != "strix-main" {
		t.Fatalf("coding config = %+v", cfg)
	}
	if cfg.FastBaseURL != "https://strix.example/v1" || cfg.FastAPIKey != "strix-key" || cfg.FastModel != "strix-main" {
		t.Fatalf("fast config = %+v", cfg)
	}
}

func TestResolveAIConfigFromEnv_StrixServiceWinsOverDecisionsOnly(t *testing.T) {
	t.Setenv("USE_STRIX_SERVICE", "true")
	t.Setenv("USE_STRIX_DECISIONS_ONLY", "true")
	t.Setenv("AI_API_BASE", "https://api.openai.example/v1")
	t.Setenv("AI_API_KEY", "openai-key")
	t.Setenv("AI_MODEL", "gpt-test")
	t.Setenv("STRIX_API_BASE", "https://strix.example/v1")
	t.Setenv("STRIX_API_KEY", "strix-key")
	t.Setenv("STRIX_MODEL", "strix-main")

	cfg := resolveAIConfigFromEnv()

	if cfg.BaseURL != "https://strix.example/v1" || cfg.APIKey != "strix-key" || cfg.Model != "strix-main" {
		t.Fatalf("primary config = %+v", cfg)
	}
}

func TestResolveAIConfigFromEnv_StrixDecisionsOnlyIgnoresLaneModelOnlyOverridesWithoutEndpoint(t *testing.T) {
	t.Setenv("USE_STRIX_SERVICE", "false")
	t.Setenv("USE_STRIX_DECISIONS_ONLY", "true")
	t.Setenv("AI_API_BASE", "https://api.openai.example/v1")
	t.Setenv("AI_API_KEY", "openai-key")
	t.Setenv("AI_MODEL", "gpt-test")
	t.Setenv("AI_CODING_API_BASE", "https://planner.example/v1")
	t.Setenv("AI_CODING_API_KEY", "planner-key")
	t.Setenv("AI_CODING_MODEL", "planner-model")
	t.Setenv("AI_FAST_API_BASE", "https://fast.example/v1")
	t.Setenv("AI_FAST_API_KEY", "fast-key")
	t.Setenv("AI_FAST_MODEL", "fast-model")
	t.Setenv("STRIX_CODING_MODEL", "strix-planner")
	t.Setenv("STRIX_FAST_MODEL", "strix-fast")

	cfg := resolveAIConfigFromEnv()

	if cfg.CodingBaseURL != "https://planner.example/v1" || cfg.CodingAPIKey != "planner-key" || cfg.CodingModel != "planner-model" {
		t.Fatalf("coding config = %+v", cfg)
	}
	if cfg.FastBaseURL != "https://fast.example/v1" || cfg.FastAPIKey != "fast-key" || cfg.FastModel != "fast-model" {
		t.Fatalf("fast config = %+v", cfg)
	}
}
