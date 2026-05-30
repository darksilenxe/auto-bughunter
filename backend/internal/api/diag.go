package api

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// diagEnvVars lists the environment variables included in the diagnostic
// bundle. Values that match sensitiveEnvPatterns are redacted so the bundle
// is safe to share in bug reports.
var diagEnvVars = []string{
	"AI_API_BASE",
	"AI_CODING_API_BASE",
	"AI_FAST_API_BASE",
	"AI_MODEL",
	"AI_CODING_MODEL",
	"AI_FAST_MODEL",
	"AI_MAX_CONCURRENT_REQUESTS",
	"AI_MAX_CONCURRENT_REQUESTS_PRIMARY",
	"AI_MAX_CONCURRENT_REQUESTS_CODING",
	"AI_MAX_CONCURRENT_REQUESTS_FAST",
	"AI_REQUEST_TIMEOUT_SECONDS",
	"AGENT_LEARNER_URL",
	"ASNMAP_BINARY",
	"CHROME_REMOTE_URL",
	"CLOUDLIST_BINARY",
	"CORS_ALLOWED_ORIGINS",
	"DATABASE_URL",
	"DEFAULT_BACKOFF_MILLIS",
	"DEFAULT_MAX_RETRIES",
	"DNSX_BINARY",
	"ENABLE_AUTONOMOUS_ORCHESTRATION",
	"ENABLE_KITERUNNER_INTEGRATION",
	"ENABLE_KITERUNNER_WORDLISTS",
	"ENABLE_NIKTO_INTEGRATION",
	"ENABLE_OAST",
	"ENABLE_PROXY",
	"ENABLE_SECLISTS_WORDLISTS",
	"ENABLE_VECTOR_MEMORY",
	"ENABLE_WPSCAN_INTEGRATION",
	"FFUF_BINARY",
	"GLOBAL_SCAN_BUDGET",
	"GOBUSTER_BINARY",
	"HTTPX_BINARY",
	"INTEGRATION_TIMEOUT_SECONDS",
	"KATANA_BINARY",
	"KITERUNNER_BINARY",
	"KNOWLEDGE_SERVICE_URL",
	"MAX_CONCURRENT_SCANS_PER_TARGET",
	"MAX_ORCHESTRATION_ROUNDS",
	"ML_MODEL_PATH",
	"ML_SCORING_MODE",
	"MSF_RPC_URL",
	"NAABU_BINARY",
	"NEO4J_DATABASE",
	"NEO4J_URI",
	"NUCLEI_BINARY",
	"NUCLEI_SERVICE_URL",
	"OAST_LISTEN_PORT",
	"OAST_MAX_BODY_BYTES",
	"OAST_PUBLIC_BASE_URL",
	"OLLAMA_MODEL",
	"OLLAMA_SECONDARY_MODEL",
	"OLLAMA_FAST_MODEL",
	"PROXY_PORT",
	"PROXY_PUBLIC_HOST",
	"PROXY_RETENTION_HOURS",
	"SCAN_TIMEOUT_SECONDS",
	"SECLISTS_DIR",
	"SIDECAR_EXEC_DISABLE",
	"SHARED_TMP_DIR",
	"SHUFFLEDNS_BINARY",
	"SUBFINDER_BINARY",
	"TLSX_BINARY",
	"TOOL_UPDATES_REPORT_PATH",
	"USE_HTTP_TOOL_SERVICES",
	"VITE_API_BASE",
	"WORDLIST_PROFILE",
	"XSSMAP_BINARY",
	"XSSMAP_MAX_PAYLOADS",
	"XSSMAP_MODEL",
	"XSSMAP_OLLAMA_URL",
	"XSSMAP_TIMEOUT_SECONDS",
	"ZAP_BASELINE_BINARY",
}

// sensitiveEnvPatterns lists substrings (case-insensitive) that cause a value
// to be redacted in the diagnostic bundle.
var sensitiveEnvPatterns = []string{
	"key", "password", "secret", "token", "credential", "pass",
}

// sensitiveEnvNames lists exact environment variable names whose values must
// always be redacted regardless of name-pattern matching.  These are variables
// that carry connection strings or URIs that may embed credentials.
var sensitiveEnvNames = map[string]struct{}{
	"DATABASE_URL": {},
	"NEO4J_URI":    {},
}

func redactEnvValue(name, value string) string {
	if _, ok := sensitiveEnvNames[name]; ok {
		if value == "" {
			return ""
		}
		return "[REDACTED]"
	}
	lower := strings.ToLower(name)
	for _, pattern := range sensitiveEnvPatterns {
		if strings.Contains(lower, pattern) {
			if value == "" {
				return ""
			}
			return "[REDACTED]"
		}
	}
	return value
}

// diagRuntimeInfo collects lightweight Go runtime metrics.
type diagRuntimeInfo struct {
	GoVersion    string `json:"goVersion"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	NumCPU       int    `json:"numCPU"`
	NumGoroutine int    `json:"numGoroutine"`
	HeapAllocMB  string `json:"heapAllocMB"`
	HeapSysMB    string `json:"heapSysMB"`
}

func collectRuntimeInfo() diagRuntimeInfo {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return diagRuntimeInfo{
		GoVersion:    runtime.Version(),
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		HeapAllocMB:  fmt.Sprintf("%.2f", float64(mem.HeapAlloc)/1024/1024),
		HeapSysMB:    fmt.Sprintf("%.2f", float64(mem.HeapSys)/1024/1024),
	}
}

// handleDiagLogs assembles a JSON troubleshooting bundle suitable for
// attaching to bug reports. All sensitive env-var values are redacted before
// the bundle leaves the process.
func (s *Server) handleDiagLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Collect environment variables (redacting sensitive values).
	envMap := make(map[string]string, len(diagEnvVars))
	for _, name := range diagEnvVars {
		val := os.Getenv(name)
		envMap[name] = redactEnvValue(name, val)
	}

	// Collect recent scan summaries (no findings — IDs + status only).
	type scanDigest struct {
		ID           string `json:"id"`
		Target       string `json:"target"`
		Status       string `json:"status"`
		StartedAt    string `json:"startedAt"`
		CompletedAt  string `json:"completedAt,omitempty"`
		FindingCount int    `json:"findingCount"`
	}
	recentScans := []scanDigest{}
	var recentScansError string
	if jobs, err := s.repo.ListCompletedJobs(r.Context(), 10); err != nil {
		recentScansError = "failed to list recent scans: " + err.Error()
	} else {
		for _, j := range jobs {
			d := scanDigest{
				ID:           j.ID,
				Target:       j.Target,
				Status:       j.Status,
				StartedAt:    j.StartedAt.UTC().Format(time.RFC3339),
				FindingCount: len(j.Findings),
			}
			if j.CompletedAt != nil {
				d.CompletedAt = j.CompletedAt.UTC().Format(time.RFC3339)
			}
			recentScans = append(recentScans, d)
		}
	}

	// Collect tool health.
	tools := collectToolHealth()
	// Sort by name for deterministic output.
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	bundle := map[string]any{
		"generatedAt":      time.Now().UTC().Format(time.RFC3339),
		"runtime":          collectRuntimeInfo(),
		"environment":      envMap,
		"toolsHealth":      tools,
		"recentScans":      recentScans,
		"recentScansError": recentScansError,
	}

	writeJSON(w, http.StatusOK, bundle)
}
