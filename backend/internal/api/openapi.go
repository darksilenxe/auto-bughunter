package api

import (
	"net/http"
)

// handleOpenAPI serves a minimal but accurate OpenAPI 3.1 specification
// describing the public HTTP surface of the backend. The document is
// hand-curated to keep this dependency-free; if a route is added to
// Routes() the corresponding entry should be added here as well.
//
// The spec is intentionally generic about response bodies (it advertises
// `application/json` without enumerating every possible field) so that
// behavioural changes to handlers don't require schema updates. Path
// parameters and request body shapes for POST endpoints are documented
// explicitly because they are the most actionable part for API consumers.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, openAPIDocument())
}

func openAPIDocument() map[string]any {
	jsonResp := func(desc string) map[string]any {
		return map[string]any{
			"description": desc,
			"content": map[string]any{
				"application/json": map[string]any{"schema": map[string]any{"type": "object"}},
			},
		}
	}
	textResp := func(desc, mediaType string) map[string]any {
		return map[string]any{
			"description": desc,
			"content": map[string]any{
				mediaType: map[string]any{"schema": map[string]any{"type": "string"}},
			},
		}
	}
	binaryResp := func(desc, mediaType string) map[string]any {
		return map[string]any{
			"description": desc,
			"content": map[string]any{
				mediaType: map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}},
			},
		}
	}
	pathParam := func(name, desc string) map[string]any {
		return map[string]any{
			"name":        name,
			"in":          "path",
			"required":    true,
			"description": desc,
			"schema":      map[string]any{"type": "string"},
		}
	}
	queryParam := func(name, desc string, required bool) map[string]any {
		return map[string]any{
			"name":        name,
			"in":          "query",
			"required":    required,
			"description": desc,
			"schema":      map[string]any{"type": "string"},
		}
	}
	jsonBody := func(example map[string]any) map[string]any {
		return map[string]any{
			"required": true,
			"content": map[string]any{
				"application/json": map[string]any{
					"schema":  map[string]any{"type": "object"},
					"example": example,
				},
			},
		}
	}

	paths := map[string]any{
		"/api/health": map[string]any{
			"get": map[string]any{
				"summary":     "Liveness probe",
				"description": "Returns 200 if the process is up. Exempt from auth and rate limiting.",
				"tags":        []string{"Health"},
				"security":    []any{},
				"responses":   map[string]any{"200": jsonResp("Service is alive")},
			},
		},
		"/api/ready": map[string]any{
			"get": map[string]any{
				"summary":     "Readiness probe",
				"description": "Returns 200 only when dependent subsystems (database) are reachable. Exempt from auth and rate limiting.",
				"tags":        []string{"Health"},
				"security":    []any{},
				"responses": map[string]any{
					"200": jsonResp("Service is ready"),
					"503": jsonResp("One or more dependencies are unavailable"),
				},
			},
		},
		"/metrics": map[string]any{
			"get": map[string]any{
				"summary":   "Prometheus metrics",
				"tags":      []string{"Health"},
				"security":  []any{},
				"responses": map[string]any{"200": textResp("Prometheus text exposition", "text/plain")},
			},
		},
		"/api/openapi.json": map[string]any{
			"get": map[string]any{
				"summary":   "This OpenAPI document",
				"tags":      []string{"Health"},
				"security":  []any{},
				"responses": map[string]any{"200": jsonResp("OpenAPI 3.1 document")},
			},
		},
		"/api/tools/health": map[string]any{
			"get": map[string]any{
				"summary":   "Scanner toolchain readiness",
				"tags":      []string{"Health"},
				"responses": map[string]any{"200": jsonResp("Tool presence by category")},
			},
		},
		"/api/scan": map[string]any{
			"post": map[string]any{
				"summary": "Create a scan",
				"tags":    []string{"Scans"},
				"requestBody": jsonBody(map[string]any{
					"target":         "https://example.com",
					"idempotencyKey": "scan-example-001",
					"authProfile":    map[string]any{"headers": map[string]string{"Authorization": "Bearer ******"}},
					"options":        map[string]any{},
				}),
				"responses": map[string]any{
					"202": jsonResp("Scan accepted"),
					"400": jsonResp("Invalid target or scan options"),
					"409": jsonResp("Scan already running for target"),
				},
			},
		},
		"/api/scans": map[string]any{
			"get": map[string]any{
				"summary":   "List recent completed scans",
				"tags":      []string{"Scans"},
				"responses": map[string]any{"200": jsonResp("Scan summaries")},
			},
		},
		"/api/scan/{id}": map[string]any{
			"get": map[string]any{
				"summary":    "Get scan job state and findings",
				"tags":       []string{"Scans"},
				"parameters": []any{pathParam("id", "Scan ID")},
				"responses":  map[string]any{"200": jsonResp("Scan job"), "404": jsonResp("Not found")},
			},
		},
		"/api/scan/{id}/events": map[string]any{
			"get": map[string]any{
				"summary":     "Stream scan progress",
				"description": "Server-Sent Events stream of scan progress.",
				"tags":        []string{"Scans"},
				"parameters":  []any{pathParam("id", "Scan ID")},
				"responses":   map[string]any{"200": textResp("SSE event stream", "text/event-stream")},
			},
		},
		"/api/scan/{id}/sarif": map[string]any{
			"get": map[string]any{
				"summary":    "Download findings as SARIF v2.1.0",
				"tags":       []string{"Scans"},
				"parameters": []any{pathParam("id", "Scan ID")},
				"responses":  map[string]any{"200": jsonResp("SARIF v2.1.0 document")},
			},
		},
		"/api/report/{id}": map[string]any{
			"get": map[string]any{
				"summary":    "Download PDF scan report",
				"tags":       []string{"Scans"},
				"parameters": []any{pathParam("id", "Scan ID")},
				"responses":  map[string]any{"200": binaryResp("PDF report", "application/pdf")},
			},
		},
		"/api/proxy/requests": map[string]any{
			"get": map[string]any{
				"summary":   "List captured proxy requests",
				"tags":      []string{"Proxy"},
				"responses": map[string]any{"200": jsonResp("Proxy requests")},
			},
			"delete": map[string]any{
				"summary":   "Clear all captured proxy requests",
				"tags":      []string{"Proxy"},
				"responses": map[string]any{"200": jsonResp("Cleared")},
			},
		},
		"/api/proxy/requests/{id}": map[string]any{
			"get": map[string]any{
				"summary":    "Get a captured proxy request",
				"tags":       []string{"Proxy"},
				"parameters": []any{pathParam("id", "Proxy request ID")},
				"responses":  map[string]any{"200": jsonResp("Proxy request"), "404": jsonResp("Not found")},
			},
		},
		"/api/proxy/replay": map[string]any{
			"post": map[string]any{
				"summary": "Replay a captured proxy request",
				"tags":    []string{"Proxy"},
				"requestBody": jsonBody(map[string]any{
					"method":  "GET",
					"url":     "https://example.com/api/me",
					"headers": map[string]string{},
					"body":    "",
				}),
				"responses": map[string]any{"200": jsonResp("Replay result")},
			},
		},
		"/api/feedback": map[string]any{
			"post": map[string]any{
				"summary": "Record bug-bounty outcome for a finding",
				"tags":    []string{"Feedback & Suppressions"},
				"requestBody": jsonBody(map[string]any{
					"scanId":      "scan-uuid",
					"findingId":   "finding-id",
					"category":    "headers",
					"title":       "Missing security header",
					"programName": "Example Program",
					"outcome":     "accepted",
					"payoutUsd":   150.0,
				}),
				"responses": map[string]any{"202": jsonResp("Recorded")},
			},
		},
		"/api/finding-verification": map[string]any{
			"post": map[string]any{
				"summary": "Submit manual exploitability verification",
				"tags":    []string{"Feedback & Suppressions"},
				"requestBody": jsonBody(map[string]any{
					"scanId":     "scan-uuid",
					"findingId":  "finding-id",
					"status":     "confirmed",
					"verifiedBy": "analyst@example.com",
				}),
				"responses": map[string]any{"202": jsonResp("Recorded")},
			},
		},
		"/api/suppressions": map[string]any{
			"get": map[string]any{
				"summary":    "List active suppression rules",
				"tags":       []string{"Feedback & Suppressions"},
				"parameters": []any{queryParam("target", "Optional target host scope", false)},
				"responses":  map[string]any{"200": jsonResp("Active suppression rules")},
			},
			"post": map[string]any{
				"summary": "Create a baseline / noise-reduction rule",
				"tags":    []string{"Feedback & Suppressions"},
				"requestBody": jsonBody(map[string]any{
					"target":   "example.com",
					"category": "headers",
					"title":    "Missing X-Frame-Options",
					"reason":   "Tracked separately in JIRA-1234",
				}),
				"responses": map[string]any{"202": jsonResp("Recorded")},
			},
		},
		"/api/automation/event": map[string]any{
			"post": map[string]any{
				"summary": "Queue an event-driven scan",
				"tags":    []string{"Automation"},
				"requestBody": jsonBody(map[string]any{
					"eventType": "deploy",
					"target":    "https://example.com",
				}),
				"responses": map[string]any{"202": jsonResp("Queued")},
			},
		},
		"/api/automation/report": map[string]any{
			"get": map[string]any{
				"summary":   "Executive automation report",
				"tags":      []string{"Automation"},
				"responses": map[string]any{"200": jsonResp("Automation report")},
			},
		},
		"/api/automation/tickets": map[string]any{
			"get": map[string]any{
				"summary":    "List open automation tickets",
				"tags":       []string{"Automation"},
				"parameters": []any{queryParam("target", "Optional target host filter", false)},
				"responses":  map[string]any{"200": jsonResp("Automation tickets")},
			},
		},
		"/api/ml/engagements": map[string]any{
			"get": map[string]any{
				"summary":    "Sanitized ML engagement dataset",
				"tags":       []string{"ML"},
				"parameters": []any{queryParam("limit", "Maximum rows", false)},
				"responses":  map[string]any{"200": jsonResp("Engagement dataset")},
			},
		},
		"/api/ml/agent-weights": map[string]any{
			"get": map[string]any{
				"summary":   "Agent learner weights",
				"tags":      []string{"ML"},
				"responses": map[string]any{"200": jsonResp("Agent weights"), "503": jsonResp("Agent learner not configured")},
			},
		},
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "Auto BugHunter API",
			"version":     "1.0.0",
			"description": "Automated security testing pipeline. Endpoints other than /api/health, /api/ready, /metrics and /api/openapi.json require an API token when API_TOKEN is configured.",
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"description":  "Static API token (set server-side via API_TOKEN). Send as `Authorization: Bearer <token>` or `X-API-Token: <token>`.",
					"bearerFormat": "opaque",
				},
			},
		},
		"security": []any{map[string]any{"bearerAuth": []any{}}},
		"paths":    paths,
	}
}
