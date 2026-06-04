package proofpolicy

import (
	"strings"

	"auto-bughunter/backend/internal/model"
)

type Result struct {
	Category  string
	Required  []string
	Satisfied []string
	Missing   []string
	Coverage  float64
}

type requirement struct {
	name string
	hit  func(blob string, finding model.Finding) bool
}

var rulesByCategory = map[string][]requirement{
	"xss": {
		{name: "payload_or_script_context", hit: func(blob string, f model.Finding) bool {
			return strings.TrimSpace(f.PoC) != "" || hasAny(blob, "xss", "script", "onerror", "alert(", "javascript:")
		}},
		{name: "reflection_or_execution_signal", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "reflected", "unsanitized", "unescaped", "executed", "payload appears", "dom xss")
		}},
		{name: "affected_location", hit: func(blob string, f model.Finding) bool {
			return strings.TrimSpace(f.AffectedURL) != "" || strings.TrimSpace(f.AffectedParameter) != "" || hasAny(blob, "param", "query", "path", "endpoint")
		}},
	},
	"sqli": {
		{name: "sql_injection_payload_or_error", hit: func(blob string, f model.Finding) bool {
			return strings.TrimSpace(f.PoC) != "" || hasAny(blob, "sql injection", "sql syntax", "mysql", "postgres", "sqlite", "sqlstate", "ora-", "union select", "or 1=1")
		}},
		{name: "input_vector", hit: func(blob string, f model.Finding) bool {
			return strings.TrimSpace(f.AffectedParameter) != "" || hasAny(blob, "parameter", "id=", "query param", "request body")
		}},
		{name: "database_response_or_effect", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "database error", "stack trace", "time-based", "boolean-based", "delay", "row", "sql error")
		}},
	},
	"idor": {
		{name: "object_reference_surface", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "idor", "object id", "resource id", "user id", "account id", "tenant id", "/users/", "/accounts/")
		}},
		{name: "authorization_bypass_signal", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "unauthorized", "forbidden bypass", "cross-tenant", "horizontal privilege", "vertical privilege", "broken access")
		}},
		{name: "cross_subject_data_or_action", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "other user", "another account", "different tenant", "foreign record", "sensitive data")
		}},
	},
	"headers": {
		{name: "header_name", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")
		}},
		{name: "misconfiguration_signal", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "missing", "absent", "weak", "misconfigured", "not set", "permissive")
		}},
		{name: "response_scope", hit: func(blob string, f model.Finding) bool {
			return strings.TrimSpace(f.AffectedURL) != "" || hasAny(blob, "response header", "all responses", "endpoint", "route")
		}},
	},
	"wordlist": {
		{name: "discovered_path", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "wordlist", "discovered", "enumerated", "directory", "endpoint", "path")
		}},
		{name: "http_signal", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "status", "200", "401", "403", "302", "content length", "response size")
		}},
		{name: "interesting_exposure", hit: func(blob string, _ model.Finding) bool {
			return hasAny(blob, "admin", "debug", "backup", ".git", ".env", "swagger", "openapi", "config")
		}},
	},
}

func EvaluateFinding(f model.Finding) Result {
	category := canonicalCategory(f.Category)
	reqs := rulesByCategory[category]
	if len(reqs) == 0 {
		return Result{}
	}

	result := Result{
		Category: category,
		Required: make([]string, 0, len(reqs)),
	}
	blob := evidenceBlob(f)

	for _, req := range reqs {
		result.Required = append(result.Required, req.name)
		if req.hit(blob, f) {
			result.Satisfied = append(result.Satisfied, req.name)
		} else {
			result.Missing = append(result.Missing, req.name)
		}
	}
	if len(result.Required) > 0 {
		result.Coverage = float64(len(result.Satisfied)) / float64(len(result.Required))
	}
	return result
}

func canonicalCategory(category string) string {
	cat := strings.TrimSpace(strings.ToLower(category))
	switch cat {
	case "xss", "dom_xss", "reflected_xss", "stored_xss":
		return "xss"
	case "sqli", "sql_injection":
		return "sqli"
	case "idor", "broken_access_control", "access_control":
		return "idor"
	case "headers", "security_headers":
		return "headers"
	case "wordlist", "wordlist_discovery", "content_discovery":
		return "wordlist"
	default:
		return ""
	}
}

func evidenceBlob(f model.Finding) string {
	parts := []string{
		f.Title,
		f.Description,
		f.Evidence,
		f.Recommendation,
		f.AffectedURL,
		f.AffectedParameter,
		f.CWE,
		f.PoC,
	}
	parts = append(parts, f.ReproductionSteps...)
	for _, artifact := range f.ProofArtifacts {
		parts = append(parts, artifact.Type, artifact.Label, artifact.Description, artifact.Value)
	}
	for k, v := range f.EvidenceFields {
		parts = append(parts, k, v)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func hasAny(text string, tokens ...string) bool {
	for _, token := range tokens {
		if strings.Contains(text, strings.ToLower(token)) {
			return true
		}
	}
	return false
}
