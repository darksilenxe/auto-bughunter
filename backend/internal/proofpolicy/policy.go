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
// MinCoverage is the minimum Coverage fraction required for the finding's
// category tier. Findings below this threshold have insufficient evidence
// to support their claimed severity.
MinCoverage float64
// BelowMinCoverage is true when Required is non-empty and Coverage < MinCoverage.
BelowMinCoverage bool
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
{name: "database_response_or_effect", hit: func(blob string, f model.Finding) bool {
return hasAny(blob, "database error", "stack trace", "time-based", "boolean-based", "delay", "row", "sql error") ||
strings.TrimSpace(f.EvidenceFields["oobInteraction"]) != "" ||
strings.TrimSpace(f.EvidenceFields["timingDifferentialMs"]) != ""
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
"ssrf": {
{name: "internal_request_target", hit: func(blob string, _ model.Finding) bool {
return hasAny(blob, "169.254", "metadata.internal", "internal service", "localhost", "127.0.0.1",
"ssrf", "server-side request forgery", "server side request forgery", "outbound request")
}},
{name: "response_differential_or_oob_signal", hit: func(blob string, f model.Finding) bool {
return hasAny(blob, "response diff", "oob", "out-of-band", "interactsh", "dns interaction",
"http interaction", "timing", "time differential", "delay", "callback", "outbound") ||
strings.TrimSpace(f.EvidenceFields["oobInteraction"]) != "" ||
strings.TrimSpace(f.EvidenceFields["timingDifferentialMs"]) != ""
}},
{name: "affected_request_parameter", hit: func(blob string, f model.Finding) bool {
return strings.TrimSpace(f.AffectedParameter) != "" || strings.TrimSpace(f.AffectedURL) != "" ||
hasAny(blob, "url parameter", "webhook", "redirect", "fetch", "import", "callback", "param")
}},
},
"ssti": {
{name: "template_execution_signal", hit: func(blob string, _ model.Finding) bool {
return hasAny(blob, "ssti", "template injection", "{{", "${", "49", "7*7",
"expression", "rendered output", "template engine", "server-side template")
}},
{name: "payload_or_poc", hit: func(blob string, f model.Finding) bool {
return strings.TrimSpace(f.PoC) != "" || hasAny(blob, "jinja2", "twig", "freemarker",
"velocity", "smarty", "mako", "erb", "tornado", "pebble", "payload")
}},
{name: "affected_location", hit: func(blob string, f model.Finding) bool {
return strings.TrimSpace(f.AffectedURL) != "" || strings.TrimSpace(f.AffectedParameter) != "" ||
hasAny(blob, "param", "field", "input", "rendered", "context", "endpoint")
}},
},
"xxe": {
{name: "entity_resolution_signal", hit: func(blob string, f model.Finding) bool {
return hasAny(blob, "xxe", "xml external entity", "entity resolution", "oob", "out-of-band",
"dns interaction", "file content", "etc/passwd", "win.ini", "interactsh") ||
strings.TrimSpace(f.EvidenceFields["oobInteraction"]) != ""
}},
{name: "xml_parser_identified", hit: func(blob string, _ model.Finding) bool {
return hasAny(blob, "xml", "doctype", "entity", "dtd", "soap", "xslt", "parser", "libxml", "expat")
}},
{name: "payload_or_affected_location", hit: func(blob string, f model.Finding) bool {
return strings.TrimSpace(f.PoC) != "" || strings.TrimSpace(f.AffectedURL) != "" ||
hasAny(blob, "payload", "endpoint", "parameter", "content-type", "application/xml")
}},
},
"nosqli": {
{name: "nosql_operator_or_filter_bypass", hit: func(blob string, _ model.Finding) bool {
return hasAny(blob, "nosql", "mongodb", "nosql injection", "$where", "$ne", "$gt", "$regex",
"filter bypass", "operator injection", "authentication bypass", "couchdb", "redis injection")
}},
{name: "affected_field_or_collection", hit: func(blob string, f model.Finding) bool {
return strings.TrimSpace(f.AffectedParameter) != "" ||
hasAny(blob, "collection", "field", "document", "query", "filter", "parameter")
}},
{name: "response_or_behavior_signal", hit: func(blob string, _ model.Finding) bool {
return hasAny(blob, "unauthorized access", "data returned", "bypass", "different response",
"all records", "authentication", "login bypass")
}},
},
"path_traversal": {
{name: "traversal_payload_or_sequence", hit: func(blob string, f model.Finding) bool {
return hasAny(blob, "../", `..\\`, "%2e%2e", "%2f", "path traversal", "directory traversal",
"lfi", "local file inclusion") || strings.TrimSpace(f.PoC) != ""
}},
{name: "file_content_or_system_signal", hit: func(blob string, _ model.Finding) bool {
return hasAny(blob, "etc/passwd", "root:", "win.ini", "boot.ini", "system32", "shadow",
"file content", "system file", "/etc/", "c:\\windows")
}},
{name: "affected_parameter_or_path", hit: func(blob string, f model.Finding) bool {
return strings.TrimSpace(f.AffectedParameter) != "" || strings.TrimSpace(f.AffectedURL) != "" ||
hasAny(blob, "filename", "filepath", "path", "file parameter", "include")
}},
},
"open_redirect": {
{name: "redirect_destination_controlled", hit: func(blob string, f model.Finding) bool {
return hasAny(blob, "open redirect", "unvalidated redirect", "redirect destination",
"redirect url", "attacker-controlled") || strings.TrimSpace(f.PoC) != ""
}},
{name: "redirect_mechanism_identified", hit: func(blob string, _ model.Finding) bool {
return hasAny(blob, "location:", "302", "301", "307", "308", "meta refresh",
"javascript redirect", "window.location", "redirect")
}},
{name: "affected_parameter", hit: func(blob string, f model.Finding) bool {
return strings.TrimSpace(f.AffectedParameter) != "" || strings.TrimSpace(f.AffectedURL) != "" ||
hasAny(blob, "url=", "return=", "next=", "redirect=", "callback=", "param")
}},
},
}

// categoryMinCoverage defines the minimum proof-policy coverage fraction
// required before a finding is considered adequately evidenced for its
// claimed severity. Critical/high-value exploit classes require full (1.0)
// coverage; medium-risk classes require 0.66; low/informational classes 0.50.
var categoryMinCoverage = map[string]float64{
"sqli":           1.0,
"ssrf":           1.0,
"xxe":            1.0,
"ssti":           1.0,
"nosqli":         1.0,
"xss":            0.66,
"idor":           0.66,
"path_traversal": 0.66,
"open_redirect":  0.66,
"cors":           0.66,
"headers":        0.50,
"wordlist":       0.50,
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
if min, ok := categoryMinCoverage[category]; ok {
result.MinCoverage = min
result.BelowMinCoverage = result.Coverage < min
}
return result
}

func canonicalCategory(category string) string {
cat := strings.TrimSpace(strings.ToLower(category))
// Normalise space-separated names (e.g. "path traversal" → "path_traversal").
cat = strings.ReplaceAll(cat, " ", "_")
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
case "ssrf", "server_side_request_forgery":
return "ssrf"
case "ssti", "template_injection", "server_side_template_injection":
return "ssti"
case "xxe", "xml_external_entity":
return "xxe"
case "nosqli", "nosql_injection":
return "nosqli"
case "path_traversal", "directory_traversal", "lfi":
return "path_traversal"
case "open_redirect", "unvalidated_redirect":
return "open_redirect"
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
