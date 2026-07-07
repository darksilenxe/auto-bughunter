package scanner

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// EvidenceRecord is the typed, machine-checkable evidence shape emitted
// by Phase 3 probes. Downstream reporting, calibration, and
// cross-tool consensus can read these fields without string-scraping
// EvidenceFields.
//
// The record intentionally mirrors the free-form keys already written
// by Phase 1 probes so evidence_normalizer.go can coerce existing
// findings without loss.
type EvidenceRecord struct {
	RequestID             string            `json:"requestId,omitempty"`
	Method                string            `json:"method,omitempty"`
	URL                   string            `json:"url,omitempty"`
	Param                 string            `json:"param,omitempty"`
	PayloadClass          string            `json:"payloadClass,omitempty"`
	ReflectionContext     string            `json:"reflectionContext,omitempty"`
	ResponseShape         string            `json:"responseShape,omitempty"`
	ControlBaselineRef    string            `json:"controlBaselineRef,omitempty"`
	DifferentialConfirmed bool              `json:"differentialConfirmed,omitempty"`
	OracleName            string            `json:"oracleName,omitempty"`
	OracleVersion         string            `json:"oracleVersion,omitempty"`
	VerifiedBy            string            `json:"verifiedBy,omitempty"`
	TimingMillis          int64             `json:"timingMillis,omitempty"`
	HashOfBody            string            `json:"hashOfBody,omitempty"`
	Extra                 map[string]string `json:"extra,omitempty"`
}

// EvidenceValidationError is returned by Validate when required fields
// for a given category are missing. It intentionally carries the list
// of missing field names so callers can populate
// AutomationMetrics.Extra.evidenceMissingByField.
type EvidenceValidationError struct {
	Category      string
	MissingFields []string
}

func (e *EvidenceValidationError) Error() string {
	return fmt.Sprintf("evidence for %s missing: %s", e.Category, strings.Join(e.MissingFields, ","))
}

// evidenceCategoryRequirements maps a finding category to the set of
// EvidenceRecord fields that must be non-empty for the record to count
// as valid. Categories not listed fall back to the minimum
// "url + method" requirement.
//
// Kept intentionally small — the goal is that a normalized record is
// self-describing enough for downstream consumers, not that every
// probe fill every field.
var evidenceCategoryRequirements = map[string][]string{
	"xss":                 {"url", "param", "payloadClass", "reflectionContext"},
	"sqli":                {"url", "param", "payloadClass"},
	"ssrf":                {"url", "param", "payloadClass"},
	"xpath-injection":     {"url", "param", "payloadClass"},
	"xpath_injection":     {"url", "param", "payloadClass"},
	"open-redirect":       {"url", "param", "payloadClass"},
	"open_redirect":       {"url", "param", "payloadClass"},
	"path-traversal":      {"url", "param", "payloadClass"},
	"path_traversal":      {"url", "param", "payloadClass"},
	"command-injection":   {"url", "param", "payloadClass"},
	"command_injection":   {"url", "param", "payloadClass"},
	"deserialization":     {"url", "param", "payloadClass"},
	"dom-xss":             {"url", "payloadClass", "reflectionContext"},
	"dom_xss":             {"url", "payloadClass", "reflectionContext"},
	"ssti":                {"url", "param", "payloadClass"},
	"xxe":                 {"url", "payloadClass", "responseShape"},
	"cors":                {"url", "responseShape"},
	"clickjacking":        {"url", "responseShape"},
	"csrf":                {"url", "method"},
	"http-methods":        {"url", "method"},
	"http_methods":        {"url", "method"},
	"prototype-pollution": {"url", "param", "payloadClass"},
	"prototype_pollution": {"url", "param", "payloadClass"},
	"crlf":                {"url", "param", "payloadClass"},
	"jwt":                 {"url", "oracleName"},
	"formula-injection":   {"url", "param", "payloadClass"},
	"formula_injection":   {"url", "param", "payloadClass"},
	"dangling-markup":     {"url", "param", "reflectionContext"},
	"dangling_markup":     {"url", "param", "reflectionContext"},
	"upload-bypass":       {"url", "param", "payloadClass"},
	"file-upload":         {"url", "param", "payloadClass"},
	"file_upload":         {"url", "param", "payloadClass"},
}

// Validate returns nil when the record satisfies the category's
// evidence requirements. Missing fields are reported via
// EvidenceValidationError so callers can update metrics.
func (r *EvidenceRecord) Validate(category string) error {
	if r == nil {
		return &EvidenceValidationError{Category: category, MissingFields: []string{"*"}}
	}
	category = strings.ToLower(strings.TrimSpace(category))
	required := evidenceCategoryRequirements[category]
	if len(required) == 0 {
		// Baseline for every category — a record must at least identify
		// the endpoint that produced it and the oracle that observed it.
		required = []string{"url", "method"}
	}
	var missing []string
	for _, f := range required {
		if r.field(f) == "" {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return &EvidenceValidationError{Category: category, MissingFields: missing}
	}
	return nil
}

// field looks up an EvidenceRecord field by lower-case name. Only the
// fields referenced by evidenceCategoryRequirements need to be
// recognised.
func (r *EvidenceRecord) field(name string) string {
	switch strings.ToLower(name) {
	case "requestid":
		return r.RequestID
	case "method":
		return r.Method
	case "url":
		return r.URL
	case "param":
		return r.Param
	case "payloadclass":
		return r.PayloadClass
	case "reflectioncontext":
		return r.ReflectionContext
	case "responseshape":
		return r.ResponseShape
	case "controlbaselineref":
		return r.ControlBaselineRef
	case "oraclename":
		return r.OracleName
	case "oracleversion":
		return r.OracleVersion
	case "verifiedby":
		return r.VerifiedBy
	case "hashofbody":
		return r.HashOfBody
	default:
		if r.Extra != nil {
			return r.Extra[name]
		}
		return ""
	}
}

// HashBody returns a deterministic 20-hex-character digest of body
// content, safe for evidence records without revealing full body
// bytes. Empty input returns "".
func HashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha1.Sum(body)
	return hex.EncodeToString(sum[:])[:20]
}
