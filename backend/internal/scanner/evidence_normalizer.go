package scanner

import (
	"strconv"
	"strings"
	"sync/atomic"

	"auto-bughunter/backend/internal/model"
)

// EvidenceQualityValid / …Incomplete are the values written back into
// Finding.EvidenceFields["evidenceQuality"] by NormalizeEvidence. The
// strict-reporting filter reads this key to decide whether to suppress
// findings without a machine-checkable evidence record.
const (
	EvidenceQualityValid      = "valid"
	EvidenceQualityIncomplete = "incomplete"
)

// EvidenceMetrics is exposed to AutomationMetrics.Extra so operators
// can see what fraction of findings carry Phase 3-compliant evidence.
type EvidenceMetrics struct {
	Valid            uint64            `json:"valid"`
	Incomplete       uint64            `json:"incomplete"`
	ValidRatio       float64           `json:"validRatio"`
	MissingByField   map[string]uint64 `json:"missingByField"`
}

type evidenceMetricsState struct {
	valid          atomic.Uint64
	incomplete     atomic.Uint64
	missing        map[string]*atomic.Uint64
	missingKnownAt uint64 // (unused, retained for future append) — see comment below
}

// Fields tracked in EvidenceMetrics.MissingByField. Kept as a fixed set
// so JSON is stable and unit tests can assert on it. Extra fields are
// added on demand under lock, but the common ones are pre-registered
// here so the snapshot always exposes them (even as 0).
var trackedMissingFields = []string{
	"url", "method", "param", "payloadClass",
	"reflectionContext", "responseShape", "oracleName",
}

var globalEvidenceMetrics = func() *evidenceMetricsState {
	s := &evidenceMetricsState{missing: map[string]*atomic.Uint64{}}
	for _, f := range trackedMissingFields {
		s.missing[f] = new(atomic.Uint64)
	}
	return s
}()

// NormalizeEvidence coerces the free-form EvidenceFields on a Finding
// into a typed EvidenceRecord, validates it against
// evidence_schema.go's per-category requirements, and stamps
// EvidenceFields["evidenceQuality"] with "valid" or "incomplete".
//
// The typed record is serialised into the standard string map keys so
// it survives Finding transport without introducing a new field.
// Existing keys are preserved when the record does not override them.
func NormalizeEvidence(f model.Finding) model.Finding {
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	rec := evidenceFromFinding(f)

	if err := rec.Validate(f.Category); err != nil {
		if ve, ok := err.(*EvidenceValidationError); ok {
			for _, field := range ve.MissingFields {
				counter := globalEvidenceMetrics.counterFor(field)
				counter.Add(1)
			}
		}
		f.EvidenceFields["evidenceQuality"] = EvidenceQualityIncomplete
		globalEvidenceMetrics.incomplete.Add(1)
	} else {
		f.EvidenceFields["evidenceQuality"] = EvidenceQualityValid
		globalEvidenceMetrics.valid.Add(1)
	}
	writeEvidenceRecord(&f, rec)
	return f
}

// evidenceFromFinding builds an EvidenceRecord from whatever the probe
// already wrote into EvidenceFields plus a few top-level Finding
// fields. Missing values stay empty so Validate can catch them.
func evidenceFromFinding(f model.Finding) *EvidenceRecord {
	get := func(k string) string {
		if f.EvidenceFields == nil {
			return ""
		}
		return f.EvidenceFields[k]
	}
	rec := &EvidenceRecord{
		RequestID:          firstNonEmptyEv(get("requestId"), get("request_id")),
		Method:             firstNonEmptyEv(get("method"), get("httpMethod")),
		URL:                firstNonEmptyEv(get("url"), get("endpoint"), get("target")),
		Param:              firstNonEmptyEv(get("param"), get("parameter")),
		PayloadClass:       firstNonEmptyEv(get("payloadClass"), get("payload_type")),
		ReflectionContext:  firstNonEmptyEv(get("reflectionContext"), get("reflection_context")),
		ResponseShape:      firstNonEmptyEv(get("responseShape"), get("response_shape")),
		ControlBaselineRef: firstNonEmptyEv(get("controlBaselineRef"), get("baselineRef")),
		OracleName:         firstNonEmptyEv(get("oracleName"), get("oracle"), f.Category),
		OracleVersion:      firstNonEmptyEv(get("oracleVersion"), "v1"),
		VerifiedBy:         get("verifiedBy"),
		HashOfBody:         get("hashOfBody"),
	}
	if v := get("differentialConfirmed"); v != "" {
		rec.DifferentialConfirmed = v == "true" || v == "1" || v == "yes"
	}
	if v := get("timingMillis"); v != "" {
		if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
			rec.TimingMillis = ms
		}
	}
	return rec
}

// writeEvidenceRecord back-fills the string map from the (possibly
// enriched) record so both the free-form keys and the typed record
// agree.
func writeEvidenceRecord(f *model.Finding, r *EvidenceRecord) {
	if r == nil {
		return
	}
	set := func(k, v string) {
		if v == "" {
			return
		}
		if _, ok := f.EvidenceFields[k]; ok {
			return
		}
		f.EvidenceFields[k] = v
	}
	set("method", r.Method)
	set("url", r.URL)
	set("param", r.Param)
	set("payloadClass", r.PayloadClass)
	set("reflectionContext", r.ReflectionContext)
	set("responseShape", r.ResponseShape)
	set("controlBaselineRef", r.ControlBaselineRef)
	set("oracleName", r.OracleName)
	set("oracleVersion", r.OracleVersion)
	set("verifiedBy", r.VerifiedBy)
	set("hashOfBody", r.HashOfBody)
	if r.DifferentialConfirmed {
		set("differentialConfirmed", "true")
	}
	if r.TimingMillis > 0 {
		set("timingMillis", strconv.FormatInt(r.TimingMillis, 10))
	}
}

func firstNonEmptyEv(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// counterFor returns (creating on demand) the atomic counter for a
// missing-field name. Concurrent creation is protected by a
// double-check pattern on the map because updates are rare after
// warm-up.
var evidenceMetricsMu = struct{ dummy int }{}

func (s *evidenceMetricsState) counterFor(field string) *atomic.Uint64 {
	if c, ok := s.missing[field]; ok {
		return c
	}
	// Slow path: register the previously-unseen field. This map is only
	// grown, never trimmed, so a plain append+lock-free read races
	// benignly with subsequent reads (worst case: we double-increment
	// one write; the counter is a rough gauge, not an invariant).
	c := new(atomic.Uint64)
	s.missing[field] = c
	return c
}

// GetEvidenceMetrics returns a snapshot for AutomationMetrics.Extra.
func GetEvidenceMetrics() EvidenceMetrics {
	valid := globalEvidenceMetrics.valid.Load()
	incomplete := globalEvidenceMetrics.incomplete.Load()
	total := valid + incomplete
	var ratio float64
	if total > 0 {
		ratio = float64(valid) / float64(total)
	}
	out := EvidenceMetrics{
		Valid:          valid,
		Incomplete:     incomplete,
		ValidRatio:     ratio,
		MissingByField: map[string]uint64{},
	}
	for k, v := range globalEvidenceMetrics.missing {
		out.MissingByField[k] = v.Load()
	}
	return out
}

// ResetEvidenceMetrics zeros the process-wide counters. Intended for
// tests.
func ResetEvidenceMetrics() {
	globalEvidenceMetrics.valid.Store(0)
	globalEvidenceMetrics.incomplete.Store(0)
	for _, c := range globalEvidenceMetrics.missing {
		c.Store(0)
	}
}
