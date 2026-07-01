package scanner

import (
	"strings"

	"auto-bughunter/backend/internal/model"
)

// CalibrationSignalRecord is the scanner-side view of the Phase 4
// probe-signal payload. It mirrors the fields ml-service accepts on
// /v1/calibrate-probe-signals but stays inside the scanner package so
// it can be built from EvidenceRecord + Finding without importing the
// ml client here (avoiding an import cycle).
//
// backend/internal/ml/service.go declares the wire-level struct
// (probeSignalRecord) whose JSON tags line up with this shape; the
// aggregation layer in api/handlers.go copies one into the other.
type CalibrationSignalRecord struct {
	Category              string
	Outcome               string
	StatusCode            int
	Endpoint              string
	EvidenceValid         bool
	DifferentialConfirmed bool
	SurfaceGapReason      string
	OracleName            string
	OracleVersion         string
}

// PackageCalibrationSignals folds each finding into a
// CalibrationSignalRecord using its normalized EvidenceRecord plus the
// most recent surface-gap detection for context. The returned slice
// stays proportional to len(findings); no aggregation happens here so
// the ml-service can weight per-category priors independently.
func PackageCalibrationSignals(findings []model.Finding) []CalibrationSignalRecord {
	if len(findings) == 0 {
		return nil
	}
	// Snapshot surface metrics once so every record sees the same
	// gap counters, keeping calibration deterministic per scan.
	surface := GetSurfaceCoverageMetrics()
	gapReason := deriveDominantGapReason(surface)

	out := make([]CalibrationSignalRecord, 0, len(findings))
	for _, f := range findings {
		rec := evidenceFromFinding(f)
		valid := f.EvidenceFields != nil && f.EvidenceFields["evidenceQuality"] == EvidenceQualityValid
		out = append(out, CalibrationSignalRecord{
			Category:              strings.ToLower(strings.TrimSpace(f.Category)),
			Outcome:               calibrationOutcomeFor(f),
			StatusCode:            0,
			Endpoint:              rec.URL,
			EvidenceValid:         valid,
			DifferentialConfirmed: rec.DifferentialConfirmed,
			SurfaceGapReason:      gapReason,
			OracleName:            rec.OracleName,
			OracleVersion:         rec.OracleVersion,
		})
	}
	return out
}

// deriveDominantGapReason picks the strongest surface-gap signal to
// carry along with each record. This is a compact way to expose
// per-scan coverage state to the calibrator without extending the
// batch envelope.
func deriveDominantGapReason(m SurfaceCoverageMetrics) string {
	if m.GapUnprobed >= m.GapMethodMissing && m.GapUnprobed >= m.GapParamMissing && m.GapUnprobed > 0 {
		return string(SurfaceGapUnprobed)
	}
	if m.GapMethodMissing >= m.GapParamMissing && m.GapMethodMissing > 0 {
		return string(SurfaceGapMethodNotTested)
	}
	if m.GapParamMissing > 0 {
		return string(SurfaceGapParamNotFuzzed)
	}
	return ""
}

// calibrationOutcomeFor derives a coarse outcome label the calibrator
// can use as its supervision signal. Confirmed / high-confidence
// findings count as positives; low-confidence or verifier-suppressed
// ones as negatives.
func calibrationOutcomeFor(f model.Finding) string {
	if f.EvidenceFields != nil {
		switch strings.ToLower(f.EvidenceFields["preReport.verified"]) {
		case "true":
			return "confirmed"
		case "false":
			return "suppressed"
		}
	}
	if f.Confidence >= 0.85 {
		return "confirmed"
	}
	if f.Confidence <= 0.4 {
		return "suppressed"
	}
	return "candidate"
}
