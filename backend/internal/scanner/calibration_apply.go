package scanner

import (
	"strings"
	"sync/atomic"

	"auto-bughunter/backend/internal/model"
)

// CalibrationApplyMetrics is surfaced via
// AutomationMetrics.Extra.calibration* so operators can see how many
// findings the ml-service influenced.
type CalibrationApplyMetrics struct {
	Applied       uint64  `json:"applied"`
	Skipped       uint64  `json:"skipped"`
	Promoted      uint64  `json:"promoted"`
	Demoted       uint64  `json:"demoted"`
	MeanPosterior float64 `json:"meanPosterior"`
}

type calibrationApplyState struct {
	applied  atomic.Uint64
	skipped  atomic.Uint64
	promoted atomic.Uint64
	demoted  atomic.Uint64
	// running mean of posterior confidences applied to findings, kept
	// as a fixed-point sum plus count so we can compute the mean
	// without a lock on read.
	postSum   atomic.Uint64 // stores float64 as microscale integer (mul 1e6)
	postCount atomic.Uint64
}

var globalCalibrationApply = &calibrationApplyState{}

// ApplyCalibratedConfidences overlays per-category posterior confidences
// onto each finding's Confidence and records the transition on
// EvidenceFields (calibrationPrior, calibrationPosterior,
// calibrationVersion). Passing a nil or empty map is a no-op that
// increments the Skipped counter.
//
// The returned slice is the same underlying array as the input; the
// function mutates in place after the copy that Go semantics implies
// for map[string]float64.
func ApplyCalibratedConfidences(findings []model.Finding, posteriors map[string]float64, version string) []model.Finding {
	if len(findings) == 0 {
		return findings
	}
	if len(posteriors) == 0 {
		globalCalibrationApply.skipped.Add(uint64(len(findings)))
		return findings
	}
	if version == "" {
		version = "v1"
	}
	for i := range findings {
		cat := strings.ToLower(strings.TrimSpace(findings[i].Category))
		post, ok := posteriors[cat]
		if !ok {
			globalCalibrationApply.skipped.Add(1)
			continue
		}
		// Clamp so we never emit nonsensical confidences.
		if post < 0 {
			post = 0
		}
		if post > 1 {
			post = 1
		}
		prior := findings[i].Confidence
		if findings[i].EvidenceFields == nil {
			findings[i].EvidenceFields = map[string]string{}
		}
		findings[i].EvidenceFields["calibrationVersion"] = version
		findings[i].EvidenceFields["calibrationPrior"] = formatFloat(prior)
		findings[i].EvidenceFields["calibrationPosterior"] = formatFloat(post)
		findings[i].Confidence = post
		globalCalibrationApply.applied.Add(1)
		if post > prior+0.05 {
			globalCalibrationApply.promoted.Add(1)
		} else if post < prior-0.05 {
			globalCalibrationApply.demoted.Add(1)
		}
		globalCalibrationApply.postSum.Add(uint64(post * 1_000_000))
		globalCalibrationApply.postCount.Add(1)
	}
	return findings
}

// GetCalibrationApplyMetrics returns a snapshot for
// AutomationMetrics.Extra.
func GetCalibrationApplyMetrics() CalibrationApplyMetrics {
	sum := globalCalibrationApply.postSum.Load()
	count := globalCalibrationApply.postCount.Load()
	var mean float64
	if count > 0 {
		mean = float64(sum) / float64(count) / 1_000_000.0
	}
	return CalibrationApplyMetrics{
		Applied:       globalCalibrationApply.applied.Load(),
		Skipped:       globalCalibrationApply.skipped.Load(),
		Promoted:      globalCalibrationApply.promoted.Load(),
		Demoted:       globalCalibrationApply.demoted.Load(),
		MeanPosterior: mean,
	}
}

// ResetCalibrationApplyMetrics clears the counters. Intended for tests.
func ResetCalibrationApplyMetrics() {
	globalCalibrationApply.applied.Store(0)
	globalCalibrationApply.skipped.Store(0)
	globalCalibrationApply.promoted.Store(0)
	globalCalibrationApply.demoted.Store(0)
	globalCalibrationApply.postSum.Store(0)
	globalCalibrationApply.postCount.Store(0)
}

// formatFloat writes a short deterministic representation so the
// EvidenceFields map stays diffable across scans.
func formatFloat(v float64) string {
	// 3 decimals is plenty for a confidence in [0,1].
	return strings.TrimRight(strings.TrimRight(
		trunc3(v), "0"), ".")
}

func trunc3(v float64) string {
	// Manual truncation avoids pulling in strconv formatting quirks
	// around rounding for values very close to a boundary.
	if v < 0 {
		return "0.000"
	}
	if v >= 1 {
		return "1.000"
	}
	scaled := int64(v*1000 + 0.5)
	whole := scaled / 1000
	frac := scaled % 1000
	digits := [3]byte{
		byte('0' + (frac/100)%10),
		byte('0' + (frac/10)%10),
		byte('0' + frac%10),
	}
	return string([]byte{byte('0' + whole), '.', digits[0], digits[1], digits[2]})
}
