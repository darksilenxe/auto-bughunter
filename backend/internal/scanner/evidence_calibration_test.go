package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestNormalizeEvidenceValid(t *testing.T) {
	ResetEvidenceMetrics()
	f := model.Finding{
		Category: "xss",
		EvidenceFields: map[string]string{
			"url":               "https://example.com/a?q=1",
			"param":             "q",
			"payloadClass":      "xss-reflected",
			"reflectionContext": "html_body",
			"method":            "GET",
		},
	}
	out := NormalizeEvidence(f)
	if got := out.EvidenceFields["evidenceQuality"]; got != EvidenceQualityValid {
		t.Fatalf("expected valid, got %q", got)
	}
	m := GetEvidenceMetrics()
	if m.Valid != 1 || m.Incomplete != 0 {
		t.Fatalf("metrics = %+v", m)
	}
}

func TestNormalizeEvidenceIncomplete(t *testing.T) {
	ResetEvidenceMetrics()
	f := model.Finding{Category: "sqli", EvidenceFields: map[string]string{"url": "https://x/y"}}
	out := NormalizeEvidence(f)
	if got := out.EvidenceFields["evidenceQuality"]; got != EvidenceQualityIncomplete {
		t.Fatalf("expected incomplete, got %q", got)
	}
	m := GetEvidenceMetrics()
	if m.Incomplete != 1 || m.MissingByField["param"] != 1 || m.MissingByField["payloadClass"] != 1 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
}

func TestApplyCalibratedConfidencesPromoteDemote(t *testing.T) {
	ResetCalibrationApplyMetrics()
	findings := []model.Finding{
		{Category: "sqli", Confidence: 0.5},
		{Category: "xss", Confidence: 0.9},
		{Category: "unknown", Confidence: 0.6},
	}
	posteriors := map[string]float64{"sqli": 0.85, "xss": 0.6}
	out := ApplyCalibratedConfidences(findings, posteriors, "v2")
	if out[0].Confidence != 0.85 || out[1].Confidence != 0.6 || out[2].Confidence != 0.6 {
		t.Fatalf("unexpected confidences: %v %v %v", out[0].Confidence, out[1].Confidence, out[2].Confidence)
	}
	if out[0].EvidenceFields["calibrationVersion"] != "v2" {
		t.Fatalf("expected version stamp")
	}
	m := GetCalibrationApplyMetrics()
	if m.Applied != 2 || m.Promoted != 1 || m.Demoted != 1 || m.Skipped != 1 {
		t.Fatalf("metrics = %+v", m)
	}
	if m.MeanPosterior < 0.72 || m.MeanPosterior > 0.73 {
		t.Fatalf("unexpected mean %v", m.MeanPosterior)
	}
}

func TestApplyCalibratedConfidencesEmpty(t *testing.T) {
	ResetCalibrationApplyMetrics()
	findings := []model.Finding{{Category: "sqli", Confidence: 0.5}}
	ApplyCalibratedConfidences(findings, nil, "")
	m := GetCalibrationApplyMetrics()
	if m.Skipped != 1 || m.Applied != 0 {
		t.Fatalf("expected skip; got %+v", m)
	}
}

func TestPackageCalibrationSignals(t *testing.T) {
	ResetSurfaceCoverageMetrics()
	findings := []model.Finding{
		{
			Category:   "sqli",
			Confidence: 0.9,
			EvidenceFields: map[string]string{
				"url":                    "https://x/a",
				"param":                  "id",
				"payloadClass":           "sqli-error",
				"differentialConfirmed":  "true",
				"evidenceQuality":        EvidenceQualityValid,
				"preReport.verified":     "true",
				"oracleName":             "active_sqli",
			},
		},
	}
	signals := PackageCalibrationSignals(findings)
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	s := signals[0]
	if s.Category != "sqli" || s.Outcome != "confirmed" || !s.DifferentialConfirmed || !s.EvidenceValid {
		t.Fatalf("unexpected signal: %+v", s)
	}
	if s.Endpoint != "https://x/a" || s.OracleName != "active_sqli" {
		t.Fatalf("unexpected endpoint/oracle: %+v", s)
	}
}
