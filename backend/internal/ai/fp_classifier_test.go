package ai

import (
	"context"
	"encoding/json"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// fpTestProvider is a fake Provider that returns a fixed response string.
type fpTestProvider struct {
	response string
	err      error
}

func (p *fpTestProvider) Complete(_ context.Context, _ string, _ []Message, _ float64, _ bool) (string, error) {
	return p.response, p.err
}

func TestClassifyFalsePositive_NilClient(t *testing.T) {
	t.Parallel()
	var c *Client
	result := c.ClassifyFalsePositive(context.Background(), model.FPClassificationInput{
		ProbeName: "xss_probe",
		Category:  "xss",
		FPRate:    0.5,
		FPSamples: 10,
	})
	if result.IsFalsePositive {
		t.Fatal("nil client should return IsFalsePositive=false")
	}
}

func TestClassifyFalsePositive_AIReturnsFP(t *testing.T) {
	t.Parallel()
	aiResp := model.FPClassification{
		IsFalsePositive: true,
		Confidence:      0.88,
		CorrectionHint:  "Reflected content matches baseline without payload",
	}
	body, _ := json.Marshal(aiResp)

	c := &Client{Model: "gpt-test", provider: &fpTestProvider{response: string(body)}}
	result := c.ClassifyFalsePositive(context.Background(), model.FPClassificationInput{
		ProbeName: "active_xss",
		Category:  "xss",
		Title:     "Reflected XSS",
		Evidence:  "payload echoed in body",
		FPRate:    0.55,
		FPSamples: 11,
		Signals:   []string{"reflection"},
	})
	if !result.IsFalsePositive {
		t.Fatal("expected IsFalsePositive=true from AI response")
	}
	if result.Confidence < 0.87 || result.Confidence > 0.89 {
		t.Fatalf("unexpected confidence %v", result.Confidence)
	}
	if result.CorrectionHint == "" {
		t.Fatal("expected CorrectionHint to be set")
	}
}

func TestClassifyFalsePositive_AIReturnsNotFP(t *testing.T) {
	t.Parallel()
	aiResp := model.FPClassification{
		IsFalsePositive: false,
		Confidence:      0.92,
		CorrectionHint:  "Strong sink evidence present",
	}
	body, _ := json.Marshal(aiResp)

	c := &Client{Model: "gpt-test", provider: &fpTestProvider{response: string(body)}}
	result := c.ClassifyFalsePositive(context.Background(), model.FPClassificationInput{
		ProbeName: "active_xss",
		Category:  "xss",
		FPRate:    0.45,
		FPSamples: 9,
	})
	if result.IsFalsePositive {
		t.Fatal("expected IsFalsePositive=false from AI response")
	}
}

func TestClassifyFalsePositive_BadJSON(t *testing.T) {
	t.Parallel()
	c := &Client{Model: "gpt-test", provider: &fpTestProvider{response: "not-json"}}
	result := c.ClassifyFalsePositive(context.Background(), model.FPClassificationInput{
		ProbeName: "xss_probe",
		Category:  "xss",
		FPRate:    0.6,
		FPSamples: 10,
	})
	// Unparseable response → zero value → not FP.
	if result.IsFalsePositive {
		t.Fatal("unparseable response should return IsFalsePositive=false")
	}
}

func TestClassifyFalsePositive_ConfidenceClamp(t *testing.T) {
	t.Parallel()
	aiResp := model.FPClassification{
		IsFalsePositive: true,
		Confidence:      2.5, // out of range
	}
	body, _ := json.Marshal(aiResp)

	c := &Client{Model: "gpt-test", provider: &fpTestProvider{response: string(body)}}
	result := c.ClassifyFalsePositive(context.Background(), model.FPClassificationInput{
		ProbeName: "sqli_probe",
		Category:  "sqli",
		FPRate:    0.5,
		FPSamples: 10,
	})
	if result.Confidence > 1.0 {
		t.Fatalf("confidence should be clamped to 1.0, got %v", result.Confidence)
	}
}
