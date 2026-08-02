package ai

import (
	"context"
	"encoding/json"
	"strings"

	"auto-bughunter/backend/internal/model"
)

const fpClassificationSchema = `{"isFalsePositive":boolean,"confidence":number,"correctionHint":string}`

const fpClassificationSystemPrompt = `You are a security-finding quality-control specialist embedded in an automated vulnerability scanner. Your job is to decide whether a candidate finding is a false positive, given the probe's recent error rate and the finding's evidence.

A false positive is a finding that does NOT represent a real, exploitable vulnerability. Common false-positive indicators:
- The "evidence" contains content that the application returns regardless of the payload (e.g., a reflection of normal parameters, baseline template output, server boilerplate).
- The category and evidence are inconsistent (e.g., an XSS finding whose evidence shows no actual HTML execution context).
- The probe's historical false-positive rate is high AND the current evidence is weak.

A true positive should NOT be suppressed when:
- There is strong evidence of exploit execution (OAST hit, DOM execution, SQL error string, timing difference exceeding baseline).
- The evidence is clearly payload-specific (the random canary or arithmetic expression appears unescaped in a dangerous context).
- Multiple independent evidence signals are present.

Respond ONLY with a JSON object matching the outputContract. No prose.`

const fpClassificationReminder = `Output strict JSON matching {"isFalsePositive":boolean,"confidence":number,"correctionHint":string}. confidence must be in [0,1]. correctionHint must be ≤ 150 characters.`

// ClassifyFalsePositive asks the configured AI model whether a candidate
// finding is a false positive, based on the probe's historical FP rate,
// the finding's evidence, and the proof-policy outcome.
//
// It uses the fast model lane to minimise latency and cost; the fast model is
// used because this decision is made inline during the scan's verification
// pipeline for every borderline finding.
//
// Returns a zero-value FPClassification (IsFalsePositive=false) when no AI
// provider is configured or the model's response cannot be parsed, so the
// caller (ProbeCorrection.Evaluate) safely admits the finding.
//
// ClassifyFalsePositive satisfies scanner.FPClassifierClient.
func (c *Client) ClassifyFalsePositive(ctx context.Context, input model.FPClassificationInput) model.FPClassification {
	if c == nil || !c.shouldCallProvider() {
		return model.FPClassification{}
	}

	userPayload := map[string]any{
		"probeName":      input.ProbeName,
		"category":       input.Category,
		"title":          input.Title,
		"evidence":       truncate(input.Evidence, 800),
		"fpRate":         input.FPRate,
		"fpSamples":      input.FPSamples,
		"policyReason":   input.PolicyReason,
		"outputContract": fpClassificationSchema,
	}
	if len(input.Signals) > 0 {
		userPayload["signals"] = input.Signals
	}

	body, err := json.Marshal(userPayload)
	if err != nil {
		return model.FPClassification{}
	}

	messages := []Message{
		{Role: "system", Content: fpClassificationSystemPrompt + " " + fpClassificationReminder},
		{Role: "user", Content: string(body)},
	}

	content, err := c.fastComplete(ctx, messages, 0.1, true)
	if err != nil || strings.TrimSpace(content) == "" {
		return model.FPClassification{}
	}

	var out model.FPClassification
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return model.FPClassification{}
	}

	// Clamp confidence to [0, 1].
	if out.Confidence < 0 {
		out.Confidence = 0
	}
	if out.Confidence > 1 {
		out.Confidence = 1
	}
	// Trim hint to safe length.
	if len(out.CorrectionHint) > 150 {
		out.CorrectionHint = out.CorrectionHint[:150]
	}
	return out
}

// truncate returns at most maxChars characters of s.
func truncate(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	return s[:maxChars]
}
