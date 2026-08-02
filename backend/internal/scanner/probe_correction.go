package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
)

// FPClassifierClient is implemented by *ai.Client. It is declared as an
// interface so the scanner package does not depend on the ai package directly.
type FPClassifierClient interface {
	ClassifyFalsePositive(ctx context.Context, input model.FPClassificationInput) model.FPClassification
}

// ProbeCalibratorService is implemented by *ml.Service. It is called once at
// scan end to feed confirmed FP correction records into the ML calibration
// pipeline.
type ProbeCalibratorService interface {
	CalibrateProbeSignals(ctx context.Context, records []model.ProbeRecord)
}

// probeCorrectionCtxKey is the unexported context key for ProbeCorrection.
type probeCorrectionCtxKey struct{}

// WithProbeCorrection returns a copy of ctx with pc attached. Called by
// scanner.Run when UseAIFPCorrection is enabled so every SubmitVerifiedFinding
// call in the scan's probe goroutines can retrieve it.
func WithProbeCorrection(ctx context.Context, pc *ProbeCorrection) context.Context {
	if pc == nil {
		return ctx
	}
	return context.WithValue(ctx, probeCorrectionCtxKey{}, pc)
}

// probeCorrectionFromCtx extracts the ProbeCorrection from ctx. Returns nil
// when none is set (feature off or ctx did not pass through scanner.Run).
func probeCorrectionFromCtx(ctx context.Context) *ProbeCorrection {
	v := ctx.Value(probeCorrectionCtxKey{})
	if v == nil {
		return nil
	}
	pc, _ := v.(*ProbeCorrection)
	return pc
}

// ProbeCorrection bundles the per-scan FP signal store, rate estimator, and
// optional AI classifier into a single object. It is created by scanner.Run
// (when ScanOptions.UseAIFPCorrection is true) and injected into the request
// context via WithProbeCorrection so every call to SubmitVerifiedFinding can
// apply FP correction to candidate findings.
//
// ProbeCorrection is nil-safe: all methods are no-ops on a nil receiver.
type ProbeCorrection struct {
	store     *FPSignalStore
	estimator *FPRateEstimator
	// classify is the optional AI classifier. When nil, only the rule-based
	// estimator is used; borderline findings are admitted without an AI call.
	classify FPClassifierClient

	mu               sync.Mutex
	correctedRecords []model.ProbeRecord
}

// NewProbeCorrection creates a ProbeCorrection with a fresh FPSignalStore and
// estimator. classify may be nil; when nil, only the rule-based rate estimator
// is used (no AI calls).
func NewProbeCorrection(classify FPClassifierClient) *ProbeCorrection {
	store := NewFPSignalStore()
	return &ProbeCorrection{
		store:     store,
		estimator: NewFPRateEstimator(store),
		classify:  classify,
	}
}

// Evaluate records the current probe outcome into the FP signal store and,
// when the candidate is not already suppressed, applies FP-rate-based
// correction. Returns true when the candidate was corrected (suppressed due
// to a high FP rate or the AI classifier's verdict). outcome is updated
// in-place when correction occurs: Suppressed is set to true, Reason is set,
// CorrectionHint is populated, and EmittedFinding is zeroed.
func (pc *ProbeCorrection) Evaluate(
	ctx context.Context,
	cand VerifyCandidate,
	probeName string,
	outcome *VerificationOutcome,
) bool {
	if pc == nil {
		return false
	}
	affectedURL := cand.Finding.AffectedURL

	// Step 1: Record the outcome into the store so the estimator accumulates
	// signal data even when no correction is applied this round.
	pc.store.Record(probeName, affectedURL, outcome.Suppressed)

	// Step 2: If the finding is already suppressed by proof-policy or PoC
	// replay failure, no further correction is needed.
	if outcome.Suppressed {
		return false
	}

	// Step 3: Assess the FP rate for this (probe, URL-pattern) pair.
	assessment, fpRate, fpSamples := pc.estimator.Assess(probeName, affectedURL)
	switch assessment {
	case FPAssessmentUnknown, FPAssessmentLikelyReal:
		// Insufficient signal or clearly real → admit the finding.
		return false

	case FPAssessmentLikelyFP:
		// Rate at or above suspect threshold → suppress without an AI call.
		hint := fmt.Sprintf(
			"FP rate %.0f%% (≥ %.0f%% threshold) over %d samples",
			fpRate*100, fpRateSuspectThreshold*100, fpSamples,
		)
		pc.doSuppress(outcome, "fp-rate-above-threshold", hint)
		// Record the additional suppression event caused by correction.
		pc.store.Record(probeName, affectedURL, true)
		return true

	case FPAssessmentBorderline:
		// Borderline FP rate → call the AI classifier when available.
		if pc.classify == nil {
			// No AI client configured; admit the finding.
			return false
		}
		signals := make([]string, 0, len(cand.Signals))
		for _, s := range cand.Signals {
			signals = append(signals, string(s))
		}
		classInput := model.FPClassificationInput{
			ProbeName:    probeName,
			Category:     cand.Finding.Category,
			Title:        cand.Finding.Title,
			Evidence:     cand.Finding.Evidence,
			FPRate:       fpRate,
			FPSamples:    fpSamples,
			Signals:      signals,
			PolicyReason: outcome.Reason,
		}
		result := pc.classify.ClassifyFalsePositive(ctx, classInput)
		if !result.IsFalsePositive {
			return false
		}
		hint := result.CorrectionHint
		if strings.TrimSpace(hint) == "" {
			hint = fmt.Sprintf(
				"AI confidence %.2f (borderline FP rate %.0f%%)",
				result.Confidence, fpRate*100,
			)
		}
		pc.doSuppress(outcome, "ai-fp-classification", hint)
		pc.store.Record(probeName, affectedURL, true)
		pc.appendCorrectedRecord(probeName, cand.Finding)
		return true
	}
	return false
}

// doSuppress sets the outcome fields to indicate the finding was suppressed
// by FP correction.
func (pc *ProbeCorrection) doSuppress(outcome *VerificationOutcome, reason, hint string) {
	outcome.Suppressed = true
	outcome.Verified = false
	outcome.Downgraded = false
	outcome.Reason = reason
	outcome.CorrectionHint = hint
	outcome.EmittedFinding = model.Finding{}
}

// appendCorrectedRecord persists a ProbeRecord for a finding that was
// confirmed as a false positive by the AI classifier. These records are
// drained at scan end and fed to the ML calibration pipeline via
// ProbeCalibratorService.CalibrateProbeSignals.
func (pc *ProbeCorrection) appendCorrectedRecord(probeName string, finding model.Finding) {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", probeName, finding.AffectedURL, finding.Evidence)
	id := hex.EncodeToString(h.Sum(nil))

	payloadHash := ""
	if finding.EvidenceFields != nil {
		payloadHash = finding.EvidenceFields["payload.hash"]
	}
	paramName := ""
	if finding.EvidenceFields != nil {
		paramName = finding.EvidenceFields["param"]
	}

	rec := model.ProbeRecord{
		ID:          id,
		Category:    finding.Category,
		Endpoint:    finding.AffectedURL,
		ParamName:   paramName,
		PayloadHash: payloadHash,
		// Treat AI-confirmed FP corrections as strong negative training
		// examples by recording them as ProbeNoSignal (no genuine signal).
		Outcome:   model.ProbeNoSignal,
		Confirmed: false,
		CreatedAt: time.Now().UTC(),
	}
	pc.mu.Lock()
	pc.correctedRecords = append(pc.correctedRecords, rec)
	pc.mu.Unlock()
}

// DrainCorrectedRecords returns and clears all accumulated corrected probe
// records. Called by scanner.Run at scan end to feed the ML calibration
// pipeline. Safe to call concurrently.
func (pc *ProbeCorrection) DrainCorrectedRecords() []model.ProbeRecord {
	if pc == nil {
		return nil
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	out := pc.correctedRecords
	pc.correctedRecords = nil
	return out
}
