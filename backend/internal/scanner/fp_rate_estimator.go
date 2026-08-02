package scanner

const (
	// fpRateSuspectThreshold is the FP rate at or above which a (probe,
	// URL-pattern) combination is marked as "likely FP" without an AI
	// consultation.
	fpRateSuspectThreshold = 0.70

	// fpRateBorderlineLow is the lower bound of the "borderline" range. FP
	// rates in [fpRateBorderlineLow, fpRateSuspectThreshold) trigger the AI
	// classifier; below this the finding is admitted without further checking.
	fpRateBorderlineLow = 0.30

	// fpRateMinSamples is the minimum number of probe firings required before
	// the estimator makes any assessment. Avoids hair-trigger suppression when
	// only one or two probes have fired.
	fpRateMinSamples = 5
)

// FPAssessment is the estimator's preliminary verdict for a (probe,
// URL-pattern) pair given the accumulated signal store.
type FPAssessment int

const (
	// FPAssessmentUnknown means there are too few samples to make a decision.
	FPAssessmentUnknown FPAssessment = iota
	// FPAssessmentLikelyReal means the observed FP rate is below
	// fpRateBorderlineLow; the finding is admitted without further checking.
	FPAssessmentLikelyReal
	// FPAssessmentBorderline means the FP rate is in the range
	// [fpRateBorderlineLow, fpRateSuspectThreshold). The AI classifier is
	// consulted to make a final decision.
	FPAssessmentBorderline
	// FPAssessmentLikelyFP means the FP rate is at or above
	// fpRateSuspectThreshold; the finding is suppressed without an AI call.
	FPAssessmentLikelyFP
)

// FPRateEstimator applies threshold logic to an FPSignalStore to produce a
// coarse preliminary assessment that drives whether an AI call is needed.
type FPRateEstimator struct {
	store            *FPSignalStore
	suspectThreshold float64
	borderlineLow    float64
	minSamples       int
}

// NewFPRateEstimator returns an estimator backed by store with the default
// thresholds.
func NewFPRateEstimator(store *FPSignalStore) *FPRateEstimator {
	return &FPRateEstimator{
		store:            store,
		suspectThreshold: fpRateSuspectThreshold,
		borderlineLow:    fpRateBorderlineLow,
		minSamples:       fpRateMinSamples,
	}
}

// Assess returns the FP assessment and the observed FP rate and sample count
// for (probeName, affectedURL). When fewer than minSamples have been recorded,
// returns (FPAssessmentUnknown, 0, 0).
func (e *FPRateEstimator) Assess(probeName, affectedURL string) (FPAssessment, float64, int) {
	rate, samples := e.store.FPRate(probeName, affectedURL, e.minSamples)
	if samples < e.minSamples {
		return FPAssessmentUnknown, 0, samples
	}
	switch {
	case rate >= e.suspectThreshold:
		return FPAssessmentLikelyFP, rate, samples
	case rate >= e.borderlineLow:
		return FPAssessmentBorderline, rate, samples
	default:
		return FPAssessmentLikelyReal, rate, samples
	}
}
