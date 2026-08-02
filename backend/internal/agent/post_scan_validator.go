package agent

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/scope"
)

// postScanValidatorChecks lists the logical phases this agent performs. An AI
// advisor may reorder or focus entries; the agent always runs both passes when
// UsePostScanValidation is true.
var postScanValidatorChecks = []string{
	"fp_retest",
	"fn_gap_sweep",
}

// fpRetestEvidenceTiers lists EvidenceQualityTier values that trigger Pass A
// re-testing regardless of the finding's numerical confidence.
var fpRetestEvidenceTiers = map[string]bool{
	"low":         true,
	"speculative": true,
	"unconfirmed": true,
}

// fnSweepCategories are the lightweight probe categories used in Pass B.
// They are deliberately broad but fast — the deterministic oracle only emits
// a finding when the signal is unambiguous.
var fnSweepCategories = []string{"xss", "cors", "open_redirect", "ssrf"}

// maxFNSweepEndpoints caps the number of un-probed endpoints Pass B will target.
const maxFNSweepEndpoints = 20

// fpRetestConfidenceThreshold is the exclusive upper bound below which a
// finding's numerical confidence qualifies it for Pass A re-testing.
const fpRetestConfidenceThreshold = 0.65

// verifyHypothesisFn is the signature of the oracle used in both passes.
// It is a field on PostScanValidatorAgent so tests can inject a mock without
// needing a real scan service or a network-accessible server.
type verifyHypothesisFn func(
	ctx context.Context,
	endpoint, paramName, payloadHint, category string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) *model.Finding

// PostScanValidatorAgent runs a two-pass post-scan re-evaluation after the
// deterministic scan completes:
//
//	Pass A (FP Re-Test): re-probes each low-confidence or weak-evidence finding
//	via the scanner's deterministic oracle.  Confirmed findings get their
//	confidence raised to ≥ 0.80; unconfirmed findings are annotated with
//	retestResult=not-confirmed and have their confidence reduced by 0.20.
//	Findings are never deleted — the human triage board has final say.
//
//	Pass B (FN Gap Sweep): collects endpoints from the scan's seed surface
//	that do not appear as an AffectedURL in any existing finding, then probes
//	the highest-ROI candidates with a lightweight multi-category sweep to
//	surface false negatives.  When an AI client is configured, it also
//	generates and verifies AI-guided hypotheses for the un-covered surface.
type PostScanValidatorAgent struct {
	aiClient    *ai.Client
	scanService *scanner.Service
	enabled     bool
	// verifyFn is the oracle called by both passes.  It defaults to
	// scanService.RunHypothesisVerification and can be replaced in tests.
	verifyFn verifyHypothesisFn
}

// NewPostScanValidatorAgent constructs a PostScanValidatorAgent.
// Both aiClient and scanService may be nil; the agent skips its passes when
// scanService is absent.  AI-guided hypothesis generation in Pass B is skipped
// when aiClient is nil.
func NewPostScanValidatorAgent(scanService *scanner.Service, aiClient *ai.Client, enabled bool) *PostScanValidatorAgent {
	a := &PostScanValidatorAgent{
		aiClient:    aiClient,
		scanService: scanService,
		enabled:     enabled,
	}
	if scanService != nil {
		a.verifyFn = scanService.RunHypothesisVerification
	}
	return a
}

func (a *PostScanValidatorAgent) Name() string  { return "post_scan_validator" }
func (a *PostScanValidatorAgent) Enabled() bool { return a.enabled }

// Run executes both passes and returns annotated re-test results (Pass A) and
// newly discovered findings (Pass B) in the agent output.
func (a *PostScanValidatorAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if !input.Options.UsePostScanValidation {
		output.DebugNotes = "PostScanValidatorAgent: skipped — UsePostScanValidation is false"
		return output, nil
	}
	if a.scanService == nil && a.verifyFn == nil {
		output.DebugNotes = "PostScanValidatorAgent: skipped — scanService not configured"
		return output, nil
	}

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventInfo,
		AgentName: a.Name(),
		Message:   "Post-scan re-evaluation started (Pass A: FP re-test, Pass B: FN gap sweep)",
	})

	// ── Pass A — FP Re-Test ───────────────────────────────────────────────
	fpAnnotated := a.runPassA(ctx, input)
	output.Findings = append(output.Findings, fpAnnotated...)

	select {
	case <-ctx.Done():
		output.DebugNotes = "PostScanValidatorAgent: cancelled after Pass A"
		return output, ctx.Err()
	default:
	}

	// ── Pass B — FN Gap Sweep (active probes only) ────────────────────────
	if !input.Options.PassiveOnly {
		fnFound := a.runPassB(ctx, input)
		output.Findings = append(output.Findings, fnFound...)
	}

	// Build summary metadata.
	fpTotal, fpConfirmed, fpUnconfirmed := 0, 0, 0
	for _, f := range fpAnnotated {
		if v, ok := f.EvidenceFields["retestResult"]; ok {
			fpTotal++
			if v == "confirmed" {
				fpConfirmed++
			} else {
				fpUnconfirmed++
			}
		}
	}
	fnNew := len(output.Findings) - len(fpAnnotated)

	output.Metadata["fp_retest_total"] = itoa(fpTotal)
	output.Metadata["fp_retest_confirmed"] = itoa(fpConfirmed)
	output.Metadata["fp_retest_unconfirmed"] = itoa(fpUnconfirmed)
	output.Metadata["fn_sweep_new"] = itoa(fnNew)
	output.DebugNotes = fmt.Sprintf(
		"PostScanValidatorAgent: Pass A re-tested %d finding(s) (%d confirmed, %d unconfirmed); Pass B found %d new finding(s).",
		fpTotal, fpConfirmed, fpUnconfirmed, fnNew,
	)

	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventInfo,
		AgentName: a.Name(),
		Message: fmt.Sprintf(
			"Post-scan re-evaluation complete: %d re-tested (%d confirmed, %d unconfirmed), %d new FN finding(s)",
			fpTotal, fpConfirmed, fpUnconfirmed, fnNew,
		),
	})

	return output, nil
}

// runPassA re-probes all low-confidence or weak-evidence findings from
// input.AllFindings.  It returns an annotated copy of each re-tested finding.
func (a *PostScanValidatorAgent) runPassA(ctx context.Context, input AgentInput) []model.Finding {
	if input.Options.PassiveOnly {
		log.Printf("post_scan_validator: Pass A skipped (passive-only mode)")
		return nil
	}

	var candidates []model.Finding
	for _, f := range input.AllFindings {
		if !needsRetest(f) {
			continue
		}
		ep := strings.TrimSpace(f.AffectedURL)
		if ep == "" {
			ep = input.Target
		}
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}
		candidates = append(candidates, f)
	}

	if len(candidates) == 0 {
		return nil
	}

	log.Printf("post_scan_validator: Pass A — re-testing %d low-confidence finding(s)", len(candidates))
	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventInfo,
		AgentName: "post_scan_validator",
		Message:   fmt.Sprintf("Pass A: re-testing %d low-confidence finding(s)", len(candidates)),
	})

	annotated := make([]model.Finding, 0, len(candidates))
	for _, f := range candidates {
		select {
		case <-ctx.Done():
			return annotated
		default:
		}

		ep := strings.TrimSpace(f.AffectedURL)
		if ep == "" {
			ep = input.Target
		}
		paramName := strings.TrimSpace(f.AffectedParameter)
		category := strings.ToLower(strings.TrimSpace(f.Category))

		confirmed := a.verifyFn(
			ctx, ep, paramName, "", category,
			input.AuthProfile, input.Options,
		)

		cp := f
		if cp.EvidenceFields == nil {
			cp.EvidenceFields = map[string]string{}
		}
		if confirmed != nil {
			cp.EvidenceFields["retestResult"] = "confirmed"
			if cp.Confidence < 0.80 {
				cp.Confidence = 0.80
			}
			log.Printf("post_scan_validator: Pass A confirmed finding %q on %s", f.ID, ep)
		} else {
			cp.EvidenceFields["retestResult"] = "not-confirmed"
			cp.Confidence -= 0.20
			if cp.Confidence < 0.10 {
				cp.Confidence = 0.10
			}
			log.Printf("post_scan_validator: Pass A could not confirm finding %q on %s", f.ID, ep)
		}
		annotated = append(annotated, cp)
	}
	return annotated
}

// runPassB sweeps un-probed endpoints with a lightweight multi-category probe
// set to surface false negatives missed by the deterministic scan.
func (a *PostScanValidatorAgent) runPassB(ctx context.Context, input AgentInput) []model.Finding {
	// Build the set of AffectedURLs already covered by existing findings.
	covered := make(map[string]bool, len(input.AllFindings))
	for _, f := range input.AllFindings {
		if u := strings.TrimSpace(f.AffectedURL); u != "" {
			covered[normalizeURLKey(u)] = true
		}
	}

	// Collect un-probed in-scope endpoints from the seed surface.
	surface := append([]string{input.Target}, input.Options.SeedRuntimeEndpoints...)
	seenKey := make(map[string]bool)
	var unprobed []string
	for _, raw := range surface {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !scope.IsURLInScope(raw, input.Scope) {
			continue
		}
		key := normalizeURLKey(raw)
		if seenKey[key] || covered[key] {
			continue
		}
		seenKey[key] = true
		unprobed = append(unprobed, raw)
	}

	if len(unprobed) == 0 {
		return nil
	}

	// Rank by path depth + param count heuristic; cap at maxFNSweepEndpoints.
	sort.Slice(unprobed, func(i, j int) bool {
		return endpointROI(unprobed[i]) > endpointROI(unprobed[j])
	})
	if len(unprobed) > maxFNSweepEndpoints {
		unprobed = unprobed[:maxFNSweepEndpoints]
	}

	log.Printf("post_scan_validator: Pass B — sweeping %d un-probed endpoint(s)", len(unprobed))
	Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventInfo,
		AgentName: "post_scan_validator",
		Message:   fmt.Sprintf("Pass B: sweeping %d un-probed endpoint(s) for false negatives", len(unprobed)),
	})

	// Optional AI-guided hypothesis generation for the un-covered surface.
	var aiHypotheses []ai.VulnerabilityHypothesis
	if a.aiClient != nil {
		aiHypotheses = a.aiClient.Hypothesize(ctx, input.Target, input.AllFindings, unprobed)
	}

	var found []model.Finding

	// Lightweight category sweep on each un-probed endpoint.
	for _, ep := range unprobed {
		select {
		case <-ctx.Done():
			return found
		default:
		}
		for _, cat := range fnSweepCategories {
			select {
			case <-ctx.Done():
				return found
			default:
			}
			f := a.verifyFn(
				ctx, ep, "", "", cat, input.AuthProfile, input.Options,
			)
			if f == nil {
				continue
			}
			f.ID = fmt.Sprintf("psv-fn-%s-%s", cat, sanitizeIDSegment(ep))
			f.Sources = appendUnique(f.Sources, "post_scan_validator")
			f.Sources = appendUnique(f.Sources, "fn_sweep")
			if f.EvidenceFields == nil {
				f.EvidenceFields = map[string]string{}
			}
			f.EvidenceFields["sweepCategory"] = cat
			f.EvidenceFields["sweepEndpoint"] = ep
			found = append(found, *f)
		}
	}

	// Verify AI-generated hypotheses for the un-covered surface.
	for i, h := range aiHypotheses {
		select {
		case <-ctx.Done():
			return found
		default:
		}
		ep := strings.TrimSpace(h.Endpoint)
		if ep == "" || !scope.IsURLInScope(ep, input.Scope) {
			continue
		}
		f := a.verifyFn(
			ctx, ep, h.ParamName, h.PayloadHint, h.Category,
			input.AuthProfile, input.Options,
		)
		if f == nil {
			continue
		}
		f.ID = fmt.Sprintf("psv-ai-h%d-%s", i+1, strings.ToLower(strings.TrimSpace(h.Category)))
		f.Sources = appendUnique(f.Sources, "post_scan_validator")
		f.Sources = appendUnique(f.Sources, "fn_sweep")
		if f.EvidenceFields == nil {
			f.EvidenceFields = map[string]string{}
		}
		f.EvidenceFields["hypothesisRationale"] = h.Rationale
		found = append(found, *f)
	}

	return found
}

// needsRetest returns true when a finding should be re-probed by Pass A:
// the finding's numerical confidence is below the threshold, or its
// EvidenceQualityTier indicates low-quality evidence.
func needsRetest(f model.Finding) bool {
	if f.Confidence > 0 && f.Confidence < fpRetestConfidenceThreshold {
		return true
	}
	tier := strings.ToLower(strings.TrimSpace(f.EvidenceQualityTier))
	return fpRetestEvidenceTiers[tier]
}

// normalizeURLKey returns a lower-case scheme+host+path key used to compare
// URLs when checking whether an endpoint has already been covered by a finding.
func normalizeURLKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return strings.ToLower(u.Scheme + "://" + u.Host + u.Path)
}

// endpointROI scores an endpoint for Pass B scheduling priority.
// Higher path depth and more query parameters increase the priority so
// complex, parameter-rich endpoints are tested before bare base URLs.
func endpointROI(raw string) int {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	segments := strings.Count(u.Path, "/")
	params := len(u.Query())
	return segments + params*2
}

// sanitizeIDSegment converts a URL into a short, ID-safe suffix suitable for
// embedding in finding IDs.
func sanitizeIDSegment(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "unknown"
	}
	seg := strings.ToLower(u.Host + u.Path)
	seg = strings.NewReplacer("/", "-", ".", "-", ":", "-").Replace(seg)
	if len(seg) > 32 {
		seg = seg[:32]
	}
	if seg == "" {
		return "unknown"
	}
	return seg
}
