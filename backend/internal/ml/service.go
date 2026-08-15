package ml

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proofpolicy"
	"auto-bughunter/backend/internal/sidecartls"
)

type Repository interface {
	ListCompletedJobs(ctx context.Context, limit int) ([]*model.ScanJob, error)
	GetAssetsByScanID(ctx context.Context, scanID string) ([]model.ScanAsset, error)
	ListAuditEvents(ctx context.Context, scanID string) ([]model.ScanAuditEvent, error)
	ListFeedback(ctx context.Context, limit int) ([]model.ReportFeedback, error)
	// ListProbeRecordsByCategory is used in Stage 4 to fold probe-level negative
	// evidence into the ML training dataset.
	ListProbeRecordsByCategory(ctx context.Context, category string, since time.Time, limit int) ([]model.ProbeRecord, error)
}

type ProxyStore interface {
	ListProxyRequests(ctx context.Context) ([]*model.ProxyRequest, error)
}

type Config struct {
	PseudonymSalt string
	ExternalURL   string
	AuthToken     string
	Timeout       time.Duration
}

type Service struct {
	salt        string
	externalURL string
	authToken   string
	httpClient  *http.Client

	// calibrationMu protects categoryCalibration. The calibration map is
	// populated by CalibrateProbeSignals and read (without blocking) in
	// ScoreFindings. A zero-value map means no calibration has been applied.
	calibrationMu      sync.RWMutex
	categoryCalibration map[string]float64
}

func NewService(cfg Config) *Service {
	salt := strings.TrimSpace(cfg.PseudonymSalt)
	if salt == "" {
		salt = "auto-bughunter"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}
	sidecartls.ConfigureClient(httpClient)
	return &Service{
		salt:        salt,
		externalURL: strings.TrimRight(strings.TrimSpace(cfg.ExternalURL), "/"),
		authToken:   strings.TrimSpace(cfg.AuthToken),
		httpClient:  httpClient,
	}
}

type EngagementDataset struct {
	Records []EngagementRecord `json:"records"`
}

type EngagementRecord struct {
	ScanID          string                   `json:"scanId"`
	TargetHash      string                   `json:"targetHash"`
	ToolOptions     map[string]bool          `json:"toolOptions"`
	Findings        []SanitizedFinding       `json:"findings"`
	Assets          []SanitizedAsset         `json:"assets"`
	AuditTrail      []SanitizedEvent         `json:"auditTrail"`
	ProxySignals    []ProxySignal            `json:"proxySignals"`
	Feedback        []FeedbackOutcome        `json:"feedback,omitempty"`
	ProbeNegatives  []ProbeNegativeSignal    `json:"probeNegatives,omitempty"`
	Dashboard       *model.DecisionDashboard `json:"dashboard,omitempty"`
	NextActions     []string                 `json:"nextActions,omitempty"`
	AutomatedReport string                   `json:"automatedReport,omitempty"`
	Labels          EngagementLabels         `json:"labels"`
}

type ProbeNegativeSignal struct {
	Category string             `json:"category"`
	Outcome  model.ProbeOutcome `json:"outcome"`
	Count    int                `json:"count"`
	LastSeen time.Time          `json:"lastSeen"`
}

type SanitizedFinding struct {
	ID           string         `json:"id"`
	Category     string         `json:"category"`
	Severity     model.Severity `json:"severity"`
	Title        string         `json:"title"`
	Evidence     string         `json:"evidence"`
	Confidence   float64        `json:"confidence"`
	DriftStatus  string         `json:"driftStatus"`
	BusinessTags []string       `json:"businessTags,omitempty"`
}

type SanitizedAsset struct {
	AssetType string `json:"assetType"`
	AssetKey  string `json:"assetKey"`
	AssetHash string `json:"assetHash"`
}

type SanitizedEvent struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type ProxySignal struct {
	Method          string `json:"method"`
	URLHash         string `json:"urlHash"`
	ResponseStatus  int    `json:"responseStatus"`
	HasAuthHeader   bool   `json:"hasAuthHeader"`
	HasCookieHeader bool   `json:"hasCookieHeader"`
}

type FeedbackOutcome struct {
	FindingID string  `json:"findingId"`
	Category  string  `json:"category,omitempty"`
	Title     string  `json:"title,omitempty"`
	Outcome   string  `json:"outcome"`
	PayoutUSD float64 `json:"payoutUsd,omitempty"`
	Notes     string  `json:"notes,omitempty"`
}

type EngagementLabels struct {
	ToolUsefulness      map[string]float64 `json:"toolUsefulness"`
	PrioritizationScore map[string]float64 `json:"prioritizationScore"`
	ResolvedFindings    int                `json:"resolvedFindings"`
	EngagementSuccess   float64            `json:"engagementSuccess"`
}

func (s *Service) BuildTrainingDataset(ctx context.Context, repo Repository, proxyStore ProxyStore, limit int) (*EngagementDataset, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	jobs, err := repo.ListCompletedJobs(ctx, limit)
	if err != nil {
		return nil, err
	}
	proxySignalsByHost := map[string][]ProxySignal{}
	if proxyStore != nil {
		if reqs, err := proxyStore.ListProxyRequests(ctx); err == nil {
			for _, req := range reqs {
				if req == nil {
					continue
				}
				host := hostOf(req.URL)
				if host == "" {
					continue
				}
				proxySignalsByHost[host] = append(proxySignalsByHost[host], ProxySignal{
					Method:          req.Method,
					URLHash:         s.hash(req.URL),
					ResponseStatus:  req.ResponseStatus,
					HasAuthHeader:   hasHeader(req.RequestHeaders, "authorization"),
					HasCookieHeader: hasHeader(req.RequestHeaders, "cookie"),
				})
			}
		}
	}
	feedbackByScan := map[string][]model.ReportFeedback{}
	if entries, err := repo.ListFeedback(ctx, 5000); err == nil {
		for _, item := range entries {
			scanID := strings.TrimSpace(item.ScanID)
			if scanID == "" {
				continue
			}
			feedbackByScan[scanID] = append(feedbackByScan[scanID], item)
		}
	}
	out := &EngagementDataset{Records: make([]EngagementRecord, 0, len(jobs))}
	for _, job := range jobs {
		if job == nil {
			continue
		}
		record, err := s.buildRecord(ctx, repo, job, proxySignalsByHost[hostOf(job.Target)], feedbackByScan[job.ID])
		if err != nil {
			continue
		}
		out.Records = append(out.Records, record)
	}
	return out, nil
}

func (s *Service) RecommendFromHistory(ctx context.Context, repo Repository, proxyStore ProxyStore, job *model.ScanJob) *model.ModelRecommendations {
	if job == nil {
		return nil
	}
	dataset, err := s.BuildTrainingDataset(ctx, repo, proxyStore, 200)
	if err != nil {
		return fallbackRecommendations(job)
	}
	feedback := s.feedbackSignals(ctx, repo)
	payouts := s.payoutSignals(ctx, repo, job.ProgramName)
	recs := &model.ModelRecommendations{
		ToolSelection:       recommendTools(dataset.Records),
		PrioritizedFindings: prioritizeFindings(job.Findings, feedback, payouts),
		Copilot:             buildCopilotSuggestion(job, dataset.Records),
		ModelMode:           "historical-deterministic",
	}
	recs.ToolSelection = downrankFlakyTools(recs.ToolSelection, job.Findings)
	if len(dataset.Records) == 0 {
		recs.ModelMode = "fallback-deterministic"
	}
	return recs
}

func fallbackRecommendations(job *model.ScanJob) *model.ModelRecommendations {
	return &model.ModelRecommendations{
		ToolSelection: []model.ToolRecommendation{
			{Tool: "native-http-tls-wordlist", Score: 0.8, Reason: "No historical training data available; defaulting to safe built-in checks.", Confidence: 0.6},
		},
		PrioritizedFindings: prioritizeFindings(job.Findings, nil, nil),
		Copilot:             buildCopilotSuggestion(job, nil),
		ModelMode:           "fallback-deterministic",
	}
}

func recommendTools(records []EngagementRecord) []model.ToolRecommendation {
	if len(records) == 0 {
		return []model.ToolRecommendation{{Tool: "native-http-tls-wordlist", Score: 0.8, Reason: "No prior engagements available.", Confidence: 0.6}}
	}
	agg := map[string]struct {
		score float64
		count int
	}{}
	for _, r := range records {
		for tool, usefulness := range r.Labels.ToolUsefulness {
			cur := agg[tool]
			cur.score += usefulness
			cur.count++
			agg[tool] = cur
		}
	}
	recs := make([]model.ToolRecommendation, 0, len(agg))
	for tool, v := range agg {
		if v.count == 0 {
			continue
		}
		mean := v.score / float64(v.count)
		recs = append(recs, model.ToolRecommendation{
			Tool:       tool,
			Score:      round2(mean),
			Reason:     fmt.Sprintf("Mean usefulness %.2f across %d engagements.", mean, v.count),
			Confidence: round2(min(0.98, 0.5+float64(v.count)/250.0)),
		})
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].Score != recs[j].Score {
			return recs[i].Score > recs[j].Score
		}
		return recs[i].Tool < recs[j].Tool
	})
	if len(recs) > 6 {
		recs = recs[:6]
	}
	return recs
}

// prioritizeFindings ranks the supplied findings using a deterministic
// composition of the severity, confidence, drift, exploitability, operator
// feedback, and program payout signals. The resulting Reason is a stable
// human-readable string and Rationale exposes the per-component contribution
// so that UIs and reports can render explainability without parsing prose.
func prioritizeFindings(findings []model.Finding, feedback map[string]float64, payouts map[string]float64) []model.PrioritizedFinding {
	out := make([]model.PrioritizedFinding, 0, len(findings))
	for _, f := range findings {
		base, components := scoreFindingWithComponents(f)
		score := base
		fb := feedbackBoost(feedback, f)
		if fb != 0 {
			score += fb
			components["feedback_boost"] = round2(fb)
		}
		pb := payoutBoost(payouts, f)
		if pb != 0 {
			score += pb
			components["payout_boost"] = round2(pb)
		}
		score = clamp(score, 0, 1)
		components["score"] = round2(score)
		out = append(out, model.PrioritizedFinding{
			FindingID: f.ID,
			Title:     f.Title,
			Severity:  f.Severity,
			Score:     round2(score),
			Reason:    priorityReason(f, score, components),
			Rationale: components,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Title < out[j].Title
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

func downrankFlakyTools(recs []model.ToolRecommendation, findings []model.Finding) []model.ToolRecommendation {
	failureRate := 0.0
	for _, f := range findings {
		if f.ID != "integration-health-telemetry" || f.EvidenceFields == nil {
			continue
		}
		if raw, ok := f.EvidenceFields["failureRate"]; ok {
			if v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil && v > failureRate {
				failureRate = v
			}
		}
	}
	if failureRate <= 0 {
		return recs
	}
	penalty := min(0.35, failureRate*0.5)
	for i := range recs {
		recs[i].Score = round2(clamp(recs[i].Score-penalty, 0, 1))
		recs[i].Reason = recs[i].Reason + fmt.Sprintf(" Penalized by %.2f due to flaky integration telemetry.", penalty)
		recs[i].Confidence = round2(clamp(recs[i].Confidence-penalty/2, 0, 1))
	}
	return recs
}

func (s *Service) feedbackSignals(ctx context.Context, repo Repository) map[string]float64 {
	entries, err := repo.ListFeedback(ctx, 1000)
	if err != nil || len(entries) == 0 {
		return nil
	}
	type agg struct {
		total    int
		accepted int
		rejected int
	}
	m := map[string]agg{}
	for _, f := range entries {
		key := feedbackKey(f.Category, f.Title, f.FindingID)
		cur := m[key]
		cur.total++
		switch strings.ToLower(strings.TrimSpace(f.Outcome)) {
		case "accepted":
			cur.accepted++
		case "rejected", "duplicate", "informative", "na", "n/a":
			cur.rejected++
		}
		m[key] = cur
	}
	out := map[string]float64{}
	for k, v := range m {
		if v.total == 0 {
			continue
		}
		out[k] = (float64(v.accepted) - float64(v.rejected)*0.35) / float64(v.total)
	}
	return out
}

func feedbackBoost(signals map[string]float64, f model.Finding) float64 {
	if len(signals) == 0 {
		return 0
	}
	key := feedbackKey(f.Category, f.Title, f.ID)
	if v, ok := signals[key]; ok {
		return clamp(v*0.12, -0.06, 0.12)
	}
	return 0
}

func feedbackKey(category, title, id string) string {
	base := strings.TrimSpace(strings.ToLower(category + "|" + title))
	if base == "|" {
		return strings.TrimSpace(strings.ToLower(id))
	}
	return base
}

// payoutSignals aggregates historical bug-bounty payout outcomes per finding
// category, scoped to the supplied program name when provided. The returned
// map is keyed by lowercased category and stores a normalized boost value in
// the range [-0.06, +0.12]. Programs with no historical accepted payouts
// produce no entries.
//
// This realises the Wave 2 "payout-feedback loop into prioritization scoring
// by program profile" deliverable: prior accepted, payout-confirmed findings
// from the same program steer the ranker toward high-yield categories, while
// rejected/duplicate outcomes pull it back.
func (s *Service) payoutSignals(ctx context.Context, repo Repository, programName string) map[string]float64 {
	if repo == nil {
		return nil
	}
	entries, err := repo.ListFeedback(ctx, 1000)
	if err != nil || len(entries) == 0 {
		return nil
	}
	wantProgram := strings.TrimSpace(strings.ToLower(programName))
	type agg struct {
		samples  int
		accepted int
		payout   float64
		negative int
	}
	m := map[string]agg{}
	for _, fb := range entries {
		if wantProgram != "" && strings.TrimSpace(strings.ToLower(fb.ProgramName)) != wantProgram {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(fb.Category))
		if key == "" {
			continue
		}
		cur := m[key]
		cur.samples++
		switch strings.ToLower(strings.TrimSpace(fb.Outcome)) {
		case "accepted":
			cur.accepted++
			if fb.PayoutUSD > 0 {
				cur.payout += fb.PayoutUSD
			}
		case "rejected", "duplicate", "informative", "na", "n/a":
			cur.negative++
		}
		m[key] = cur
	}
	if len(m) == 0 {
		return nil
	}
	out := map[string]float64{}
	for k, v := range m {
		if v.samples == 0 {
			continue
		}
		// Normalised acceptance rate in [-1, 1].
		acceptance := (float64(v.accepted) - float64(v.negative)*0.5) / float64(v.samples)
		// Payout amplification saturates at $1k average payout per accepted
		// finding so a single outlier cannot dominate.
		payoutAmp := 0.0
		if v.accepted > 0 && v.payout > 0 {
			avg := v.payout / float64(v.accepted)
			payoutAmp = min(1.0, avg/1000.0)
		}
		boost := acceptance * (0.06 + 0.06*payoutAmp)
		boost = clamp(boost, -0.06, 0.12)
		if boost == 0 {
			continue
		}
		out[k] = boost
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func payoutBoost(signals map[string]float64, f model.Finding) float64 {
	if len(signals) == 0 {
		return 0
	}
	key := strings.TrimSpace(strings.ToLower(f.Category))
	if key == "" {
		return 0
	}
	if v, ok := signals[key]; ok {
		return v
	}
	return 0
}

func buildCopilotSuggestion(job *model.ScanJob, history []EngagementRecord) model.EngagementCopilotSuggestion {
	topFindings := prioritizeFindings(job.Findings, nil, nil)
	actions := []string{
		"Triage top-ranked findings and confirm exploitability in a controlled environment.",
		"Map prioritized findings to recent release changes and ownership boundaries.",
		"Run a verification scan after remediation to confirm drift transitions to resolved.",
	}
	if len(topFindings) > 0 {
		actions = append(actions, "Start with: "+topFindings[0].Title)
	}
	if len(history) > 10 {
		actions = append(actions, "Use historical high-yield tools from previous engagements for follow-up validation.")
	}
	return model.EngagementCopilotSuggestion{
		Summary:          fmt.Sprintf("Copilot analyzed %d current findings with %d historical engagements.", len(job.Findings), len(history)),
		SuggestedActions: dedupe(actions),
		Confidence:       round2(min(0.97, 0.55+float64(len(history))/200.0)),
	}
}

func (s *Service) buildRecord(ctx context.Context, repo Repository, job *model.ScanJob, proxySignals []ProxySignal, feedback []model.ReportFeedback) (EngagementRecord, error) {
	assets, _ := repo.GetAssetsByScanID(ctx, job.ID)
	events, _ := repo.ListAuditEvents(ctx, job.ID)
	record := EngagementRecord{
		ScanID:          job.ID,
		TargetHash:      s.hash(job.Target),
		ToolOptions:     optionsMap(job.Options),
		Findings:        sanitizeFindings(job.Findings),
		Assets:          sanitizeAssets(s, assets),
		AuditTrail:      sanitizeEvents(events),
		ProxySignals:    proxySignals,
		Feedback:        sanitizeFeedback(feedback),
		ProbeNegatives:  s.collectProbeNegatives(ctx, repo, job),
		Dashboard:       job.Dashboard,
		NextActions:     sanitizeStrings(job.NextActions),
		AutomatedReport: sanitizeText(job.AutomatedReport),
	}
	record.Labels = buildLabels(record.Findings)
	return record, nil
}

func optionsMap(o model.ScanOptions) map[string]bool {
	return map[string]bool{
		"nuclei":       o.UseNucleiIntegration,
		"zap_baseline": o.UseZAPBaselineIntegration,
		"subfinder":    o.UseSubfinderIntegration,
		"httpx":        o.UseHttpxIntegration,
		"cloudlist":    o.UseCloudlistIntegration,
		"naabu":        o.UseNaabuIntegration,
		"dnsx":         o.UseDnsxIntegration,
		"shuffledns":   o.UseShuffleDNSIntegration,
		"ct":           o.UseCertTransparency,
		"amass":        o.UseAmassIntegration,
		"katana":       o.UseKatanaIntegration,
		"tlsx":         o.UseTlsxIntegration,
		"cdncheck":     o.UseCdncheckIntegration,
		"asnmap":       o.UseAsnmapIntegration,
		"wpscan":       o.UseWPScanIntegration,
		"nikto":        o.UseNiktoIntegration,
		"sqlmap":       o.UseSQLMapIntegration,
		"ffuf":         o.UseFFUFIntegration,
		"gobuster":     o.UseGobusterIntegration,
		"kiterunner":   o.UseKiterunnerIntegration,
		"gau":          o.UseGauIntegration,
		"arjun":        o.UseArjunIntegration,
		"commix":       o.UseCommixIntegration,
		"linkfinder":   o.UseLinkFinderIntegration,
		"retire":       o.UseRetireJSIntegration,
		"trufflehog":   o.UseTruffleHogIntegration,
		"uncover":      o.UseUncoverIntegration,
		"vulnx":        o.UseVulnxIntegration,
	}
}

func sanitizeFindings(findings []model.Finding) []SanitizedFinding {
	out := make([]SanitizedFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, SanitizedFinding{
			ID:           f.ID,
			Category:     f.Category,
			Severity:     f.Severity,
			Title:        sanitizeText(f.Title),
			Evidence:     sanitizeText(f.Evidence),
			Confidence:   f.Confidence,
			DriftStatus:  f.DriftStatus,
			BusinessTags: f.BusinessTags,
		})
	}
	return out
}

func sanitizeAssets(s *Service, assets []model.ScanAsset) []SanitizedAsset {
	out := make([]SanitizedAsset, 0, len(assets))
	for _, a := range assets {
		out = append(out, SanitizedAsset{
			AssetType: a.AssetType,
			AssetKey:  sanitizeText(a.AssetKey),
			AssetHash: s.hash(a.AssetValue),
		})
	}
	return out
}

func sanitizeEvents(events []model.ScanAuditEvent) []SanitizedEvent {
	out := make([]SanitizedEvent, 0, len(events))
	for _, ev := range events {
		out = append(out, SanitizedEvent{
			Stage:   ev.Stage,
			Message: sanitizeText(ev.Message),
		})
	}
	return out
}

func sanitizeFeedback(entries []model.ReportFeedback) []FeedbackOutcome {
	out := make([]FeedbackOutcome, 0, len(entries))
	for _, item := range entries {
		outcome := strings.TrimSpace(strings.ToLower(item.Outcome))
		if outcome == "" {
			continue
		}
		out = append(out, FeedbackOutcome{
			FindingID: item.FindingID,
			Category:  sanitizeText(item.Category),
			Title:     sanitizeText(item.Title),
			Outcome:   outcome,
			PayoutUSD: item.PayoutUSD,
			Notes:     sanitizeText(item.Notes),
		})
	}
	return out
}

func buildLabels(findings []SanitizedFinding) EngagementLabels {
	toolUsefulness := map[string]float64{}
	toolCounts := map[string]int{}
	prioritization := map[string]float64{}
	resolved := 0
	for _, f := range findings {
		tool := inferToolFromFindingID(f.ID)
		score := scoreSanitizedFinding(f)
		toolUsefulness[tool] += score
		toolCounts[tool]++
		prioritization[f.ID] = round2(score)
		if strings.EqualFold(f.DriftStatus, "resolved") {
			resolved++
		}
	}
	for tool, total := range toolUsefulness {
		count := toolCounts[tool]
		if count == 0 {
			continue
		}
		toolUsefulness[tool] = round2(total / float64(count))
	}
	success := 0.0
	if len(findings) > 0 {
		success = round2(float64(resolved) / float64(len(findings)))
	}
	return EngagementLabels{
		ToolUsefulness:      toolUsefulness,
		PrioritizationScore: prioritization,
		ResolvedFindings:    resolved,
		EngagementSuccess:   success,
	}
}

func (s *Service) collectProbeNegatives(ctx context.Context, repo Repository, job *model.ScanJob) []ProbeNegativeSignal {
	if repo == nil || job == nil || len(job.Findings) == 0 {
		return nil
	}

	categorySet := map[string]struct{}{}
	for _, f := range job.Findings {
		cat := strings.TrimSpace(strings.ToLower(f.Category))
		if cat == "" {
			continue
		}
		categorySet[cat] = struct{}{}
	}
	if len(categorySet) == 0 {
		return nil
	}

	type agg struct {
		count    int
		lastSeen time.Time
	}
	stats := map[string]map[model.ProbeOutcome]agg{}
	since := time.Now().UTC().Add(-90 * 24 * time.Hour)

	for cat := range categorySet {
		records, err := repo.ListProbeRecordsByCategory(ctx, cat, since, 500)
		if err != nil || len(records) == 0 {
			continue
		}
		for _, rec := range records {
			if rec.Confirmed || !isNegativeProbeOutcome(rec.Outcome) {
				continue
			}
			if _, ok := stats[cat]; !ok {
				stats[cat] = map[model.ProbeOutcome]agg{}
			}
			cur := stats[cat][rec.Outcome]
			cur.count++
			if rec.CreatedAt.After(cur.lastSeen) {
				cur.lastSeen = rec.CreatedAt
			}
			stats[cat][rec.Outcome] = cur
		}
	}

	out := make([]ProbeNegativeSignal, 0)
	for cat, byOutcome := range stats {
		for outcome, bucket := range byOutcome {
			out = append(out, ProbeNegativeSignal{
				Category: cat,
				Outcome:  outcome,
				Count:    bucket.count,
				LastSeen: bucket.lastSeen,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category == out[j].Category {
			return out[i].Outcome < out[j].Outcome
		}
		return out[i].Category < out[j].Category
	})
	return out
}

func isNegativeProbeOutcome(outcome model.ProbeOutcome) bool {
	switch outcome {
	case model.ProbeNoSignal, model.ProbeNearMiss, model.ProbeWAFBlocked, model.ProbeServerError, model.ProbeError:
		return true
	default:
		return false
	}
}

func scoreSanitizedFinding(f SanitizedFinding) float64 {
	score := 0.4 + (severityWeight(f.Severity) * 0.15)
	score += min(0.35, max(0, f.Confidence)*0.35)
	switch strings.ToLower(strings.TrimSpace(f.DriftStatus)) {
	case "new":
		score += 0.1
	case "changed":
		score += 0.05
	case "resolved":
		score -= 0.1
	}
	return clamp(score, 0, 1)
}

func scoreFinding(f model.Finding) float64 {
	score, _ := scoreFindingWithComponents(f)
	return score
}

// scoreFindingWithComponents returns the finding's base score (severity +
// confidence + drift + exploitability) along with a per-component map that
// callers can persist as machine-readable ranking rationale.
func scoreFindingWithComponents(f model.Finding) (float64, map[string]float64) {
	components := map[string]float64{}
	severity := severityWeight(f.Severity) * 0.15
	components["severity"] = round2(severity)
	// Use the same calibrated confidence as the false-positive path so a
	// finding with omitted (zero) confidence is treated consistently across
	// ranking and triage instead of being silently down-ranked.
	calibrated := calibratedFindingConfidence(f)
	confidence := min(0.35, max(0, calibrated)*0.35)
	components["confidence"] = round2(confidence)
	base := 0.35 + severity + confidence
	if f.Exploitability != nil && f.Exploitability.Reachable {
		base += 0.07
		components["exploitability"] = 0.07
	}
	switch strings.ToLower(strings.TrimSpace(f.DriftStatus)) {
	case "new":
		base += 0.08
		components["drift"] = 0.08
	case "changed":
		base += 0.04
		components["drift"] = 0.04
	case "resolved":
		base -= 0.08
		components["drift"] = -0.08
	}
	return clamp(base, 0, 1), components
}

func priorityReason(f model.Finding, score float64, components map[string]float64) string {
	parts := []string{
		"severity=" + string(f.Severity),
		"confidence=" + strconv.FormatFloat(f.Confidence, 'f', 2, 64),
		"drift=" + strings.TrimSpace(f.DriftStatus),
	}
	if f.Exploitability != nil && f.Exploitability.Reachable {
		parts = append(parts, "reachable=true")
	}
	if v, ok := components["feedback_boost"]; ok && v != 0 {
		parts = append(parts, fmt.Sprintf("feedback=%+0.2f", v))
	}
	if v, ok := components["payout_boost"]; ok && v != 0 {
		parts = append(parts, fmt.Sprintf("payout=%+0.2f", v))
	}
	return fmt.Sprintf("Score %.2f from %s", score, strings.Join(parts, ", "))
}

func inferToolFromFindingID(id string) string {
	l := strings.ToLower(id)
	switch {
	case strings.Contains(l, "nuclei"):
		return "nuclei"
	case strings.Contains(l, "zap"):
		return "zap_baseline"
	case strings.Contains(l, "subfinder"):
		return "subfinder"
	case strings.Contains(l, "httpx"):
		return "httpx"
	case strings.Contains(l, "naabu"):
		return "naabu"
	case strings.Contains(l, "dnsx"):
		return "dnsx"
	case strings.Contains(l, "shuffledns"):
		return "shuffledns"
	case strings.Contains(l, "amass"):
		return "amass"
	case strings.Contains(l, "katana"):
		return "katana"
	case strings.Contains(l, "tlsx"):
		return "tlsx"
	case strings.Contains(l, "cdncheck"):
		return "cdncheck"
	case strings.Contains(l, "asnmap"):
		return "asnmap"
	case strings.Contains(l, "wpscan"):
		return "wpscan"
	case strings.Contains(l, "nikto"):
		return "nikto"
	case strings.Contains(l, "sqlmap"):
		return "sqlmap"
	case strings.Contains(l, "ffuf"):
		return "ffuf"
	case strings.Contains(l, "gobuster"):
		return "gobuster"
	default:
		return "native"
	}
}

func severityWeight(s model.Severity) float64 {
	switch s {
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

func (s *Service) hash(v string) string {
	sum := sha256.Sum256([]byte(s.salt + "|" + strings.TrimSpace(strings.ToLower(v))))
	return hex.EncodeToString(sum[:])[:24]
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(strings.TrimSpace(k), name) {
			return true
		}
	}
	return false
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization\s*:\s*)(bearer|basic)\s+[A-Za-z0-9\-._~+/=]+`),
	regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*["']?[A-Za-z0-9\-._~+/=]+["']?`),
	regexp.MustCompile(`(?i)(cookie\s*:\s*)[^;\n\r]+`),
	regexp.MustCompile(`https?://[^\s/$.?#].[^\s]*`),
}

func sanitizeText(v string) string {
	out := strings.TrimSpace(v)
	for _, p := range secretPatterns {
		out = p.ReplaceAllString(out, "$1[redacted]")
	}
	return out
}

func sanitizeStrings(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		t := sanitizeText(item)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func dedupe(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func round2(v float64) float64 {
	f, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", v), 64)
	return f
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ScoredFinding wraps a finding with ML-derived risk scoring.
type ScoredFinding struct {
	Finding        model.Finding
	Score          float64
	Confidence     float64
	Exploitability string
}

type FalsePositiveAssessment struct {
	Score     float64
	Threshold float64
	Candidate bool
}

// ScoreFindings scores findings by risk; falls back to deterministic scoring.
func (s *Service) ScoreFindings(findings []model.Finding) []ScoredFinding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]ScoredFinding, 0, len(findings))
	for _, f := range findings {
		score := scoreFinding(f)
		exploit := "unknown"
		if f.Exploitability != nil && f.Exploitability.Reachable {
			exploit = "reachable"
		}
		conf := calibratedFindingConfidence(f)
		// Apply per-category calibration multiplier when probe-signal
		// calibration has been run for this scan (ML_CALIBRATE_PROBE_SIGNALS).
		conf = clamp(conf*s.categoryCalibrationMultiplier(f.Category), 0.1, 0.99)
		out = append(out, ScoredFinding{
			Finding:        f,
			Score:          round2(score),
			Confidence:     round2(conf),
			Exploitability: exploit,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// BuildAttackPaths derives attack path strings from findings.
func (s *Service) BuildAttackPaths(findings []model.Finding) []string {
	paths := make([]string, 0)
	for _, f := range findings {
		if f.Exploitability == nil {
			continue
		}
		for _, hint := range f.Exploitability.AttackPathHints {
			if h := strings.TrimSpace(hint); h != "" {
				paths = append(paths, h+": "+f.Title)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// BuildRemediationPlan returns ordered remediation steps.
func (s *Service) BuildRemediationPlan(findings []model.Finding, limit int) []string {
	scored := s.ScoreFindings(findings)
	if limit <= 0 || limit > len(scored) {
		limit = len(scored)
	}
	plan := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		f := scored[i].Finding
		step := strings.TrimSpace(f.Recommendation)
		if step == "" {
			step = "Remediate: " + f.Title
		}
		plan = append(plan, step)
	}
	return plan
}

// FindPotentialFalsePositives returns likely-false-positive findings.
func (s *Service) FindPotentialFalsePositives(findings []model.Finding) []ScoredFinding {
	out := make([]ScoredFinding, 0)
	for _, f := range findings {
		assessment := s.AssessFalsePositiveCandidate(f)
		if !assessment.Candidate {
			continue
		}
		enriched := f
		annotateProofPolicy(&enriched)
		out = append(out, ScoredFinding{
			Finding:        enriched,
			Score:          round2(clamp(assessment.Score, 0, 1)),
			Confidence:     round2(clamp(0.35+assessment.Score*0.55, 0.35, 0.97)),
			Exploitability: "unlikely",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// AssessFalsePositiveCandidate computes whether a finding should be queued for
// manual false-positive review in shadow mode.
func (s *Service) AssessFalsePositiveCandidate(f model.Finding) FalsePositiveAssessment {
	score := falsePositiveSignalScore(f)
	threshold := falsePositiveThresholdForFinding(f)
	return FalsePositiveAssessment{
		Score:     score,
		Threshold: threshold,
		Candidate: score >= threshold,
	}
}

func calibratedFindingConfidence(f model.Finding) float64 {
	conf := f.Confidence
	if conf <= 0 {
		conf = 0.45
	}
	conf = clamp(conf, 0.1, 0.99)
	conf += validationStrengthSignal(f) * 0.45
	if hasUncertainLanguage(f) {
		conf -= 0.08
	}
	if strings.EqualFold(strings.TrimSpace(f.DriftStatus), "resolved") {
		conf -= 0.06
	}
	return clamp(conf, 0.2, 0.99)
}

func falsePositiveSignalScore(f model.Finding) float64 {
	score := 0.0
	conf := calibratedFindingConfidence(f)

	if conf < 0.45 {
		score += 0.34
	} else if conf < 0.6 {
		score += 0.18
	}
	if hasUncertainLanguage(f) {
		score += 0.22
	}
	if f.Severity == model.SeverityInfo {
		score += 0.18
	}
	if strings.EqualFold(strings.TrimSpace(f.DriftStatus), "resolved") {
		score += 0.12
	}
	if weakEvidenceSignal(f) {
		score += 0.18
	}
	// Blind vulnerability classes (blind SQLi, blind SSRF, blind XXE) where
	// in-band response analysis is not sufficient need an out-of-band signal to
	// be treated as reliable. Without an OOB signal, push the score up so the
	// finding surfaces as a candidate for human review rather than being quietly
	// accepted or promoted automatically.
	if isBlindClass(f) && !hasOOBSignal(f) {
		score += 0.18
	}
	score += proofPolicyPenalty(f)

	score -= validationStrengthSignal(f) * 0.7
	return clamp(score, 0, 1)
}

// isBlindClass returns true for vulnerability categories where in-band response
// evidence alone is not sufficient to confirm the finding.
func isBlindClass(f model.Finding) bool {
	cat := strings.ToLower(strings.TrimSpace(f.Category))
	switch cat {
	case "sqli", "sql injection", "blind sqli", "blind sql injection",
		"ssrf", "blind ssrf",
		"xxe", "xml external entity":
		return true
	}
	return false
}

// hasOOBSignal returns true when the finding carries any out-of-band
// confirmation evidence in its EvidenceFields, Evidence text, or Description.
func hasOOBSignal(f model.Finding) bool {
	if oob := strings.TrimSpace(f.EvidenceFields["oobInteraction"]); oob != "" {
		return true
	}
	if ms := strings.TrimSpace(f.EvidenceFields["timingDifferentialMs"]); ms != "" {
		return true
	}
	combined := strings.ToLower(f.Evidence + " " + f.Description)
	oobKeywords := []string{"callback", "out-of-band", "interactsh", "dns interaction", "outbound", "oob"}
	for _, kw := range oobKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

func proofPolicyPenalty(f model.Finding) float64 {
	result := proofpolicy.EvaluateFinding(f)
	if len(result.Required) == 0 {
		return 0
	}
	if len(result.Missing) == 0 {
		// All required proof fields satisfied.
		// For High/Critical findings with full coverage apply a stronger protective
		// bonus so that well-evidenced severe findings are not mistakenly flagged as
		// false-positive candidates based on surface signals alone.
		if f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical {
			return -0.20
		}
		return -0.10
	}
	base := min(0.36, float64(len(result.Missing))*0.12)
	// For High/Critical findings that fall below the minimum coverage threshold,
	// apply an additional penalty to surface them for human review before any
	// automated triage decision is made.
	if result.BelowMinCoverage && (f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical) {
		base = min(0.48, base+0.12)
	}
	return base
}

func annotateProofPolicy(f *model.Finding) {
	if f == nil {
		return
	}
	result := proofpolicy.EvaluateFinding(*f)
	if len(result.Required) == 0 {
		return
	}
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["proofPolicyCategory"] = result.Category
	f.EvidenceFields["proofPolicyCoverage"] = fmt.Sprintf("%.2f", result.Coverage)
	if len(result.Missing) > 0 {
		f.EvidenceFields["proofPolicyMissing"] = strings.Join(result.Missing, " | ")
	}
	if len(result.Satisfied) > 0 {
		f.EvidenceFields["proofPolicySatisfied"] = strings.Join(result.Satisfied, " | ")
	}
}

var categoryFalsePositiveThresholds = map[string]float64{
	"information_disclosure": 0.48,
	"headers":                0.5,
	"misconfiguration":       0.52,
	"open_redirect":          0.56,
	"csrf":                   0.58,
	"xss":                    0.6,
	"idor":                   0.64,
	"sqli":                   0.68,
	"ssrf":                   0.7,
}

func falsePositiveThresholdForFinding(f model.Finding) float64 {
	category := strings.ToLower(strings.TrimSpace(f.Category))
	if threshold, ok := categoryFalsePositiveThresholds[category]; ok {
		return threshold
	}
	return falsePositiveThresholdBySeverity(f.Severity)
}

func falsePositiveThresholdBySeverity(sev model.Severity) float64 {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return 0.72
	case model.SeverityMedium:
		return 0.62
	default:
		return 0.52
	}
}

func weakEvidenceSignal(f model.Finding) bool {
	if len(f.ReproductionSteps) > 0 || f.PoC != "" || len(f.ProofArtifacts) > 0 {
		return false
	}
	if strings.TrimSpace(f.Evidence) != "" || len(f.EvidenceFields) > 0 {
		return false
	}
	return strings.TrimSpace(f.AffectedURL) == ""
}

func validationStrengthSignal(f model.Finding) float64 {
	signal := 0.0
	if f.Exploitability != nil && f.Exploitability.Reachable {
		signal += 0.45
		switch strings.ToLower(strings.TrimSpace(f.Exploitability.VerifiedStatus)) {
		case "validated", "verified":
			signal += 0.2
		case "exploited", "impact_demonstrated", "submission_ready":
			signal += 0.3
		}
	}
	switch f.ProofState {
	case model.ProofStateValidated:
		signal += 0.2
	case model.ProofStateExploited, model.ProofStateImpactDemonstrated, model.ProofStateSubmissionReady:
		signal += 0.35
	}
	if len(f.ReproductionSteps) > 0 {
		signal += 0.12
	}
	if f.PoC != "" {
		signal += 0.14
	}
	if len(f.ProofArtifacts) > 0 {
		signal += 0.1
	}
	switch strings.ToLower(strings.TrimSpace(f.EvidenceQualityTier)) {
	case "high", "strong", "corroborated":
		signal += 0.14
	case "medium":
		signal += 0.06
	}
	return clamp(signal, 0, 1)
}

func hasUncertainLanguage(f model.Finding) bool {
	lower := strings.ToLower(strings.Join([]string{
		f.Title, f.Description, f.Evidence,
	}, " "))
	terms := []string{"potential", "possible", "likely", "suspected", "may indicate", "might be"}
	for _, term := range terms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

// probeSignalBatch is the JSON body sent to /v1/calibrate-probe-signals.
type probeSignalBatch struct {
	ProbeRecords []probeSignalRecord `json:"probeRecords"`
}

type probeSignalRecord struct {
	Category              string `json:"category"`
	Outcome               string `json:"outcome"`
	StatusCode            int    `json:"statusCode"`
	Endpoint              string `json:"endpoint"`
	// Phase 4 optional signals — backward-compatible with earlier
	// ml-service builds because Pydantic tolerates extra fields.
	EvidenceValid         bool   `json:"evidenceValid,omitempty"`
	DifferentialConfirmed bool   `json:"differentialConfirmed,omitempty"`
	SurfaceGapReason      string `json:"surfaceGapReason,omitempty"`
	OracleName            string `json:"oracleName,omitempty"`
	OracleVersion         string `json:"oracleVersion,omitempty"`
}

type calibrateResponse struct {
	Multipliers map[string]float64 `json:"multipliers"`
	Calibrated  bool               `json:"calibrated"`
}

// CalibrateProbeSignals sends the probe records from the current scan to the
// Python ml-service /v1/calibrate-probe-signals endpoint and updates the
// per-category confidence multipliers stored on the Service.
//
// Gated by the ML_CALIBRATE_PROBE_SIGNALS=true env var and a configured
// ExternalURL. If either is absent, the call is a no-op.
func (s *Service) CalibrateProbeSignals(ctx context.Context, records []model.ProbeRecord) {
	if os.Getenv("ML_CALIBRATE_PROBE_SIGNALS") != "true" {
		return
	}
	if s.externalURL == "" || len(records) == 0 {
		return
	}
	batch := probeSignalBatch{ProbeRecords: make([]probeSignalRecord, 0, len(records))}
	for _, r := range records {
		batch.ProbeRecords = append(batch.ProbeRecords, probeSignalRecord{
			Category:   r.Category,
			Outcome:    string(r.Outcome),
			StatusCode: r.StatusCode,
			Endpoint:   r.Endpoint,
		})
	}
	var resp calibrateResponse
	if !s.postJSON(ctx, "/v1/calibrate-probe-signals", batch, &resp) {
		return
	}
	if !resp.Calibrated || len(resp.Multipliers) == 0 {
		return
	}
	// Store multipliers so ScoreFindings can apply them without re-locking.
	s.calibrationMu.Lock()
	s.categoryCalibration = resp.Multipliers
	s.calibrationMu.Unlock()
}

// categoryCalibrationMultiplier returns the stored per-category calibration
// multiplier, clamped to [0.5, 1.5] so it cannot invert the confidence.
// Returns 1.0 (neutral) when no calibration data is available.
func (s *Service) categoryCalibrationMultiplier(category string) float64 {
	if s == nil {
		return 1.0
	}
	s.calibrationMu.RLock()
	m := s.categoryCalibration[strings.ToLower(strings.TrimSpace(category))]
	s.calibrationMu.RUnlock()
	if m <= 0 {
		return 1.0
	}
	if m < 0.5 {
		return 0.5
	}
	if m > 1.5 {
		return 1.5
	}
	return m
}

func (s *Service) postJSON(ctx context.Context, path string, payload any, out any) bool {
	if s.externalURL == "" || s.httpClient == nil {
		return false
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.externalURL+path, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	if s.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.authToken)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return false
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out) == nil
}
