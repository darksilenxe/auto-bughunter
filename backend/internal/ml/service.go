package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
)

type Repository interface {
	ListCompletedJobs(ctx context.Context, limit int) ([]*model.ScanJob, error)
	GetAssetsByScanID(ctx context.Context, scanID string) ([]model.ScanAsset, error)
	ListAuditEvents(ctx context.Context, scanID string) ([]model.ScanAuditEvent, error)
}

type ProxyStore interface {
	ListProxyRequests(ctx context.Context) ([]*model.ProxyRequest, error)
}

type Config struct {
	PseudonymSalt string
}

type Service struct {
	salt string
}

func NewService(cfg Config) *Service {
	salt := strings.TrimSpace(cfg.PseudonymSalt)
	if salt == "" {
		salt = "auto-bughunter"
	}
	return &Service{salt: salt}
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
	Dashboard       *model.DecisionDashboard `json:"dashboard,omitempty"`
	NextActions     []string                 `json:"nextActions,omitempty"`
	AutomatedReport string                   `json:"automatedReport,omitempty"`
	Labels          EngagementLabels         `json:"labels"`
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
	out := &EngagementDataset{Records: make([]EngagementRecord, 0, len(jobs))}
	for _, job := range jobs {
		if job == nil {
			continue
		}
		record, err := s.buildRecord(ctx, repo, job, proxySignalsByHost[hostOf(job.Target)])
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
	recs := &model.ModelRecommendations{
		ToolSelection:       recommendTools(dataset.Records),
		PrioritizedFindings: prioritizeFindings(job.Findings),
		Copilot:             buildCopilotSuggestion(job, dataset.Records),
		ModelMode:           "historical-deterministic",
	}
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
		PrioritizedFindings: prioritizeFindings(job.Findings),
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

func prioritizeFindings(findings []model.Finding) []model.PrioritizedFinding {
	out := make([]model.PrioritizedFinding, 0, len(findings))
	for _, f := range findings {
		score := scoreFinding(f)
		out = append(out, model.PrioritizedFinding{
			FindingID: f.ID,
			Title:     f.Title,
			Severity:  f.Severity,
			Score:     round2(score),
			Reason:    priorityReason(f, score),
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

func buildCopilotSuggestion(job *model.ScanJob, history []EngagementRecord) model.EngagementCopilotSuggestion {
	topFindings := prioritizeFindings(job.Findings)
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

func (s *Service) buildRecord(ctx context.Context, repo Repository, job *model.ScanJob, proxySignals []ProxySignal) (EngagementRecord, error) {
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
	base := 0.35 + (severityWeight(f.Severity) * 0.15)
	base += min(0.35, max(0, f.Confidence)*0.35)
	if f.Exploitability != nil && f.Exploitability.Reachable {
		base += 0.07
	}
	switch strings.ToLower(strings.TrimSpace(f.DriftStatus)) {
	case "new":
		base += 0.08
	case "changed":
		base += 0.04
	case "resolved":
		base -= 0.08
	}
	return clamp(base, 0, 1)
}

func priorityReason(f model.Finding, score float64) string {
	parts := []string{
		"severity=" + string(f.Severity),
		"confidence=" + strconv.FormatFloat(f.Confidence, 'f', 2, 64),
		"drift=" + strings.TrimSpace(f.DriftStatus),
	}
	if f.Exploitability != nil && f.Exploitability.Reachable {
		parts = append(parts, "reachable=true")
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
