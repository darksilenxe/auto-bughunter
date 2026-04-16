package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

type Config struct {
	ExternalURL string
	Timeout     time.Duration
}

type Service struct {
	externalURL string
	httpClient  *http.Client
}

type ScoredFinding struct {
	Finding        model.Finding
	Score          float64
	Confidence     float64
	Exploitability string
}

func NewService(cfg Config) *Service {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Service{
		externalURL: strings.TrimRight(strings.TrimSpace(cfg.ExternalURL), "/"),
		httpClient:  &http.Client{Timeout: timeout},
	}
}

func (s *Service) ScoreFindings(findings []model.Finding) []ScoredFinding {
	if scored, ok := s.scoreFindingsExternal(findings); ok {
		return scored
	}

	scored := make([]ScoredFinding, 0, len(findings))
	for _, f := range findings {
		base := severityBase(f.Severity)
		text := strings.ToLower(strings.TrimSpace(f.Title + " " + f.Description + " " + f.Evidence))

		boost := 0.0
		for keyword, weight := range keywordWeights() {
			if strings.Contains(text, keyword) {
				boost += weight
			}
		}
		catBoost := categoryWeight(f.Category)
		score := clamp01(base + boost + catBoost)

		confidence := clamp01(0.45 + score*0.45)
		exploitability := exploitabilityFromScore(score)

		scored = append(scored, ScoredFinding{
			Finding:        f,
			Score:          round2(score),
			Confidence:     round2(confidence),
			Exploitability: exploitability,
		})
	}

	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		if scored[i].Confidence != scored[j].Confidence {
			return scored[i].Confidence > scored[j].Confidence
		}
		return scored[i].Finding.Title < scored[j].Finding.Title
	})

	return scored
}

func (s *Service) BuildAttackPaths(findings []model.Finding) []string {
	if paths, ok := s.attackPathsExternal(findings); ok {
		return paths
	}

	if len(findings) == 0 {
		return nil
	}

	cats := map[string]struct{}{}
	for _, f := range findings {
		c := strings.ToLower(strings.TrimSpace(f.Category))
		if c == "" {
			continue
		}
		cats[c] = struct{}{}
	}

	paths := make([]string, 0, 4)
	if hasAny(cats, "information_disclosure", "reconnaissance", "wordlist") && hasAny(cats, "access_control", "api_security") {
		paths = append(paths, "Service discovery can expose sensitive endpoints, then weak access control may allow unauthorized data access.")
	}
	if hasAny(cats, "input_validation") && hasAny(cats, "api_security", "access_control") {
		paths = append(paths, "Input validation weaknesses can be chained with API authorization gaps to move from probing to account-level compromise.")
	}
	if hasAny(cats, "cors_redirect", "api_security") && hasAny(cats, "access_control") {
		paths = append(paths, "Permissive CORS or open redirects can assist token/session abuse when access-control checks are weak.")
	}
	if hasAny(cats, "headers", "scanning", "tls") {
		paths = append(paths, "Transport and header weaknesses can increase exploit reliability for higher-risk application flaws.")
	}

	if len(paths) == 0 {
		paths = append(paths, "No high-confidence multi-step attack chain inferred from current findings; focus on top-severity remediations first.")
	}
	if len(paths) > 3 {
		paths = paths[:3]
	}
	return paths
}

func (s *Service) BuildRemediationPlan(findings []model.Finding, limit int) []string {
	if plan, ok := s.remediationPlanExternal(findings, limit); ok {
		return plan
	}

	if limit <= 0 {
		limit = 5
	}
	if len(findings) == 0 {
		return []string{"Maintain hardening baseline and rerun scans periodically."}
	}

	scored := s.ScoreFindings(findings)
	plan := make([]string, 0, limit)
	seen := map[string]struct{}{}

	for _, sf := range scored {
		step := strings.TrimSpace(sf.Finding.Recommendation)
		if step == "" {
			continue
		}
		norm := strings.ToLower(step)
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		plan = append(plan, fmt.Sprintf("%s (from: %s)", compact(step), compact(sf.Finding.Title)))
		if len(plan) == limit {
			break
		}
	}

	if len(plan) == 0 {
		plan = append(plan, "Triage and fix high severity findings first, then medium severity findings with internet exposure.")
	}
	return plan
}

func (s *Service) FindPotentialFalsePositives(findings []model.Finding) []ScoredFinding {
	if candidates, ok := s.falsePositiveCandidatesExternal(findings); ok {
		return candidates
	}

	scored := s.ScoreFindings(findings)
	out := make([]ScoredFinding, 0)
	for _, sf := range scored {
		if sf.Confidence <= 0.55 {
			out = append(out, sf)
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func severityBase(sev model.Severity) float64 {
	switch sev {
	case model.SeverityHigh:
		return 0.75
	case model.SeverityMedium:
		return 0.55
	case model.SeverityLow:
		return 0.35
	default:
		return 0.2
	}
}

func keywordWeights() map[string]float64 {
	return map[string]float64{
		"sql":            0.15,
		"xss":            0.15,
		"idor":           0.2,
		"auth":           0.12,
		"token":          0.1,
		"session":        0.1,
		"admin":          0.1,
		"disclosure":     0.08,
		"graphql":        0.08,
		"credentials":    0.15,
		"injection":      0.15,
		"path traversal": 0.18,
	}
}

func categoryWeight(category string) float64 {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "access_control", "input_validation", "api_security":
		return 0.15
	case "information_disclosure", "cors_redirect":
		return 0.08
	default:
		return 0.03
	}
}

func exploitabilityFromScore(score float64) string {
	if score >= 0.8 {
		return "high"
	}
	if score >= 0.6 {
		return "medium"
	}
	return "low"
}

func hasAny(set map[string]struct{}, values ...string) bool {
	for _, v := range values {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func compact(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

func (s *Service) scoreFindingsExternal(findings []model.Finding) ([]ScoredFinding, bool) {
	if s.externalURL == "" {
		return nil, false
	}

	var resp struct {
		ScoredFindings []ScoredFinding `json:"scoredFindings"`
	}
	ok := s.postJSON("/v1/score-findings", map[string]any{"findings": findings}, &resp)
	if !ok || len(resp.ScoredFindings) == 0 {
		return nil, false
	}
	return resp.ScoredFindings, true
}

func (s *Service) attackPathsExternal(findings []model.Finding) ([]string, bool) {
	if s.externalURL == "" {
		return nil, false
	}

	var resp struct {
		AttackPaths []string `json:"attackPaths"`
	}
	ok := s.postJSON("/v1/attack-paths", map[string]any{"findings": findings}, &resp)
	if !ok || len(resp.AttackPaths) == 0 {
		return nil, false
	}
	return resp.AttackPaths, true
}

func (s *Service) remediationPlanExternal(findings []model.Finding, limit int) ([]string, bool) {
	if s.externalURL == "" {
		return nil, false
	}

	var resp struct {
		RemediationPlan []string `json:"remediationPlan"`
	}
	ok := s.postJSON("/v1/remediation-plan", map[string]any{"findings": findings, "limit": limit}, &resp)
	if !ok || len(resp.RemediationPlan) == 0 {
		return nil, false
	}
	return resp.RemediationPlan, true
}

func (s *Service) falsePositiveCandidatesExternal(findings []model.Finding) ([]ScoredFinding, bool) {
	if s.externalURL == "" {
		return nil, false
	}

	var resp struct {
		Candidates []ScoredFinding `json:"candidates"`
	}
	ok := s.postJSON("/v1/false-positive-candidates", map[string]any{"findings": findings}, &resp)
	if !ok {
		return nil, false
	}
	return resp.Candidates, true
}

func (s *Service) postJSON(path string, payload any, out any) bool {
	if s.externalURL == "" {
		return false
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.httpClient.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.externalURL+path, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return false
	}
	return true
}
