package impact

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Playbook struct {
	Name    string
	Goal    model.ImpactGoal
	Summary string
}

var playbooks = []Playbook{
	{Name: "ato-via-auth-or-oauth", Goal: model.ImpactGoalAccountTakeover, Summary: "Account takeover via auth bypass, token theft, or OAuth redirect abuse."},
	{Name: "idor-to-cross-account-data", Goal: model.ImpactGoalCrossTenantAccess, Summary: "Cross-account or cross-tenant object access and data extraction."},
	{Name: "payment-abuse-and-order-manipulation", Goal: model.ImpactGoalPaymentAbuse, Summary: "Coupon, checkout, credit, or invoice abuse with direct financial impact."},
	{Name: "stored-xss-session-abuse", Goal: model.ImpactGoalStoredXSS, Summary: "Stored XSS used for victim actioning, token theft, or admin session abuse."},
	{Name: "ssrf-to-internal-or-metadata-access", Goal: model.ImpactGoalSSRFInternalAccess, Summary: "SSRF to cloud metadata, internal services, or privileged control planes."},
	{Name: "tenant-breakout-or-admin-action", Goal: model.ImpactGoalTenantBreakout, Summary: "Privilege escalation or tenant breakout causing unauthorized admin actions."},
}

var impactLabelCaser = cases.Title(language.Und)

func DefaultGoals() []model.ImpactGoal {
	return []model.ImpactGoal{
		model.ImpactGoalAccountTakeover,
		model.ImpactGoalCrossTenantAccess,
		model.ImpactGoalSensitiveDataExposure,
		model.ImpactGoalPaymentAbuse,
		model.ImpactGoalAuthBypass,
		model.ImpactGoalStoredXSS,
	}
}

func GoalsOrDefault(opts model.ScanOptions) []model.ImpactGoal {
	if len(opts.ImpactGoals) == 0 {
		return append([]model.ImpactGoal(nil), DefaultGoals()...)
	}
	out := make([]model.ImpactGoal, 0, len(opts.ImpactGoals))
	seen := map[model.ImpactGoal]struct{}{}
	for _, goal := range opts.ImpactGoals {
		goal = model.ImpactGoal(strings.TrimSpace(string(goal)))
		if goal == "" {
			continue
		}
		if _, ok := seen[goal]; ok {
			continue
		}
		seen[goal] = struct{}{}
		out = append(out, goal)
	}
	if len(out) == 0 {
		return append([]model.ImpactGoal(nil), DefaultGoals()...)
	}
	return out
}

func GoalPrompt(goals []model.ImpactGoal) string {
	if len(goals) == 0 {
		goals = DefaultGoals()
	}
	names := make([]string, 0, len(goals))
	for _, goal := range goals {
		names = append(names, strings.ReplaceAll(string(goal), "_", " "))
	}
	return strings.Join(names, ", ")
}

func PlaybookPrompt(goals []model.ImpactGoal) string {
	matched := MatchingPlaybooks(goals)
	if len(matched) == 0 {
		return ""
	}
	lines := make([]string, 0, len(matched))
	for _, pb := range matched {
		lines = append(lines, pb.Name+": "+pb.Summary)
	}
	return strings.Join(lines, " | ")
}

func MatchingPlaybooks(goals []model.ImpactGoal) []Playbook {
	if len(goals) == 0 {
		goals = DefaultGoals()
	}
	goalSet := map[model.ImpactGoal]struct{}{}
	for _, goal := range goals {
		goalSet[goal] = struct{}{}
	}
	out := make([]Playbook, 0, len(playbooks))
	for _, pb := range playbooks {
		if _, ok := goalSet[pb.Goal]; ok {
			out = append(out, pb)
		}
	}
	return out
}

func EnrichFinding(f model.Finding, goals []model.ImpactGoal) model.Finding {
	goals = GoalsOrDefault(model.ScanOptions{ImpactGoals: goals})
	matchedGoals := matchedGoalsForFinding(f, goals)
	if len(f.ImpactGoals) == 0 {
		f.ImpactGoals = matchedGoals
	} else {
		f.ImpactGoals = dedupeGoals(append(f.ImpactGoals, matchedGoals...))
	}
	f.ProofArtifacts = mergeArtifacts(f.ProofArtifacts, deriveArtifacts(f))
	f.ImpactScore = MaxFloat(f.ImpactScore, scoreImpact(f, matchedGoals))
	f.BountyScore = MaxFloat(f.BountyScore, scoreBounty(f, matchedGoals))
	f.ProofState = maxProofState(f.ProofState, deriveProofState(f))
	if strings.TrimSpace(f.Impact) == "" {
		f.Impact = deriveImpactNarrative(f, matchedGoals)
	}
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	if len(f.ImpactGoals) > 0 {
		f.EvidenceFields["impactGoals"] = joinGoals(f.ImpactGoals)
	}
	if f.ProofState != "" {
		f.EvidenceFields["proofState"] = string(f.ProofState)
	}
	if f.ImpactScore > 0 {
		f.EvidenceFields["impactScore"] = fmt.Sprintf("%.2f", f.ImpactScore)
	}
	if f.BountyScore > 0 {
		f.EvidenceFields["bountyScore"] = fmt.Sprintf("%.2f", f.BountyScore)
	}
	playbookNames := suggestedPlaybooks(f.ImpactGoals)
	if len(playbookNames) > 0 {
		f.BusinessTags = appendStringUnique(f.BusinessTags, playbookNames...)
		f.EvidenceFields["impactPlaybooks"] = strings.Join(playbookNames, ",")
	}
	return f
}

func RankFindings(findings []model.Finding, goals []model.ImpactGoal) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, EnrichFinding(f, goals))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].BountyScore != out[j].BountyScore {
			return out[i].BountyScore > out[j].BountyScore
		}
		if out[i].ImpactScore != out[j].ImpactScore {
			return out[i].ImpactScore > out[j].ImpactScore
		}
		if severityWeight(out[i].Severity) != severityWeight(out[j].Severity) {
			return severityWeight(out[i].Severity) > severityWeight(out[j].Severity)
		}
		return out[i].Confidence > out[j].Confidence
	})
	return out
}

func ShouldStopForDemonstratedImpact(findings []model.Finding, goals []model.ImpactGoal) (bool, string) {
	for _, f := range findings {
		enriched := EnrichFinding(f, goals)
		if enriched.ProofState == model.ProofStateImpactDemonstrated || enriched.ProofState == model.ProofStateSubmissionReady {
			if enriched.BountyScore >= 0.80 || enriched.ImpactScore >= 0.85 {
				return true, fmt.Sprintf("impact already demonstrated by %q (%s, bounty %.2f)", enriched.Title, enriched.ProofState, enriched.BountyScore)
			}
		}
	}
	return false, ""
}

func BuildSubmissionAttachments(f model.Finding) []string {
	attachments := make([]string, 0, len(f.ProofArtifacts))
	for _, artifact := range f.ProofArtifacts {
		label := strings.TrimSpace(artifact.Label)
		if label == "" {
			label = strings.TrimSpace(artifact.Type)
		}
		if label == "" {
			continue
		}
		if artifact.Value != "" {
			attachments = append(attachments, label+": "+artifact.Value)
			continue
		}
		attachments = append(attachments, label)
	}
	return dedupeStrings(attachments)
}

func scoreImpact(f model.Finding, goals []model.ImpactGoal) float64 {
	score := 0.15
	switch f.Severity {
	case model.SeverityHigh:
		score += 0.28
	case model.SeverityMedium:
		score += 0.18
	case model.SeverityLow:
		score += 0.08
	}
	score += clamp01(f.Confidence) * 0.15
	if strings.TrimSpace(f.Impact) != "" {
		score += 0.12
	}
	if len(f.ReproductionSteps) >= 2 {
		score += 0.08
	}
	if strings.TrimSpace(f.PoC) != "" {
		score += 0.07
	}
	if strings.TrimSpace(f.Evidence) != "" {
		score += 0.05
	}
	if f.Exploitability != nil {
		if f.Exploitability.Reachable {
			score += 0.08
		}
		switch strings.ToLower(strings.TrimSpace(f.Exploitability.VerifiedStatus)) {
		case "verified":
			score += 0.12
		case "demonstrated", "confirmed":
			score += 0.20
		}
	}
	score += float64(len(deriveArtifacts(f))) * 0.03
	for _, goal := range matchedGoalsForFinding(f, goals) {
		switch goal {
		case model.ImpactGoalAccountTakeover, model.ImpactGoalTenantBreakout, model.ImpactGoalPaymentAbuse:
			score += 0.08
		case model.ImpactGoalCrossTenantAccess, model.ImpactGoalSensitiveDataExposure, model.ImpactGoalAuthBypass:
			score += 0.06
		default:
			score += 0.04
		}
	}
	return clamp01(score)
}

func scoreBounty(f model.Finding, goals []model.ImpactGoal) float64 {
	score := scoreImpact(f, goals) * 0.65
	if strings.Contains(strings.ToLower(f.Category), "access") || strings.Contains(strings.ToLower(f.Category), "auth") {
		score += 0.08
	}
	if strings.Contains(strings.ToLower(f.Title), "cross-account") || strings.Contains(strings.ToLower(f.Title), "tenant") {
		score += 0.08
	}
	if strings.Contains(strings.ToLower(f.Title), "admin") || strings.Contains(strings.ToLower(f.Impact), "admin") {
		score += 0.06
	}
	if f.ProofState == model.ProofStateImpactDemonstrated {
		score += 0.10
	}
	if f.ProofState == model.ProofStateSubmissionReady {
		score += 0.15
	}
	return clamp01(score)
}

func deriveProofState(f model.Finding) model.ProofState {
	if f.ProofState != "" {
		return f.ProofState
	}
	artifacts := deriveArtifacts(f)
	verified := ""
	if f.Exploitability != nil {
		verified = strings.ToLower(strings.TrimSpace(f.Exploitability.VerifiedStatus))
	}
	impactText := strings.ToLower(strings.TrimSpace(f.Impact + " " + f.Title + " " + strings.Join(f.BusinessTags, " ")))
	switch {
	case (verified == "demonstrated" || verified == "confirmed") && len(artifacts) >= 2 && len(f.ReproductionSteps) >= 2:
		if strings.TrimSpace(f.PoC) != "" || strings.TrimSpace(f.Evidence) != "" {
			return model.ProofStateSubmissionReady
		}
		return model.ProofStateImpactDemonstrated
	case strings.Contains(impactText, "account takeover") || strings.Contains(impactText, "cross-account") ||
		strings.Contains(impactText, "cross-tenant") || strings.Contains(impactText, "payment abuse") ||
		strings.Contains(impactText, "tenant breakout") || strings.Contains(impactText, "admin action"):
		if len(artifacts) >= 2 || verified == "verified" {
			return model.ProofStateImpactDemonstrated
		}
	case strings.TrimSpace(f.PoC) != "" && len(f.ReproductionSteps) >= 2:
		return model.ProofStateExploited
	case verified == "verified" || (f.Exploitability != nil && f.Exploitability.Reachable) || len(artifacts) >= 1:
		return model.ProofStateValidated
	}
	return model.ProofStateSuspected
}

func deriveImpactNarrative(f model.Finding, goals []model.ImpactGoal) string {
	if len(goals) == 0 {
		goals = matchedGoalsForFinding(f, DefaultGoals())
	}
	if len(goals) == 0 {
		return ""
	}
	asset := strings.TrimSpace(f.AffectedURL)
	if asset == "" {
		asset = "the affected asset"
	}
	goalText := strings.ReplaceAll(string(goals[0]), "_", " ")
	return fmt.Sprintf("Evidence suggests %s against %s, with bug-bounty relevance driven by the verified attack path and captured proof artifacts.", goalText, asset)
}

func matchedGoalsForFinding(f model.Finding, goals []model.ImpactGoal) []model.ImpactGoal {
	text := strings.ToLower(strings.Join([]string{
		f.Category,
		f.Title,
		f.Description,
		f.Evidence,
		f.Impact,
		strings.Join(f.BusinessTags, " "),
	}, " "))
	out := make([]model.ImpactGoal, 0, len(goals))
	for _, goal := range goals {
		switch goal {
		case model.ImpactGoalAccountTakeover:
			if containsAny(text, "oauth", "account takeover", "session hijack", "token theft", "jwt", "password reset", "auth bypass") {
				out = append(out, goal)
			}
		case model.ImpactGoalCrossTenantAccess:
			if containsAny(text, "idor", "bola", "cross-account", "cross tenant", "cross-tenant", "tenant data", "unauthorized invoice", "object-level") {
				out = append(out, goal)
			}
		case model.ImpactGoalSensitiveDataExposure:
			if containsAny(text, "sqli", "pii", "phi", "data exfil", "metadata", "credential", "secret", "exposure") {
				out = append(out, goal)
			}
		case model.ImpactGoalPaymentAbuse:
			if containsAny(text, "payment", "checkout", "invoice", "coupon", "credit", "refund", "pricing") {
				out = append(out, goal)
			}
		case model.ImpactGoalAuthBypass:
			if containsAny(text, "auth", "authentication", "authorization", "jwt", "session", "token", "bypass") {
				out = append(out, goal)
			}
		case model.ImpactGoalStoredXSS:
			if containsAny(text, "stored xss", "persistent xss", "cross-site scripting", "xss") {
				out = append(out, goal)
			}
		case model.ImpactGoalSSRFInternalAccess:
			if containsAny(text, "ssrf", "169.254.169.254", "metadata", "internal service", "server-side request forgery") {
				out = append(out, goal)
			}
		case model.ImpactGoalTenantBreakout:
			if containsAny(text, "tenant breakout", "tenant escape", "admin action", "privilege escalation", "cross-tenant admin") {
				out = append(out, goal)
			}
		}
	}
	return dedupeGoals(out)
}

func suggestedPlaybooks(goals []model.ImpactGoal) []string {
	goalSet := map[model.ImpactGoal]struct{}{}
	for _, goal := range goals {
		goalSet[goal] = struct{}{}
	}
	out := make([]string, 0, len(goals))
	for _, pb := range playbooks {
		if _, ok := goalSet[pb.Goal]; ok {
			out = append(out, "playbook:"+pb.Name)
		}
	}
	return out
}

func deriveArtifacts(f model.Finding) []model.ProofArtifact {
	out := make([]model.ProofArtifact, 0, 8)
	if strings.TrimSpace(f.Evidence) != "" {
		out = append(out, model.ProofArtifact{Type: "evidence", Label: "Raw evidence", Value: truncate(strings.TrimSpace(f.Evidence), 180)})
	}
	if strings.TrimSpace(f.PoC) != "" {
		out = append(out, model.ProofArtifact{Type: "poc", Label: "Proof of concept", Value: truncate(strings.TrimSpace(f.PoC), 180)})
	}
	if strings.TrimSpace(f.AffectedURL) != "" {
		out = append(out, model.ProofArtifact{Type: "request-target", Label: "Affected URL", Value: f.AffectedURL})
	}
	if strings.TrimSpace(f.AffectedParameter) != "" {
		out = append(out, model.ProofArtifact{Type: "parameter", Label: "Affected parameter", Value: f.AffectedParameter})
	}
	if curl := strings.TrimSpace(f.EvidenceFields["curlReproducer"]); curl != "" {
		out = append(out, model.ProofArtifact{Type: "curl", Label: "Curl reproducer", Value: truncate(curl, 180)})
	}
	for _, key := range []string{"beforeRole", "afterRole", "roleDiff", "ownershipMismatch", "responseDiff", "recordCount", "screenshotPath"} {
		if value := strings.TrimSpace(f.EvidenceFields[key]); value != "" {
			out = append(out, model.ProofArtifact{Type: key, Label: prettyLabel(key), Value: truncate(value, 180)})
		}
	}
	return dedupeArtifacts(out)
}

func mergeArtifacts(existing, derived []model.ProofArtifact) []model.ProofArtifact {
	return dedupeArtifacts(append(existing, derived...))
}

func dedupeArtifacts(in []model.ProofArtifact) []model.ProofArtifact {
	out := make([]model.ProofArtifact, 0, len(in))
	seen := map[string]struct{}{}
	for _, artifact := range in {
		key := artifact.Type + "|" + artifact.Label + "|" + artifact.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, artifact)
	}
	return out
}

func dedupeGoals(in []model.ImpactGoal) []model.ImpactGoal {
	out := make([]model.ImpactGoal, 0, len(in))
	seen := map[model.ImpactGoal]struct{}{}
	for _, goal := range in {
		if goal == "" {
			continue
		}
		if _, ok := seen[goal]; ok {
			continue
		}
		seen[goal] = struct{}{}
		out = append(out, goal)
	}
	return out
}

func prettyLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")
	return impactLabelCaser.String(strings.ToLower(strings.Join(strings.Fields(s), " ")))
}

func joinGoals(goals []model.ImpactGoal) string {
	parts := make([]string, 0, len(goals))
	for _, goal := range goals {
		parts = append(parts, string(goal))
	}
	return strings.Join(parts, ",")
}

func maxProofState(a, b model.ProofState) model.ProofState {
	if proofRank(b) > proofRank(a) {
		return b
	}
	return a
}

func proofRank(s model.ProofState) int {
	switch s {
	case model.ProofStateSubmissionReady:
		return 5
	case model.ProofStateImpactDemonstrated:
		return 4
	case model.ProofStateExploited:
		return 3
	case model.ProofStateValidated:
		return 2
	case model.ProofStateSuspected:
		return 1
	default:
		return 0
	}
}

func severityWeight(s model.Severity) int {
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

func appendStringUnique(dst []string, values ...string) []string {
	return dedupeStrings(append(dst, values...))
}

func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func containsAny(text string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(text, value) {
			return true
		}
	}
	return false
}

func MaxFloat(a, b float64) float64 {
	if b > a {
		return b
	}
	return a
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
