package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// Screenshot is an inline visual evidence item that may be embedded in PDF or
// HTML reports. Data is the raw bytes of a PNG image (not base64-encoded);
// callers that have base64 strings should decode before passing them in.
type Screenshot struct {
	Caption   string
	AgentName string
	URL       string
	Timestamp string
	Data      []byte
}

// AttackPathStep is a single step in a chained attack-path narrative.
type AttackPathStep struct {
	Step     int
	Title    string
	Detail   string
	Severity model.Severity
}

// AttackPathNarrative renders the high-level "proof of impact" chain (akin to
// Horizon3 / NodeZero attack paths) that the report's Attack Paths section
// uses.
type AttackPathNarrative struct {
	Title  string
	Steps  []AttackPathStep
	Impact string
}

// RemediationPriority is one row in the prioritized "Fix Actions" table:
// remediation guidance ordered by severity-weighted impact reduction.
type RemediationPriority struct {
	Rank             int
	Recommendation   string
	HighestSeverity  model.Severity
	AffectedAssets   int
	AffectedFindings int
	Examples         []string // up to 3 finding titles
}

// AssetRollup groups findings by the asset they affect so a single owner can
// see everything that needs attention on one host or URL.
type AssetRollup struct {
	Asset          string
	HighCount      int
	MediumCount    int
	LowCount       int
	InfoCount      int
	FindingTitles  []string
	HighestSeverity model.Severity
}

// ComplianceMapping is a single CWE → control crosswalk entry.
type ComplianceMapping struct {
	FindingTitle string
	Severity     model.Severity
	CWE          string
	OWASP        string
	PCI          string
	HIPAA        string
	SOC2         string
}

// FindingsDelta describes how the current scan's findings compare to the
// previous completed scan against the same target.
type FindingsDelta struct {
	HasPrevious      bool
	PreviousScanID   string
	NewFindings      []model.Finding
	ResolvedFindings []model.Finding
	UnchangedCount   int
}

// MaxInlineScreenshots caps how many screenshots are embedded into a single
// report so that PDF/HTML output stays a manageable size.
const MaxInlineScreenshots = 12

// BuildAttackPathNarratives synthesises chained narratives from the scan's
// `Dashboard.TopAttackPaths` strings and the per-finding
// `Exploitability.AttackPathHints`. Each top-level path is grouped with the
// findings whose hints contain matching keywords to give a step-by-step
// "proof of impact" chain.
func BuildAttackPathNarratives(job *model.ScanJob, findings []model.Finding) []AttackPathNarrative {
	if job == nil {
		return nil
	}
	var paths []string
	if job.Dashboard != nil {
		paths = append(paths, job.Dashboard.TopAttackPaths...)
	}
	if len(paths) == 0 {
		return nil
	}

	// Precompute a flat list of (hint -> finding) pairs.
	type hintRef struct {
		hint    string
		finding model.Finding
	}
	hints := make([]hintRef, 0)
	for _, f := range findings {
		if f.Exploitability == nil {
			continue
		}
		for _, h := range f.Exploitability.AttackPathHints {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			hints = append(hints, hintRef{hint: h, finding: f})
		}
	}

	out := make([]AttackPathNarrative, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		nar := AttackPathNarrative{Title: p}
		// Each → / -> separated chunk becomes an explicit step.
		segments := splitChain(p)
		for i, seg := range segments {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			step := AttackPathStep{Step: i + 1, Title: seg}
			// Attach the highest-severity matching finding's detail when
			// the segment contains a hint keyword.
			highest := model.SeverityInfo
			details := []string{}
			segLower := strings.ToLower(seg)
			for _, hr := range hints {
				if strings.Contains(segLower, strings.ToLower(hr.hint)) ||
					strings.Contains(strings.ToLower(hr.finding.Title), segLower) {
					if severityRank(hr.finding.Severity) > severityRank(highest) {
						highest = hr.finding.Severity
					}
					if len(details) < 2 {
						details = append(details, hr.finding.Title)
					}
				}
			}
			step.Severity = highest
			step.Detail = strings.Join(details, "; ")
			nar.Steps = append(nar.Steps, step)
		}
		// Proven impact: if the chain ends in a HIGH-severity finding match,
		// surface that; otherwise fall back to the highest severity in the chain.
		highest := model.SeverityInfo
		for _, st := range nar.Steps {
			if severityRank(st.Severity) > severityRank(highest) {
				highest = st.Severity
			}
		}
		nar.Impact = "Proven impact: " + sevDisplay(highest) + " — " +
			"chain demonstrates real-world exploitability of one or more findings above."
		out = append(out, nar)
	}
	return out
}

// splitChain splits an attack-path string on the conventional separators used
// across the codebase (→, ->, »).
func splitChain(s string) []string {
	for _, sep := range []string{"→", "->", "»", "|"} {
		if strings.Contains(s, sep) {
			return strings.Split(s, sep)
		}
	}
	return []string{s}
}

// BuildRemediationPriorities groups findings by their (deduplicated)
// remediation recommendation and orders them by severity-weighted impact: the
// top of the list is what a defender should fix first to reduce the most risk.
func BuildRemediationPriorities(findings []model.Finding) []RemediationPriority {
	type bucket struct {
		recommendation  string
		highestSeverity model.Severity
		findings        []model.Finding
		assetSet        map[string]struct{}
	}
	buckets := map[string]*bucket{}
	order := []string{} // preserve first-seen order for stability

	for _, f := range findings {
		rec := strings.TrimSpace(f.Recommendation)
		if rec == "" {
			rec = "Investigate and remediate: " + f.Title
		}
		key := strings.ToLower(rec)
		b, ok := buckets[key]
		if !ok {
			b = &bucket{recommendation: rec, highestSeverity: f.Severity, assetSet: map[string]struct{}{}}
			buckets[key] = b
			order = append(order, key)
		}
		if severityRank(f.Severity) > severityRank(b.highestSeverity) {
			b.highestSeverity = f.Severity
		}
		b.findings = append(b.findings, f)
		asset := strings.TrimSpace(f.AffectedURL)
		if asset == "" {
			asset = "(unspecified)"
		}
		b.assetSet[asset] = struct{}{}
	}

	out := make([]RemediationPriority, 0, len(buckets))
	for _, key := range order {
		b := buckets[key]
		examples := make([]string, 0, 3)
		for i, f := range b.findings {
			if i >= 3 {
				break
			}
			examples = append(examples, f.Title)
		}
		out = append(out, RemediationPriority{
			Recommendation:   b.recommendation,
			HighestSeverity:  b.highestSeverity,
			AffectedAssets:   len(b.assetSet),
			AffectedFindings: len(b.findings),
			Examples:         examples,
		})
	}
	// Sort by severity desc, then by affected-finding count desc, then by
	// alphabetical recommendation for stability.
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].HighestSeverity) != severityRank(out[j].HighestSeverity) {
			return severityRank(out[i].HighestSeverity) > severityRank(out[j].HighestSeverity)
		}
		if out[i].AffectedFindings != out[j].AffectedFindings {
			return out[i].AffectedFindings > out[j].AffectedFindings
		}
		return out[i].Recommendation < out[j].Recommendation
	})
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// BuildAssetRollup pivots findings by the asset they affect (preferring the
// hostname for grouping so multiple URL paths on the same host roll up).
func BuildAssetRollup(findings []model.Finding, fallbackTarget string) []AssetRollup {
	rollups := map[string]*AssetRollup{}
	order := []string{}

	for _, f := range findings {
		asset := assetGroupKey(f, fallbackTarget)
		r, ok := rollups[asset]
		if !ok {
			r = &AssetRollup{Asset: asset, HighestSeverity: model.SeverityInfo}
			rollups[asset] = r
			order = append(order, asset)
		}
		switch f.Severity {
		case model.SeverityHigh:
			r.HighCount++
		case model.SeverityMedium:
			r.MediumCount++
		case model.SeverityLow:
			r.LowCount++
		default:
			r.InfoCount++
		}
		if severityRank(f.Severity) > severityRank(r.HighestSeverity) {
			r.HighestSeverity = f.Severity
		}
		if len(r.FindingTitles) < 5 {
			r.FindingTitles = append(r.FindingTitles, f.Title)
		}
	}

	out := make([]AssetRollup, 0, len(rollups))
	for _, k := range order {
		out = append(out, *rollups[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].HighestSeverity) != severityRank(out[j].HighestSeverity) {
			return severityRank(out[i].HighestSeverity) > severityRank(out[j].HighestSeverity)
		}
		ai := out[i].HighCount*1000 + out[i].MediumCount*100 + out[i].LowCount*10 + out[i].InfoCount
		aj := out[j].HighCount*1000 + out[j].MediumCount*100 + out[j].LowCount*10 + out[j].InfoCount
		if ai != aj {
			return ai > aj
		}
		return out[i].Asset < out[j].Asset
	})
	return out
}

// assetGroupKey returns the host portion of a finding's affected URL when
// available, falling back to the full URL or the scan target.
func assetGroupKey(f model.Finding, fallbackTarget string) string {
	raw := strings.TrimSpace(f.AffectedURL)
	if raw == "" {
		raw = fallbackTarget
	}
	if raw == "" {
		return "(unspecified)"
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// BuildComplianceMatrix maps each finding's CWE/OWASP into the corresponding
// PCI DSS, HIPAA, and SOC 2 control identifiers. The mapping is intentionally
// deterministic and conservative: when no mapping is known, the cell is left
// empty rather than guessed.
func BuildComplianceMatrix(findings []model.Finding) []ComplianceMapping {
	out := make([]ComplianceMapping, 0, len(findings))
	for _, f := range findings {
		out = append(out, ComplianceMapping{
			FindingTitle: f.Title,
			Severity:     f.Severity,
			CWE:          f.CWE,
			OWASP:        f.OWASPCategory,
			PCI:          pciControl(f.CWE),
			HIPAA:        hipaaControl(f.CWE),
			SOC2:         soc2Control(f.CWE),
		})
	}
	return out
}

// pciControl maps a CWE identifier to the most relevant PCI DSS v4.0
// requirement.
func pciControl(cwe string) string {
	switch strings.ToUpper(strings.TrimSpace(cwe)) {
	case "CWE-89", "CWE-79", "CWE-78", "CWE-94", "CWE-91":
		return "6.2.4 / 6.4.1 (secure software development & WAF)"
	case "CWE-22", "CWE-20":
		return "6.2.4 (input validation)"
	case "CWE-287", "CWE-306", "CWE-862", "CWE-863":
		return "8.2 / 8.3 (authentication & authorization)"
	case "CWE-200", "CWE-209":
		return "3.4 / 6.4.3 (data exposure)"
	case "CWE-352":
		return "6.2.4 (CSRF protections)"
	case "CWE-327", "CWE-326", "CWE-310":
		return "4.2 (strong cryptography in transit)"
	case "CWE-732":
		return "7.1 (least-privilege access)"
	case "CWE-918":
		return "1.4.4 (egress filtering)"
	}
	return ""
}

func hipaaControl(cwe string) string {
	switch strings.ToUpper(strings.TrimSpace(cwe)) {
	case "CWE-89", "CWE-79", "CWE-94", "CWE-78", "CWE-22":
		return "164.312(c)(1) Integrity"
	case "CWE-287", "CWE-306", "CWE-862", "CWE-863":
		return "164.312(d) Person/Entity Authentication"
	case "CWE-200", "CWE-209":
		return "164.312(a)(1) Access Control"
	case "CWE-327", "CWE-326", "CWE-310":
		return "164.312(e)(1) Transmission Security"
	case "CWE-732":
		return "164.308(a)(4) Information Access Management"
	case "CWE-918":
		return "164.312(a)(1) Access Control"
	}
	return ""
}

func soc2Control(cwe string) string {
	switch strings.ToUpper(strings.TrimSpace(cwe)) {
	case "CWE-89", "CWE-79", "CWE-94", "CWE-78", "CWE-22", "CWE-352":
		return "CC6.6 / CC7.1 (secure SDLC)"
	case "CWE-287", "CWE-306", "CWE-862", "CWE-863":
		return "CC6.1 (logical access)"
	case "CWE-200", "CWE-209":
		return "CC6.7 (data confidentiality)"
	case "CWE-327", "CWE-326", "CWE-310":
		return "CC6.7 (encryption in transit)"
	case "CWE-732":
		return "CC6.3 (least privilege)"
	case "CWE-918":
		return "CC6.6 (perimeter protections)"
	}
	return ""
}

// BuildFindingsDelta compares the current set of findings against the
// findings of a previous job for the same target. Two findings are considered
// "the same" when they share an ID; otherwise the title+category fingerprint
// is used.
func BuildFindingsDelta(current []model.Finding, previous *model.ScanJob) FindingsDelta {
	if previous == nil || (len(previous.Findings) == 0 && previous.ID == "") {
		return FindingsDelta{}
	}
	delta := FindingsDelta{HasPrevious: true, PreviousScanID: previous.ID}

	prevByKey := map[string]model.Finding{}
	for _, f := range previous.Findings {
		prevByKey[findingFingerprint(f)] = f
	}
	curByKey := map[string]model.Finding{}
	for _, f := range current {
		curByKey[findingFingerprint(f)] = f
	}

	for k, f := range curByKey {
		if _, ok := prevByKey[k]; !ok {
			delta.NewFindings = append(delta.NewFindings, f)
		} else {
			delta.UnchangedCount++
		}
	}
	for k, f := range prevByKey {
		if _, ok := curByKey[k]; !ok {
			delta.ResolvedFindings = append(delta.ResolvedFindings, f)
		}
	}
	sort.SliceStable(delta.NewFindings, func(i, j int) bool {
		return severityRank(delta.NewFindings[i].Severity) > severityRank(delta.NewFindings[j].Severity)
	})
	sort.SliceStable(delta.ResolvedFindings, func(i, j int) bool {
		return severityRank(delta.ResolvedFindings[i].Severity) > severityRank(delta.ResolvedFindings[j].Severity)
	})
	return delta
}

func findingFingerprint(f model.Finding) string {
	if strings.TrimSpace(f.ID) != "" {
		return "id:" + f.ID
	}
	return "fp:" + strings.ToLower(strings.TrimSpace(f.Category)+"|"+strings.TrimSpace(f.Title))
}

// severityRank gives an integer rank to severities so that they can be sorted
// or compared (CRITICAL is largest, INFO is smallest).
func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	}
	return 0
}

// ComputeContentHash returns a deterministic SHA-256 of the report data
// content. The hash deliberately excludes the GeneratedAt timestamp so that
// the same scan rendered twice produces the same hash, allowing reviewers to
// confirm that two PDF/MD/HTML deliverables came from the same underlying
// data.
func ComputeContentHash(data PentestReportData) string {
	type stable struct {
		Title          string                       `json:"title"`
		Options        model.ReportTemplateOptions  `json:"options"`
		Findings       []model.Finding              `json:"findings"`
		SeverityCounts map[model.Severity]int       `json:"severityCounts"`
		ToolsUsed      []string                     `json:"toolsUsed"`
		CommandsUsed   []string                     `json:"commandsUsed"`
		Assets         []model.ScanAsset            `json:"assets"`
		AttackPaths    []AttackPathNarrative        `json:"attackPaths,omitempty"`
		Priorities     []RemediationPriority        `json:"priorities,omitempty"`
		AssetRollup    []AssetRollup                `json:"assetRollup,omitempty"`
		Compliance     []ComplianceMapping          `json:"compliance,omitempty"`
		Delta          FindingsDelta                `json:"delta,omitempty"`
		ScreenshotKeys []string                     `json:"screenshotKeys,omitempty"`
		JobID          string                       `json:"jobId,omitempty"`
		Target         string                       `json:"target,omitempty"`
	}
	s := stable{
		Title:          data.Title,
		Options:        data.Options,
		Findings:       data.Findings,
		SeverityCounts: data.SeverityCounts,
		ToolsUsed:      data.ToolsUsed,
		CommandsUsed:   data.CommandsUsed,
		Assets:         data.AssetsDiscovered,
		AttackPaths:    data.AttackPaths,
		Priorities:     data.RemediationPriorities,
		AssetRollup:    data.AssetRollup,
		Compliance:     data.ComplianceMatrix,
		Delta:          data.Delta,
	}
	if data.Job != nil {
		s.JobID = data.Job.ID
		s.Target = data.Job.Target
	}
	for _, sh := range data.Screenshots {
		s.ScreenshotKeys = append(s.ScreenshotKeys, fmt.Sprintf("%s|%s|%d", sh.URL, sh.Caption, len(sh.Data)))
	}

	buf, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of stable types should never fail; degrade safely.
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}
