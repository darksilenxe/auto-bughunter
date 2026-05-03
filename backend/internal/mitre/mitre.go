// Package mitre maps internal finding categories and CWE identifiers to
// MITRE ATT&CK technique IDs (https://attack.mitre.org/) so that reports and
// dashboards can present a deterministic ATT&CK view of scan results.
//
// The mapping is intentionally small and conservative: only techniques that
// are unambiguously associated with the corresponding web/bug-bounty finding
// category are included. The same finding may legitimately map to several
// techniques (e.g. SQL injection → T1190 Exploit Public-Facing Application
// and T1059 Command and Scripting Interpreter via stacked queries).
package mitre

import (
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// Technique describes a single MITRE ATT&CK technique referenced by this
// package. Name and Tactic are kept here so renderers do not need a separate
// lookup table.
type Technique struct {
	ID     string
	Name   string
	Tactic string
	URL    string
}

// catalog is the canonical list of techniques this package can emit. Keeping
// it sorted by ID makes regenerated reports byte-identical.
var catalog = map[string]Technique{
	"T1190":     {ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access", URL: "https://attack.mitre.org/techniques/T1190/"},
	"T1059":     {ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", URL: "https://attack.mitre.org/techniques/T1059/"},
	"T1059.007": {ID: "T1059.007", Name: "Command and Scripting Interpreter: JavaScript", Tactic: "Execution", URL: "https://attack.mitre.org/techniques/T1059/007/"},
	"T1505.003": {ID: "T1505.003", Name: "Server Software Component: Web Shell", Tactic: "Persistence", URL: "https://attack.mitre.org/techniques/T1505/003/"},
	"T1539":     {ID: "T1539", Name: "Steal Web Session Cookie", Tactic: "Credential Access", URL: "https://attack.mitre.org/techniques/T1539/"},
	"T1552":     {ID: "T1552", Name: "Unsecured Credentials", Tactic: "Credential Access", URL: "https://attack.mitre.org/techniques/T1552/"},
	"T1552.001": {ID: "T1552.001", Name: "Unsecured Credentials: Credentials In Files", Tactic: "Credential Access", URL: "https://attack.mitre.org/techniques/T1552/001/"},
	"T1556":     {ID: "T1556", Name: "Modify Authentication Process", Tactic: "Credential Access", URL: "https://attack.mitre.org/techniques/T1556/"},
	"T1557":     {ID: "T1557", Name: "Adversary-in-the-Middle", Tactic: "Credential Access", URL: "https://attack.mitre.org/techniques/T1557/"},
	"T1602":     {ID: "T1602", Name: "Data from Configuration Repository", Tactic: "Collection", URL: "https://attack.mitre.org/techniques/T1602/"},
	"T1213":     {ID: "T1213", Name: "Data from Information Repositories", Tactic: "Collection", URL: "https://attack.mitre.org/techniques/T1213/"},
	"T1083":     {ID: "T1083", Name: "File and Directory Discovery", Tactic: "Discovery", URL: "https://attack.mitre.org/techniques/T1083/"},
	"T1595":     {ID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance", URL: "https://attack.mitre.org/techniques/T1595/"},
	"T1592":     {ID: "T1592", Name: "Gather Victim Host Information", Tactic: "Reconnaissance", URL: "https://attack.mitre.org/techniques/T1592/"},
	"T1190.001": {ID: "T1190.001", Name: "SSRF / Out-of-Bound Interaction", Tactic: "Initial Access", URL: "https://attack.mitre.org/techniques/T1190/"},
	"T1611":     {ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation", URL: "https://attack.mitre.org/techniques/T1611/"},
	"T1068":     {ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: "Privilege Escalation", URL: "https://attack.mitre.org/techniques/T1068/"},
	"T1040":     {ID: "T1040", Name: "Network Sniffing", Tactic: "Discovery", URL: "https://attack.mitre.org/techniques/T1040/"},
	"T1499":     {ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact", URL: "https://attack.mitre.org/techniques/T1499/"},
	"T1071":     {ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control", URL: "https://attack.mitre.org/techniques/T1071/"},
}

// categoryMap maps lowercased Finding.Category to ATT&CK technique IDs.
var categoryMap = map[string][]string{
	"injection":               {"T1190", "T1059"},
	"sql_injection":           {"T1190", "T1059"},
	"xss":                     {"T1190", "T1059.007"},
	"cross_site_scripting":    {"T1190", "T1059.007"},
	"ssrf":                    {"T1190", "T1190.001"},
	"rce":                     {"T1190", "T1059", "T1505.003"},
	"command_injection":       {"T1190", "T1059"},
	"file_upload":             {"T1190", "T1505.003"},
	"path_traversal":          {"T1083", "T1552.001"},
	"information_disclosure":  {"T1592", "T1213"},
	"sensitive_data_exposure": {"T1552.001", "T1602"},
	"secrets_exposure":        {"T1552.001", "T1552"},
	"credential_leak":         {"T1552", "T1552.001"},
	"access_control":          {"T1556", "T1068"},
	"broken_authentication":   {"T1556", "T1539"},
	"session_management":      {"T1539", "T1557"},
	"cors":                    {"T1190", "T1557"},
	"open_redirect":           {"T1190"},
	"api_security":            {"T1190", "T1556"},
	"reconnaissance":          {"T1595", "T1592"},
	"wordlist":                {"T1083", "T1595"},
	"discovery":               {"T1083", "T1595"},
	"dependency":              {"T1190", "T1068"},
	"vulnerable_dependency":   {"T1190", "T1068"},
	"misconfiguration":        {"T1602", "T1556"},
	"denial_of_service":       {"T1499"},
	"network":                 {"T1040", "T1071"},
}

// cweMap supplements categoryMap when the finding has a CWE annotation.
var cweMap = map[string][]string{
	"CWE-22":  {"T1083", "T1552.001"},
	"CWE-78":  {"T1190", "T1059"},
	"CWE-79":  {"T1190", "T1059.007"},
	"CWE-89":  {"T1190", "T1059"},
	"CWE-94":  {"T1190", "T1059"},
	"CWE-200": {"T1592", "T1213"},
	"CWE-269": {"T1068", "T1556"},
	"CWE-284": {"T1556"},
	"CWE-287": {"T1556", "T1539"},
	"CWE-306": {"T1556"},
	"CWE-352": {"T1190"},
	"CWE-434": {"T1505.003"},
	"CWE-502": {"T1190", "T1059"},
	"CWE-522": {"T1552", "T1552.001"},
	"CWE-538": {"T1552.001"},
	"CWE-601": {"T1190"},
	"CWE-611": {"T1190", "T1213"},
	"CWE-732": {"T1552.001"},
	"CWE-798": {"T1552", "T1552.001"},
	"CWE-918": {"T1190", "T1190.001"},
	"CWE-942": {"T1190", "T1557"},
}

// TechniqueIDsFor returns the deterministic, sorted, deduplicated list of
// ATT&CK technique IDs associated with the given finding. Returns nil when
// the finding has no recognised category or CWE.
func TechniqueIDsFor(f model.Finding) []string {
	seen := map[string]struct{}{}
	add := func(ids []string) {
		for _, id := range ids {
			if _, ok := catalog[id]; !ok {
				continue
			}
			seen[id] = struct{}{}
		}
	}
	if cat := strings.ToLower(strings.TrimSpace(f.Category)); cat != "" {
		if ids, ok := categoryMap[cat]; ok {
			add(ids)
		}
	}
	if cwe := strings.ToUpper(strings.TrimSpace(f.CWE)); cwe != "" {
		if ids, ok := cweMap[cwe]; ok {
			add(ids)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// AnnotateFinding sets f.MITRETechniques when it is empty and a mapping is
// known. Existing annotations are preserved so scanners or AI agents can
// override the heuristic mapping.
func AnnotateFinding(f model.Finding) model.Finding {
	if len(f.MITRETechniques) > 0 {
		return f
	}
	ids := TechniqueIDsFor(f)
	if len(ids) == 0 {
		return f
	}
	f.MITRETechniques = ids
	return f
}

// AnnotateFindings is the slice form of AnnotateFinding.
func AnnotateFindings(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}
	out := make([]model.Finding, len(findings))
	for i, f := range findings {
		out[i] = AnnotateFinding(f)
	}
	return out
}

// Lookup returns the catalog entry for an ID; the second return value is
// false when the ID is not part of the package's catalog.
func Lookup(id string) (Technique, bool) {
	t, ok := catalog[id]
	return t, ok
}

// Heatmap counts the number of findings per ATT&CK technique. Findings with
// no ATT&CK annotation are ignored. The returned map is safe for direct use
// in DecisionDashboard.MITREHeatmap.
func Heatmap(findings []model.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		for _, id := range f.MITRETechniques {
			if _, ok := catalog[id]; !ok {
				continue
			}
			out[id]++
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// HeatmapEntry is a single (technique, count) pair used by report renderers.
type HeatmapEntry struct {
	ID    string
	Name  string
	Count int
}

// SortedHeatmap returns the heatmap as a slice ordered by count descending
// then ID ascending so renderers produce stable output.
func SortedHeatmap(h map[string]int) []HeatmapEntry {
	entries := make([]HeatmapEntry, 0, len(h))
	for id, count := range h {
		t, ok := catalog[id]
		name := id
		if ok {
			name = t.Name
		}
		entries = append(entries, HeatmapEntry{ID: id, Name: name, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].ID < entries[j].ID
	})
	return entries
}
