package scanner

import (
	"context"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// ProbeRecorder is a callback interface for persisting individual probe
// outcomes to the database. It mirrors agent.ProbeRecorder to avoid a
// circular import between the scanner and agent packages. The concrete
// implementation is storage.Postgres (or storage.MemoryStore for tests).
type ProbeRecorder interface {
	SaveProbeRecord(ctx context.Context, scanID string, pr model.ProbeResult) error
}

// standardScanCategories is the set of vulnerability categories that
// scanner.Run always probes regardless of the target. It is used to
// synthesize no_signal probe records for categories that returned no
// confirmed findings, so the Probe Coverage UI shows complete scanner
// coverage even when nothing was confirmed.
var standardScanCategories = []string{
	"xss",
	"sqli",
	"ssti",
	"ssrf",
	"cors",
	"open_redirect",
	"path_traversal",
	"xxe",
	"nosqli",
	"ldap_injection",
	"command_injection",
	"file_upload",
	"csrf",
	"jwt",
	"clickjacking",
	"security_headers",
	"tls",
	"graphql",
	"prototype_pollution",
	"formula_injection",
	"xssi_jsonp",
	"cache_poisoning",
	"request_smuggling",
	"smtp_injection",
	"verbose_error",
	"sensitive_files",
	"secrets",
	"stored_xss",
	"reverse_tabnabbing",
	"csp",
	"crlf_injection",
	"forbidden_bypass",
	"css_injection",
	"dom_clobbering",
	"dns_rebinding",
	"subdomain_takeover",
	"websocket",
	"account_enumeration",
	"mass_assignment",
	"rate_limit",
	"http_methods",
	"saml",
	"sri",
	"zip_slip",
	"xslt_injection",
	"cloud_storage",
	"prompt_injection",
}

// saveProbeRecords persists probe records for the Probe Coverage and
// Findings probe-history UIs. For each confirmed finding it writes a
// ProbeRecord with outcome=confirmed and the finding's ID so the
// Findings page can fetch per-finding probe history. For every standard
// category that produced no confirmed findings it writes a single
// no_signal record so the Probe Coverage page shows complete scanner
// coverage. All writes are fire-and-forget goroutines so they never
// block the caller.
func (s *Service) saveProbeRecords(recorder ProbeRecorder, scanID, target string, findings []model.Finding) {
	if recorder == nil || strings.TrimSpace(scanID) == "" {
		return
	}

	// Build a set of categories that had at least one confirmed finding.
	confirmedByCategory := make(map[string]bool, len(findings))

	for _, f := range findings {
		cat := normalizeProbeCat(f.Category)
		if cat == "" {
			continue
		}
		confirmedByCategory[cat] = true

		ep := strings.TrimSpace(f.AffectedURL)
		if ep == "" {
			ep = target
		}

		fCopy := f // capture loop var for goroutine
		epCopy := ep
		go func() {
			_ = recorder.SaveProbeRecord(context.Background(), scanID, model.ProbeResult{
				Category:    cat,
				Endpoint:    epCopy,
				ParamName:   fCopy.AffectedParameter,
				Outcome:     model.ProbeConfirmed,
				Confirmed:   true,
				Finding:     &fCopy,
				Observation: fCopy.Title,
			})
		}()
	}

	// Write a single no_signal record for every standard category that
	// ran but produced no confirmed findings.
	for _, cat := range standardScanCategories {
		if confirmedByCategory[cat] {
			continue
		}
		catCopy := cat
		go func() {
			_ = recorder.SaveProbeRecord(context.Background(), scanID, model.ProbeResult{
				Category:    catCopy,
				Endpoint:    target,
				Outcome:     model.ProbeNoSignal,
				Observation: catCopy + " scan completed — no findings for this target.",
			})
		}()
	}
}

// normalizeProbeCat lower-cases and trims the category string. It
// returns "" for internal/meta categories that should not produce probe
// records (e.g. "scanner", "coverage", "browser").
func normalizeProbeCat(cat string) string {
	cat = strings.ToLower(strings.TrimSpace(cat))
	switch cat {
	case "", "scanner", "coverage", "browser", "integration", "reconnaissance",
		"monitoring", "prioritization":
		return ""
	}
	return cat
}
