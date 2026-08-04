package scanner

import (
	"context"
	"fmt"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
	"auto-bughunter/backend/internal/toolclient"
)

// runH2CSmugglingProbe probes the target for HTTP/2 cleartext (h2c) upgrade
// acceptance and request-smuggling anomalies using the h2csmuggler-service
// sidecar.
//
// h2c smuggling occurs when a front-end proxy transparently upgrades an
// HTTP/1.1 "Upgrade: h2c" request to HTTP/2 and forwards it to a back-end
// origin. Because the proxy only inspects the HTTP/1.1 framing it may fail
// to apply WAF rules, authentication checks, or access controls to requests
// smuggled inside the h2c channel.
//
// The probe is always-on (no destructive gate required) because it only sends
// crafted HTTP/1.1 upgrade and plain HTTP/2 requests — it does not modify any
// server state.
func (s *Service) runH2CSmugglingProbe(ctx context.Context, input RunInput) []model.Finding {
	if !scope.IsURLInScope(input.Target, input.Scope) {
		return nil
	}

	RecordProbedKey("GET", input.Target, "")

	client := toolclient.NewH2CSmugglerClient()
	if !client.IsAvailable(ctx) {
		return nil
	}

	result, err := client.Scan(ctx, toolclient.H2CScanRequest{
		URL:     input.Target,
		Timeout: 15,
	})
	if err != nil || result == nil {
		return nil
	}

	var findings []model.Finding
	for _, sf := range result.Findings {
		finding := buildH2CFinding(input.Target, sf)
		outcome := SubmitVerifiedFinding(ctx, VerifyCandidate{
			Finding:               finding,
			Signals:               []EvidenceSignal{EvidenceSinkObserved},
			AllowNoReplayEmission: true,
			ProbeName:             "h2c-smuggling-probe",
		})
		if outcome.Suppressed {
			continue
		}
		findings = append(findings, outcome.EmittedFinding)
	}
	return findings
}

func buildH2CFinding(target string, sf toolclient.H2CFinding) model.Finding {
	id := "h2c-smuggling-" + sf.Type
	title := "HTTP/2 Cleartext (h2c) Upgrade Smuggling"
	severity := model.SeverityHigh
	cwe := "CWE-444"
	owaspCat := "A02:2021 - Cryptographic Failures / A10:2021 - SSRF"

	switch sf.Type {
	case "h2c-upgrade-accepted":
		title = "H2C Upgrade Accepted — Potential Smuggling Vector"
		severity = model.SeverityHigh
	case "h2c-upgrade-echoed":
		title = "H2C Upgrade Header Echoed — Misconfigured h2c Support"
		severity = model.SeverityMedium
	case "h2c-smuggling-anomaly":
		title = "H2C Smuggling Anomaly — Bypassed Intermediary Controls"
		severity = model.SeverityCritical
	}

	evidenceFields := map[string]string{
		"validationType": "active-probe",
		"findingType":    sf.Type,
		"method":         "GET",
		"url":            target,
		"oracleName":     "h2c_smuggling_probe",
		"oracleVersion":  "v1",
	}
	for k, v := range sf.Evidence {
		evidenceFields[fmt.Sprintf("evidence.%s", k)] = fmt.Sprintf("%v", v)
	}

	return model.Finding{
		ID:          id,
		Category:    "h2c-smuggling",
		Severity:    severity,
		Title:       title,
		Description: sf.Description,
		Evidence: fmt.Sprintf(
			"type=%q; description=%q",
			sf.Type, sf.Description,
		),
		Recommendation: "Disable h2c (HTTP/2 cleartext) on all public-facing servers and " +
			"reverse proxies. If HTTP/2 is required, use TLS (h2). Ensure all intermediaries " +
			"strip Upgrade: h2c headers from inbound requests so back-end origins never " +
			"receive upgrade requests from untrusted clients.",
		Confidence:    0.88,
		AffectedURL:   target,
		CWE:           cwe,
		OWASPCategory: owaspCat,
		Sources:       []string{"active-probe", "h2c-upgrade"},
		ReproductionSteps: []string{
			fmt.Sprintf("Send a GET %s request with headers: Upgrade: h2c, Connection: Upgrade\\, HTTP2-Settings, HTTP2-Settings: AAMAAABkAAQAAP__", target),
			"Observe the response for a 101 Switching Protocols or echoed Upgrade header.",
			"If h2c is accepted, attempt to send HTTP/2 requests over the cleartext channel to access internal paths.",
		},
		EvidenceFields: evidenceFields,
	}
}
