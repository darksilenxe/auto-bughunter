package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// crossDomainBodyLimit caps response body reads for policy file fetches.
const crossDomainBodyLimit = 64 * 1024

// crossDomainPolicyPaths are the well-known locations for Flash and Silverlight
// cross-domain access policy files.
var crossDomainPolicyPaths = []struct {
	path  string
	label string
}{
	{"/crossdomain.xml", "Flash cross-domain policy (crossdomain.xml)"},
	{"/clientaccesspolicy.xml", "Silverlight client access policy (clientaccesspolicy.xml)"},
}

// crossDomainXML is a minimal representation of a Flash crossdomain.xml for
// parsing the allow-access-from entries.
type crossDomainXML struct {
	XMLName     xml.Name               `xml:"cross-domain-policy"`
	AllowAccess []crossDomainAllowFrom `xml:"allow-access-from"`
}

type crossDomainAllowFrom struct {
	Domain      string `xml:"domain,attr"`
	SecureOnly  string `xml:"secure,attr"`
	HTTPSRequired string `xml:"headers,attr"`
}

// runCrossDomainPolicyProbe is an active probe covering WSTG-CONF-08. It
// fetches crossdomain.xml and clientaccesspolicy.xml from the target origin
// and flags configurations that allow unrestricted cross-origin access:
//
//   - allow-access-from domain="*" in crossdomain.xml
//   - allow-from with http-request-headers="*" in clientaccesspolicy.xml
//
// Overly permissive cross-domain policies allow malicious external sites to
// perform authenticated requests on behalf of the victim user (similar to CORS
// misconfiguration), potentially leaking sensitive data or performing
// state-changing actions.
func (s *Service) runCrossDomainPolicyProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	u, err := url.Parse(input.Target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("cross-domain-policy %s", input.Target),
			Message: "Checking cross-domain policy files (crossdomain.xml, clientaccesspolicy.xml)",
		})
	}

	var findings []model.Finding

	for _, policyPath := range crossDomainPolicyPaths {
		ref, err := url.Parse(policyPath.path)
		if err != nil {
			continue
		}
		base := &url.URL{Scheme: u.Scheme, Host: u.Host}
		policyURL := base.ResolveReference(ref).String()

		if err := safety.ValidateOutboundURL(policyURL); err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)

		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, crossDomainBodyLimit))
		respHeader := resp.Header
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			continue
		}

		// Phase 1 FP-reduction: crossdomain.xml / clientaccesspolicy.xml
		// must be served as XML. When the well-known path returns HTML
		// (typically a SPA index or 404 page rendered with HTTP 200),
		// the payload is not a policy file and simple string matches on
		// domain="*" would produce false positives.
		if !IsXMLShape(respHeader) {
			continue
		}

		bodyStr := string(body)
		shape := ClassifyResponseShape(respHeader).String()

		switch policyPath.path {
		case "/crossdomain.xml":
			findings = append(findings, tagCrossDomainShape(analyzeCrossDomainXML(policyURL, bodyStr), shape)...)
		case "/clientaccesspolicy.xml":
			findings = append(findings, tagCrossDomainShape(analyzeClientAccessPolicy(policyURL, bodyStr), shape)...)
		}
	}

	return findings
}

// tagCrossDomainShape stamps the response-shape evidence field on every
// finding so downstream metrics can attribute Phase 1 gate coverage.
func tagCrossDomainShape(findings []model.Finding, shape string) []model.Finding {
	for i := range findings {
		if findings[i].EvidenceFields == nil {
			findings[i].EvidenceFields = map[string]string{}
		}
		findings[i].EvidenceFields["responseShape"] = shape
	}
	return findings
}

// analyzeCrossDomainXML parses and checks a Flash crossdomain.xml for
// wildcard or overly permissive allow-access-from entries.
func analyzeCrossDomainXML(policyURL, body string) []model.Finding {
	var policy crossDomainXML
	if err := xml.Unmarshal([]byte(body), &policy); err != nil {
		// Still check for wildcard via simple string match if XML is malformed.
		if strings.Contains(body, `domain="*"`) {
			return wildcardCrossDomainFinding(policyURL, "crossdomain.xml", `domain="*"`)
		}
		return nil
	}

	var findings []model.Finding
	for _, entry := range policy.AllowAccess {
		if entry.Domain == "*" {
			findings = append(findings, model.Finding{
				ID:       "cross-domain-policy-wildcard-" + hhSlug(policyURL),
				Category: "configuration",
				Severity: model.SeverityHigh,
				Title:    "Overly permissive Flash cross-domain policy — wildcard domain",
				Description: fmt.Sprintf(
					"The crossdomain.xml file at %s contains 'allow-access-from domain=\"*\"'. "+
						"This permits any external website to make authenticated Flash/ActionScript requests "+
						"to this origin and read the response data. Although Flash is effectively deprecated, "+
						"a permissive crossdomain.xml may still be honoured by legacy Flash clients, "+
						"and its presence signals a historical lack of access control hygiene that may "+
						"extend to other CORS or federation configurations.",
					policyURL,
				),
				Evidence:    fmt.Sprintf("GET %s → HTTP 200; allow-access-from domain=\"*\"", policyURL),
				Recommendation: "Remove crossdomain.xml entirely if Flash-based cross-domain access is not required. " +
					"If it must exist, restrict 'allow-access-from' to explicitly trusted domains only.",
				Confidence:    0.92,
				AffectedURL:   policyURL,
				CWE:           "CWE-942",
				OWASPCategory: "A05:2021 - Security Misconfiguration",
				Sources:       []string{"active-scanner", "cross-domain-policy"},
				ReproductionSteps: []string{
					fmt.Sprintf("curl %s", policyURL),
					"Observe allow-access-from domain=\"*\" in the response.",
				},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"policyFile":     "crossdomain.xml",
					"allowedDomain":  entry.Domain,
				},
			})
		}
	}
	return findings
}

// analyzeClientAccessPolicy parses and checks a Silverlight clientaccesspolicy.xml
// for wildcard or overly permissive allow-from entries.
func analyzeClientAccessPolicy(policyURL, body string) []model.Finding {
	// Check for wildcard HTTP request headers via simple string match first
	// (robust against XML namespace variations).
	if strings.Contains(body, `http-request-headers="*"`) || strings.Contains(body, `<allow-from`) && strings.Contains(body, `"*"`) {
		return []model.Finding{{
			ID:       "client-access-policy-wildcard-" + hhSlug(policyURL),
			Category: "configuration",
			Severity: model.SeverityHigh,
			Title:    "Overly permissive Silverlight client access policy — wildcard",
			Description: fmt.Sprintf(
				"The clientaccesspolicy.xml file at %s permits unrestricted cross-domain access "+
					"(wildcard allow-from or http-request-headers=\"*\"). "+
					"This allows any origin to perform authenticated Silverlight requests to this domain "+
					"and read responses, enabling data exfiltration from authenticated sessions.",
				policyURL,
			),
			Evidence:    fmt.Sprintf("GET %s → HTTP 200; wildcard allow-from or http-request-headers=\"*\"", policyURL),
			Recommendation: "Remove clientaccesspolicy.xml if Silverlight is no longer in use. " +
				"If required, restrict allowed origins to specific trusted domains.",
			Confidence:    0.90,
			AffectedURL:   policyURL,
			CWE:           "CWE-942",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"active-scanner", "cross-domain-policy"},
			ReproductionSteps: []string{
				fmt.Sprintf("curl %s", policyURL),
				"Observe wildcard allow-from entry in the response.",
			},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"policyFile":     "clientaccesspolicy.xml",
			},
		}}
	}
	return nil
}

// wildcardCrossDomainFinding returns a finding for a wildcard domain detected
// by simple string matching when XML parsing fails.
func wildcardCrossDomainFinding(policyURL, filename, evidence string) []model.Finding {
	return []model.Finding{{
		ID:       "cross-domain-policy-wildcard-raw-" + hhSlug(policyURL),
		Category: "configuration",
		Severity: model.SeverityHigh,
		Title:    fmt.Sprintf("Overly permissive %s — wildcard domain (raw match)", filename),
		Description: fmt.Sprintf(
			"The %s file at %s contains a wildcard domain entry (%s). "+
				"This allows any external site to make cross-domain requests with credentials "+
				"and read the response data.",
			filename, policyURL, evidence,
		),
		Evidence:    fmt.Sprintf("GET %s → HTTP 200; raw match for %s", policyURL, evidence),
		Recommendation: "Remove this policy file or restrict allowed domains to explicit trusted origins.",
		Confidence:    0.85,
		AffectedURL:   policyURL,
		CWE:           "CWE-942",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		Sources:       []string{"active-scanner", "cross-domain-policy"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"policyFile":     filename,
			"rawEvidence":    evidence,
		},
	}}
}
