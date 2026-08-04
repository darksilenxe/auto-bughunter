package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// rfdParams lists query parameter names commonly reflected into a
// Content-Disposition filename by export/download/JSONP-style endpoints.
var rfdParams = []string{"callback", "filename", "name", "file", "download", "export", "format", "jsonp"}

// rfdExtensions are dangerous extensions that, when adopted by the reflected
// filename, cause the browser/OS to treat the downloaded (attacker-controlled)
// body as an executable script rather than inert data.
var rfdExtensions = []string{".bat", ".cmd", ".sh"}

const (
	rfdBodyLimit    = 64 * 1024
	rfdMaxAttempts  = 12
	rfdMarkerPrefix = "abh-rfd-7c41"
)

// runReflectedFileDownloadProbe checks for Reflected File Download (RFD): an
// endpoint that echoes an attacker-controlled query parameter verbatim into
// the Content-Disposition filename of a forced ("attachment") download. By
// choosing a parameter value ending in a dangerous extension (.bat/.cmd/.sh),
// an attacker can trick a victim into downloading a file whose name implies
// it is a script — and whose body the attacker also controls via the same or
// another reflected parameter — leading to command execution when the victim
// opens the "trusted" download. This is a well known but rarely automated
// technique because generic scanners only look for reflection in the
// response body, not in response headers.
func (s *Service) runReflectedFileDownloadProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 10)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("reflected-file-download %s", input.Target),
			Message: "Probing for reflected file download via Content-Disposition filename injection",
		})
	}

	attempts := 0
	for _, raw := range candidates {
		if attempts >= rfdMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range rfdParams {
			if attempts >= rfdMaxAttempts {
				break
			}
			for _, ext := range rfdExtensions {
				if attempts >= rfdMaxAttempts {
					break
				}
				payload := rfdMarkerPrefix + ext
				probeURL, err := phase1QueryURL(base.String(), param, payload, true)
				if err != nil || !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				attempts++
				// Phase 2 coverage accounting.
				RecordProbedKey(http.MethodGet, probeURL, param)
				if err != nil || resp == nil {
					continue
				}
				disposition := resp.Header.Get("Content-Disposition")
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, rfdBodyLimit))
				_ = resp.Body.Close()
				if disposition == "" {
					continue
				}
				if !strings.Contains(strings.ToLower(disposition), "attachment") {
					continue
				}
				if !strings.Contains(disposition, payload) {
					continue
				}

				// Two-control differential re-verify: the marker must be
				// unique to our exact payload value — both a stripped
				// (benign) value and a random benign value of comparable
				// length must NOT reproduce it, ruling out a static
				// filename that always happens to match.
				diffOutcome := phase1DifferentialQuery(ctx, s, input, "reflected-file-download", base.String(), param, payload, "abh_benign_baseline"+ext, rfdBodyLimit,
					func(_ context.Context, _ string, r *http.Response, _ []byte) (bool, error) {
						if r == nil {
							return false, nil
						}
						d := r.Header.Get("Content-Disposition")
						return strings.Contains(d, payload) && strings.Contains(strings.ToLower(d), "attachment"), nil
					},
				)
				if diffOutcome.Ran && !diffOutcome.Confirmed {
					continue
				}

				curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
				finding := model.Finding{
					ID:       "reflected-file-download-" + hhSlug(probeURL),
					Category: "injection",
					Severity: model.SeverityHigh,
					Title:    "Reflected File Download via Content-Disposition filename injection",
					Description: fmt.Sprintf(
						"The endpoint %s reflects the attacker-controlled parameter %q verbatim into the "+
							"Content-Disposition filename of a forced (\"attachment\") download. By supplying a "+
							"value ending in a dangerous extension (e.g. %s) the response is offered to victims "+
							"as a file that appears to originate from the trusted site but whose name implies "+
							"it is an executable script. Combined with attacker-controlled body content, opening "+
							"the downloaded file can lead to command execution on the victim's machine.",
						probeURL, param, ext,
					),
					Evidence:          fmt.Sprintf("Response Content-Disposition header: %q (parameter %s=%s)", disposition, param, payload),
					Recommendation:    "Never derive the Content-Disposition filename from unsanitized user input. Use a fixed, server-controlled filename (or an allowlisted extension) and set Content-Type to a non-executable value (e.g. application/octet-stream / text/plain) with X-Content-Type-Options: nosniff.",
					Confidence:        0.8,
					AffectedURL:       probeURL,
					AffectedParameter: param,
					CWE:               "CWE-641",
					OWASPCategory:     "A03:2021 - Injection",
					Sources:           []string{"active-scanner", "reflected-file-download-probe"},
					ReproductionSteps: []string{
						fmt.Sprintf("Send GET %s", probeURL),
						fmt.Sprintf("Inspect the Content-Disposition response header and confirm it contains filename \"%s\"", payload),
						"Save/open the downloaded response and observe it is treated as an executable script by the OS.",
					},
					PoC: curl,
					EvidenceFields: map[string]string{
						"validationType":  "active-probe",
						"payload":         payload,
						"curlReproducer":  curl,
						"method":          http.MethodGet,
						"url":             probeURL,
						"param":           param,
						"contentDisposition": disposition,
						"oracleName":      "reflected_file_download",
						"oracleVersion":   "v1",
					},
				}
				AttachDifferentialEvidence(&finding, diffOutcome)
				return []model.Finding{finding}
			}
		}
	}
	return nil
}
