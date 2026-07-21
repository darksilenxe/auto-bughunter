package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// storedXSSMarker is distinct from the reflected-XSS marker so findings
// can be attributed to the correct probe. The marker contains no real script
// execution attempt — we look only for the literal payload in a GET response.
const storedXSSMarker = `"><svg/onload=abh_stored_xss_9a1b()><!--abh_stored_xss_9a1b-->`

// storedXSSBodyLimit caps per-probe response reads.
const storedXSSBodyLimit = 256 * 1024

// storedXSSWritePatterns matches paths that commonly accept POST and store content.
var storedXSSWritePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/api/(feedback|comment|review|message|note|post|status)`),
	regexp.MustCompile(`(?i)/feedback`),
	regexp.MustCompile(`(?i)/comment`),
	regexp.MustCompile(`(?i)/review`),
	regexp.MustCompile(`(?i)/message`),
	regexp.MustCompile(`(?i)/post`),
}

// storedXSSReadPaths maps well-known write paths to their read counterparts.
var storedXSSReadPaths = map[string]string{
	"/api/feedback": "/api/feedback",
	"/api/comment":  "/api/comments",
	"/api/review":   "/api/reviews",
	"/api/message":  "/api/messages",
	"/api/note":     "/api/notes",
	"/api/post":     "/api/posts",
	"/feedback":     "/feedback",
	"/comments":     "/comments",
	"/reviews":      "/reviews",
}

// storedXSSWriteFields are JSON body fields commonly used for free-text input.
var storedXSSWriteFields = []string{"message", "comment", "feedback", "body", "text", "content", "description", "note", "value"}

// runStoredXSSProbe is a two-phase stateful stored-XSS scanner:
//
//  1. Inject phase: POST the storedXSSMarker payload to writable-looking
//     endpoints discovered from well-known paths and the session's XHR-
//     discovered endpoints, using the live session (cookies/tokens).
//
//  2. Retrieve phase: GET the corresponding read endpoints and check whether
//     the marker appears unescaped in the HTML response body.
//
// A finding is emitted when the payload survives storage and is reflected
// unescaped on a subsequent retrieval request.
func (s *Service) runStoredXSSProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly || input.Session == nil {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("stored-xss %s", input.Target),
			Message: "Probing for stored XSS via inject-then-retrieve payload injection",
		})
	}

	writeCandidates := collectStoredXSSWriteCandidates(base, input.Options.SeedRuntimeEndpoints, input.Scope)
	if len(writeCandidates) == 0 {
		return nil
	}

	type injectedAt struct {
		writeEP string
		readEP  string
		field   string
	}
	var injections []injectedAt

	const maxInjects = 6
	for i, wep := range writeCandidates {
		if i >= maxInjects {
			break
		}
		readEP := guessStoredXSSReadEndpoint(base, wep)
		for _, field := range storedXSSWriteFields {
			body := map[string]string{field: storedXSSMarker}
			bodyJSON, err := json.Marshal(body)
			if err != nil {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, wep, bytes.NewReader(bodyJSON))
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)
			req.Header.Set("Content-Type", "application/json")
			resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
			if err != nil || resp == nil {
				continue
			}
			_, _ = io.ReadAll(io.LimitReader(resp.Body, storedXSSBodyLimit))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				injections = append(injections, injectedAt{writeEP: wep, readEP: readEP, field: field})
				break
			}
		}
	}

	if len(injections) == 0 {
		return nil
	}

	// Retrieve phase.
	type hit struct {
		writeEP string
		readEP  string
		field   string
	}
	var hits []hit
	for _, inj := range injections {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, inj.readEP, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, storedXSSBodyLimit))
		_ = resp.Body.Close()
		if isHTMLContextReflection(string(respBody), storedXSSMarker) {
			hits = append(hits, hit(inj))
		}
	}

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	evidence := fmt.Sprintf(
		"Injected marker %q via POST %s (field=%s); marker appeared unescaped in GET %s",
		storedXSSMarker, first.writeEP, first.field, first.readEP,
	)
	steps := []string{
		fmt.Sprintf("POST to %s with JSON body {%q: %q}.", first.writeEP, first.field, storedXSSMarker),
		fmt.Sprintf("GET %s and inspect the response body.", first.readEP),
		fmt.Sprintf("Confirm the literal payload %q appears unescaped in an HTML context.", storedXSSMarker),
	}
	curl := buildCurlReproducer(http.MethodGet, first.readEP, input.AuthProfile, "", "")

	return []model.Finding{{
		ID:                "stored-xss-reflected",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "Stored Cross-Site Scripting (XSS) — payload survives storage and retrieval unencoded",
		Description:       "An HTML-context payload injected via a write endpoint was later reflected unescaped from a read endpoint. Any user who views the affected content will have the payload executed in their browser, enabling session hijacking, credential theft, and account takeover.",
		Evidence:          evidence,
		Recommendation:    "Apply context-aware output encoding (HTML entity encoding) at every rendering sink. Use a templating engine with auto-escaping and add a strict Content-Security-Policy.",
		Confidence:        0.88,
		AffectedURL:       first.readEP,
		AffectedParameter: first.field,
		CWE:               "CWE-79",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner", "stored-xss-probe"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"writeEndpoint":  first.writeEP,
			"readEndpoint":   first.readEP,
			"injectedField":  first.field,
			"curlReproducer": curl,
		},
	}}
}

// collectStoredXSSWriteCandidates builds a list of endpoints likely to accept
// POST writes, drawn from static well-known paths and session XHR endpoints.
func collectStoredXSSWriteCandidates(base *url.URL, seedEndpoints []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		var resolved *url.URL
		if ref.Scheme == "" || ref.Host == "" {
			resolved = base.ResolveReference(ref)
		} else {
			resolved = ref
		}
		s := resolved.String()
		if _, ok := seen[s]; ok {
			return
		}
		if !scope.IsURLInScope(s, scanScope) {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	for path := range storedXSSReadPaths {
		add(path)
	}

	for _, ep := range seedEndpoints {
		for _, re := range storedXSSWritePatterns {
			if re.MatchString(ep) {
				add(ep)
				break
			}
		}
	}

	const max = 10
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// guessStoredXSSReadEndpoint returns the expected GET endpoint for a write path.
func guessStoredXSSReadEndpoint(base *url.URL, writeEP string) string {
	parsed, err := url.Parse(writeEP)
	if err != nil {
		return writeEP
	}
	if readPath, ok := storedXSSReadPaths[parsed.Path]; ok {
		return base.ResolveReference(&url.URL{Path: readPath}).String()
	}
	return writeEP
}
