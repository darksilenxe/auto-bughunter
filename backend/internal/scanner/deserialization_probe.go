package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// deserializationBodyLimit caps the per-response read during probing.
const deserializationBodyLimit = 128 * 1024

// deserializationMaxEndpoints caps how many endpoints are probed per scan.
const deserializationMaxEndpoints = 8

// javaSerializedMagic is the 2-byte magic prefix for Java serialized objects
// (0xACED), both as raw bytes and as common base64-encoded variants.
var javaSerializedMagic = []string{
	"\xac\xed",
	"rO0AB", // base64(0xACED 0x0005...)  — aced 0005 is Java stream magic
	"rO0A",
}

// phpObjectPattern detects PHP serialize() output in responses.
// Format: O:N:"ClassName":M:{...} where N is class name length.
var phpObjectPattern = regexp.MustCompile(`O:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*":\d+:\{`)

// pythonPickleMarkers are byte patterns common in pickle streams.
// 0x80 0x02 is the SHORT_BINUNICODE opcode prefix for protocol 2+.
var pythonPickleMarkers = []string{
	"\x80\x02",      // protocol 2
	"\x80\x03",      // protocol 3
	"\x80\x04",      // protocol 4
	"cbuiltins\n",   // pickle GLOBAL opcode
	"cos\nsystem\n", // classic gadget
}

// ysosGadgetPattern matches reflection of ysoserial gadget chain class names
// that appear in error messages when the payload reaches a Java deserializer.
var ysosGadgetPattern = regexp.MustCompile(
	`(?i)(CommonsCollections|SpringAOP|BeanShell|MozillaRhino|Hibernate|Spring1|Spring2|ROME|Jdk7u21|Jdk8u20|JRMPClient|JRMPListener|CommonsBeanutils)`,
)

// deserializationProbePayloads are safe, inert probe values designed to trigger
// detection in error messages without executing code.  Each is a recognised
// serialization format preamble that most deserializers will attempt to process.
var deserializationProbePayloads = []struct {
	label       string
	contentType string
	body        string
}{
	{
		label:       "java-aced",
		contentType: "application/octet-stream",
		body:        "\xac\xed\x00\x05sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01",
	},
	{
		label:       "php-object",
		contentType: "application/x-www-form-urlencoded",
		body:        `data=O:8:"stdClass":1:{s:4:"test";s:1:"1";}`,
	},
}

// RunDeserializationProbe is an active insecure-deserialization detection probe.
// It submits inert serialized payloads to content-accepting endpoints and inspects
// responses for three signals:
//  1. Java serialized magic bytes (0xACED or their base64 equivalents) reflected
//     in the response body — indicating the endpoint echoes or processes serialized data.
//  2. PHP object injection patterns in response bodies.
//  3. Python pickle magic bytes in response bodies.
//  4. ysoserial gadget class name mentions in error messages (Java deserializer
//     trying to process the payload and exposing class resolution errors).
//
// No RCE payload is ever sent; the probe only submits recognised-format preambles.
func (s *Service) RunDeserializationProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	candidates := deserializationCandidates(target, options.SeedRuntimeEndpoints, scanScope)
	if len(candidates) == 0 {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("deserialization-probe %s", target),
			Message: fmt.Sprintf("Probing %d endpoints for insecure deserialization indicators", len(candidates)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		for _, probe := range deserializationProbePayloads {
			fid := "deserialization-" + probe.label + "-" + hhSlug(ep)
			if emitted[fid] {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(probe.body))
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, auth)
			req.Header.Set("Content-Type", probe.contentType)

			resp, err := s.doRequestWithRetry(ctx, req, options)
			if err != nil || resp == nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, deserializationBodyLimit))
			respHeader := resp.Header
			_ = resp.Body.Close()
			if IsBinaryShape(respHeader) {
				continue
			}
			bodyStr := string(body)

			indicator, lang := detectDeserializationSignal(bodyStr, probe.label)
			if indicator == "" {
				continue
			}
			baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
				return phase1POSTSample(bctx, s, ep, probe.contentType, "safe", RunInput{AuthProfile: auth, Options: options}, deserializationBodyLimit)
			})
			if berr == nil && phase1BaselineContains(baselines, indicator) {
				continue
			}
			diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
				ProbeName:       "deserialization-probe",
				OriginalPayload: probe.body,
				SafePayload:     "safe",
				Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
					req, err := http.NewRequestWithContext(dctx, http.MethodPost, ep, strings.NewReader(altPayload))
					if err != nil {
						return nil, nil, err
					}
					ApplyAuthProfile(req, auth)
					req.Header.Set("Content-Type", probe.contentType)
					resp, err := s.doRequestWithRetry(dctx, req, options)
					if err != nil || resp == nil {
						return nil, nil, err
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, deserializationBodyLimit))
					return resp, body, nil
				},
				Oracle: func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
					got, _ := detectDeserializationSignal(string(body), probe.label)
					return got != "", nil
				},
			})
			if diffOutcome.Ran && !diffOutcome.Confirmed {
				continue
			}

			emitted[fid] = true
			finding := model.Finding{
				ID:       fid,
				Category: "injection",
				Severity: model.SeverityHigh,
				Title:    fmt.Sprintf("Potential insecure deserialization — %s object detected in response", lang),
				Description: fmt.Sprintf(
					"The endpoint %s returned a response containing a %s deserialization indicator (%s) after receiving "+
						"an inert serialized payload. If the server is deserializing attacker-controlled input without "+
						"type allowlisting, an attacker can craft a gadget-chain payload to achieve remote code execution, "+
						"arbitrary file write, or server-side request forgery depending on the classes available in the classpath.",
					ep, lang, indicator,
				),
				Evidence: fmt.Sprintf(
					"Probe: %s (%s) → HTTP %d; response contains: %s",
					probe.label, probe.contentType, resp.StatusCode, indicator,
				),
				Recommendation: "Deserialize only trusted, signed data. For Java: use a serialization filter " +
					"(JEP 290/JEP 415) to allowlist expected classes. For PHP: avoid unserialize() on user input — " +
					"use JSON instead. For Python: never unpickle untrusted data; use json or msgpack. " +
					"Conduct a gadget-chain analysis using ysoserial/marshalsec to assess exploitability.",
				Confidence:    0.78,
				AffectedURL:   ep,
				CWE:           "CWE-502",
				OWASPCategory: "A08:2021 - Software and Data Integrity Failures",
				Sources:       []string{"active-scanner", "deserialization-probe"},
				ReproductionSteps: []string{
					fmt.Sprintf("Submit a %s serialized payload to POST %s.", lang, ep),
					fmt.Sprintf("Observe the response indicator: %s", indicator),
					"Use ysoserial (Java), PHPGGC (PHP), or pickle-tools (Python) to generate a gadget chain.",
					"Deliver the chain and confirm OOB SSRF or RCE via an OAST callback.",
				},
				BusinessTags: []string{"deserialization", "rce", lang},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"language":       lang,
					"indicator":      indicator,
					"probeLabel":     probe.label,
					"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
					"responseShape":  ClassifyResponseShape(respHeader).String(),
				},
			}
			AttachDifferentialEvidence(&finding, diffOutcome)
			findings = append(findings, finding)
		}

		// Passive check: scan the existing response body for serialization markers
		// without sending a probe (handles cases where the server returns its own
		// serialized data in error responses or debug output).
		fid := "deserialization-passive-" + hhSlug(ep)
		if !emitted[fid] {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
			if err == nil {
				ApplyAuthProfile(req, auth)
				resp, err := s.doRequestWithRetry(ctx, req, options)
				if err == nil && resp != nil {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, deserializationBodyLimit))
					respHeader := resp.Header
					_ = resp.Body.Close()
					if IsBinaryShape(respHeader) {
						continue
					}
					if indicator, lang := detectDeserializationSignal(string(body), ""); indicator != "" {
						emitted[fid] = true
						findings = append(findings, model.Finding{
							ID:       fid,
							Category: "information-disclosure",
							Severity: model.SeverityMedium,
							Title:    fmt.Sprintf("Serialized %s object found in GET response", lang),
							Description: fmt.Sprintf(
								"A GET request to %s returned a response body containing a %s serialization marker. "+
									"Serialized data in API responses can indicate that the server accepts and processes "+
									"user-supplied serialized input, or that it is leaking internal object structure "+
									"which an attacker can study to craft a gadget-chain exploit.",
								ep, lang,
							),
							Evidence: fmt.Sprintf("GET %s → HTTP %d; contains: %s", ep, resp.StatusCode, indicator),
							Recommendation: "Avoid serializing internal objects into API responses. Use plain JSON/XML. " +
								"If serialization is required, sign and validate all serialized blobs.",
							Confidence:    0.70,
							AffectedURL:   ep,
							CWE:           "CWE-502",
							OWASPCategory: "A08:2021 - Software and Data Integrity Failures",
							Sources:       []string{"active-scanner", "deserialization-probe"},
							EvidenceFields: map[string]string{
								"validationType": "safe-observation",
								"language":       lang,
								"indicator":      indicator,
							},
						})
					}
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// detectDeserializationSignal scans a response body string for Java, PHP or
// Python serialization markers. Returns a short indicator description and the
// language name, or empty strings when nothing is found.
func detectDeserializationSignal(body, hint string) (indicator, lang string) {
	// Java: raw magic bytes or base64 encoding.
	for _, magic := range javaSerializedMagic {
		if strings.Contains(body, magic) {
			return "Java serialization magic: " + strings.TrimSpace(fmt.Sprintf("%q", magic)), "Java"
		}
	}
	// Java: ysoserial gadget class in error messages.
	if m := ysosGadgetPattern.FindString(body); m != "" {
		return "ysoserial gadget class reference: " + m, "Java"
	}
	// PHP serialized object.
	if phpObjectPattern.MatchString(body) {
		return "PHP serialize() object pattern O:N:\"ClassName\"", "PHP"
	}
	// Python pickle.
	for _, marker := range pythonPickleMarkers {
		if strings.Contains(body, marker) {
			return "Python pickle protocol marker", "Python"
		}
	}
	// Hint-based fallback for the PHP probe.
	if hint == "php-object" && strings.Contains(body, "__destruct") {
		return "PHP __destruct reference in response (possible PHP object instantiation via deserialization)", "PHP"
	}
	return "", ""
}

// deserializationCandidates collects candidate API/service endpoints.
// Prefers paths that suggest data ingestion or serialization-related patterns.
func deserializationCandidates(target string, seeded []string, scanScope model.ScanScope) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	// Well-known paths that commonly accept serialized input.
	wellKnown := []string{
		"/api/data",
		"/api/import",
		"/api/upload",
		"/api/object",
		"/api/payload",
		"/api/deserialize",
		"/api/rmi",
		"/invoke",
	}

	all := append([]string{}, seeded...)
	for _, wk := range wellKnown {
		ref, err := url.Parse(wk)
		if err != nil {
			continue
		}
		all = append(all, base.ResolveReference(ref).String())
	}

	out := make([]string, 0, deserializationMaxEndpoints)
	seen := map[string]struct{}{}
	for _, raw := range all {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		if !scope.IsURLInScope(raw, scanScope) {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
		if len(out) >= deserializationMaxEndpoints {
			break
		}
	}
	return out
}
