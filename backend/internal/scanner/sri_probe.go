package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// scriptTagPattern matches <script ...> opening tags (including self-closing
// variants) so their attributes can be inspected individually.
var scriptTagPattern = regexp.MustCompile(`(?i)<script\b[^>]*>`)

// linkTagPattern matches <link ...> tags, used to find stylesheet imports.
var linkTagPattern = regexp.MustCompile(`(?i)<link\b[^>]*>`)

// sriSrcAttrPattern extracts the src="..." (or href="...") attribute value.
var sriSrcAttrPattern = regexp.MustCompile(`(?i)\bsrc=["']([^"']+)["']`)
var sriHrefAttrPattern = regexp.MustCompile(`(?i)\bhref=["']([^"']+)["']`)

// sriIntegrityAttrPattern detects a populated integrity="..." attribute.
var sriIntegrityAttrPattern = regexp.MustCompile(`(?i)\bintegrity=["'][^"']+["']`)

// sriRelStylesheetPattern confirms a <link> tag is a stylesheet import.
var sriRelStylesheetPattern = regexp.MustCompile(`(?i)\brel=["']stylesheet["']`)

// sriResource describes a cross-origin script/stylesheet import missing SRI.
type sriResource struct {
	tag string
	src string
}

// runSRIProbe is a passive probe that flags third-party (cross-origin)
// <script src=...> and <link rel="stylesheet" href=...> imports that lack a
// Subresource Integrity (integrity=...) attribute. Without SRI, a compromise
// of the third-party host (including via subdomain/CDN takeover — see
// runSubdomainTakeoverProbe) lets an attacker silently modify the resource
// served to every visitor of this page, a supply-chain risk that generic
// scanners rarely check for since it requires no direct interaction with the
// target itself.
func (s *Service) runSRIProbe(input RunInput, bodyText string) []model.Finding {
	if strings.TrimSpace(bodyText) == "" {
		return nil
	}
	base, err := url.Parse(input.Target)
	if err != nil || base.Host == "" {
		return nil
	}
	// Phase 2 coverage accounting.
	RecordProbedKey("GET", input.Target, "")

	var missing []sriResource
	seen := map[string]bool{}

	collect := func(tags []string, attrPattern *regexp.Regexp, requireStylesheet bool) {
		for _, tag := range tags {
			if requireStylesheet && !sriRelStylesheetPattern.MatchString(tag) {
				continue
			}
			m := attrPattern.FindStringSubmatch(tag)
			if len(m) < 2 {
				continue
			}
			rawSrc := strings.TrimSpace(m[1])
			if rawSrc == "" || strings.HasPrefix(strings.ToLower(rawSrc), "data:") {
				continue
			}
			resolved, err := base.Parse(rawSrc)
			if err != nil || resolved.Host == "" {
				continue
			}
			if !strings.EqualFold(resolved.Hostname(), base.Hostname()) {
				// Cross-origin resource.
				if resolved.Scheme != "http" && resolved.Scheme != "https" {
					continue
				}
				if sriIntegrityAttrPattern.MatchString(tag) {
					continue
				}
				key := strings.ToLower(resolved.String())
				if seen[key] {
					continue
				}
				seen[key] = true
				missing = append(missing, sriResource{tag: tag, src: resolved.String()})
			}
		}
	}

	collect(scriptTagPattern.FindAllString(bodyText, -1), sriSrcAttrPattern, false)
	collect(linkTagPattern.FindAllString(bodyText, -1), sriHrefAttrPattern, true)

	if len(missing) == 0 {
		return nil
	}

	examples := missing
	if len(examples) > 5 {
		examples = examples[:5]
	}
	var evidenceLines []string
	var sources []string
	for _, r := range examples {
		evidenceLines = append(evidenceLines, r.src)
		sources = append(sources, r.src)
	}

	return []model.Finding{
		{
			ID:       "sri-missing-" + hhSlug(input.Target),
			Category: "supply-chain",
			Severity: model.SeverityMedium,
			Title:    fmt.Sprintf("Missing Subresource Integrity on %d third-party resource(s)", len(missing)),
			Description: fmt.Sprintf(
				"The page %s loads %d cross-origin script/stylesheet resource(s) without a Subresource "+
					"Integrity (integrity=\"sha384-...\") attribute. If any of these third-party hosts is "+
					"compromised, mis-configured, or becomes a dangling/takeover-able subdomain, the "+
					"attacker-controlled response is executed or applied in the context of this origin for "+
					"every visitor — a supply-chain compromise that bypasses same-origin protections entirely "+
					"and is easy to miss because the vulnerable resource never touches the target's own "+
					"infrastructure.", input.Target, len(missing),
			),
			Evidence: fmt.Sprintf(
				"Cross-origin resource(s) without integrity attribute:\n%s",
				strings.Join(evidenceLines, "\n"),
			),
			Recommendation: "Add a Subresource Integrity hash (integrity=\"sha384-...\" plus crossorigin=\"anonymous\") " +
				"to every <script> and <link rel=\"stylesheet\"> tag that references a third-party host. " +
				"Where possible, self-host critical third-party assets instead of loading them cross-origin.",
			Confidence:    0.75,
			AffectedURL:   input.Target,
			CWE:           "CWE-829",
			OWASPCategory: "A08:2021 - Software and Data Integrity Failures",
			Sources:       append([]string{"passive-scanner", "sri-probe"}, sources...),
			ReproductionSteps: []string{
				fmt.Sprintf("Fetch %s and view the page source.", input.Target),
				"Locate <script src=...> / <link rel=\"stylesheet\" href=...> tags pointing to third-party hosts.",
				"Confirm none of them carry an integrity=\"...\" attribute.",
			},
			BusinessTags: []string{"supply-chain", "sri", "third-party"},
			EvidenceFields: map[string]string{
				"validationType": "passive-analysis",
				"missingCount":   fmt.Sprintf("%d", len(missing)),
				"exampleTag":     examples[0].tag,
				"exampleSrc":     examples[0].src,
			},
		},
	}
}

// sriSeededMax is the maximum number of seeded runtime endpoints the helper
// fetches for per-page SRI analysis. Kept small because each fetch is an
// extra HTTP round-trip for a passive body scan.
const sriSeededMax = 10

// runSRISeeded fetches up to sriSeededMax seeded runtime endpoints and runs
// the passive SRI probe against each response body. SPA sub-routes often load
// different third-party scripts than the root page — this closes false-
// negatives for missing SRI on those pages.
func (s *Service) runSRISeeded(ctx context.Context, input RunInput, max int) []model.Finding {
	if max <= 0 {
		max = sriSeededMax
	}
	seeds := input.Options.SeedRuntimeEndpoints
	if len(seeds) == 0 {
		return nil
	}
	seen := map[string]bool{input.Target: true}
	var findings []model.Finding
	count := 0
	for _, u := range seeds {
		if count >= max {
			break
		}
		if seen[u] || !scope.IsURLInScope(u, input.Scope) {
			continue
		}
		seen[u] = true
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		_ = resp.Body.Close()
		count++
		seededInput := input
		seededInput.Target = u
		findings = append(findings, s.runSRIProbe(seededInput, string(bodyBytes))...)
	}
	return findings
}
