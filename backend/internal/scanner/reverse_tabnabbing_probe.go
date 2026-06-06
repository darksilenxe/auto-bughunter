package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// tabnabbingPattern matches anchor tags with target="_blank" (case-insensitive).
var tabnabbingPattern = regexp.MustCompile(`(?i)<a\b[^>]*\btarget=["']?_blank["']?[^>]*>`)

// noopenerPattern checks whether an anchor tag has rel="noopener" or rel="noreferrer".
// A safe anchor must include both (or "noopener noreferrer").
var noopenerPattern = regexp.MustCompile(`(?i)\brel=["'][^"']*noopener[^"']*["']`)
var noreferrerPattern = regexp.MustCompile(`(?i)\brel=["'][^"']*noreferrer[^"']*["']`)

// runReverseTabnabbingProbe is a passive probe covering WSTG-CLNT-14.
//
// It scans the page body text for anchor tags with target="_blank" that are
// missing rel="noopener" and/or rel="noreferrer". Without these attributes,
// the opened page can navigate the opener's window via window.opener.location,
// enabling phishing attacks (reverse tabnabbing).
//
// This is a zero-request passive probe — it only inspects the already-fetched
// page HTML supplied in bodyText.
func (s *Service) runReverseTabnabbingProbe(input RunInput, bodyText string) []model.Finding {
	if strings.TrimSpace(bodyText) == "" {
		return nil
	}

	anchors := tabnabbingPattern.FindAllString(bodyText, -1)
	if len(anchors) == 0 {
		return nil
	}

	var vulnerable []string
	seen := map[string]bool{}
	for _, anchor := range anchors {
		hasNoopener := noopenerPattern.MatchString(anchor)
		hasNoreferrer := noreferrerPattern.MatchString(anchor)
		if !hasNoopener || !hasNoreferrer {
			key := strings.ToLower(anchor)
			if !seen[key] {
				seen[key] = true
				vulnerable = append(vulnerable, anchor)
			}
		}
	}

	if len(vulnerable) == 0 {
		return nil
	}

	// Build concise evidence list (cap at 5 examples).
	evidenceExamples := vulnerable
	if len(evidenceExamples) > 5 {
		evidenceExamples = evidenceExamples[:5]
	}

	return []model.Finding{
		{
			ID:       "reverse-tabnabbing-" + hhSlug(input.Target),
			Category: "client-side",
			Severity: model.SeverityLow,
			Title:    fmt.Sprintf("Reverse tabnabbing — %d link(s) missing rel=\"noopener noreferrer\"", len(vulnerable)),
			Description: fmt.Sprintf(
				"The page %s contains %d anchor tag(s) with target=\"_blank\" that are missing "+
					"rel=\"noopener\" and/or rel=\"noreferrer\". A page opened via such a link retains "+
					"a reference to the opener's window via window.opener, allowing the opened page to "+
					"redirect the original tab to a phishing page (reverse tabnabbing). This is a "+
					"low-severity finding but is trivially exploitable when user-controlled links are "+
					"rendered (e.g. forum posts, comments, user profiles).",
				input.Target, len(vulnerable),
			),
			Evidence: fmt.Sprintf(
				"Found %d target=\"_blank\" link(s) without rel=\"noopener noreferrer\" at %s. "+
					"Examples:\n%s",
				len(vulnerable), input.Target, strings.Join(evidenceExamples, "\n"),
			),
			Recommendation: "Add rel=\"noopener noreferrer\" to all anchor tags with target=\"_blank\":\n" +
				"<a href=\"...\" target=\"_blank\" rel=\"noopener noreferrer\">...</a>\n\n" +
				"Most modern linters (ESLint jsx-a11y, HTMLHint) can enforce this automatically. " +
				"Consider also using the 'noopener' default via <meta name=\"referrer\"> or HTTP headers.",
			Confidence:    0.95,
			AffectedURL:   input.Target,
			CWE:           "CWE-1022",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"passive-scanner", "reverse-tabnabbing-probe"},
			ReproductionSteps: []string{
				fmt.Sprintf("Visit %s and view the page source.", input.Target),
				"Search for anchor tags containing target=\"_blank\".",
				"Verify that the matching anchors do not have rel=\"noopener noreferrer\".",
				"Click such a link — the opened page can access window.opener from the new tab.",
			},
			BusinessTags: []string{"tabnabbing", "phishing", "client-side"},
			EvidenceFields: map[string]string{
				"validationType":   "passive-analysis",
				"vulnerableLinks":  fmt.Sprintf("%d", len(vulnerable)),
				"exampleAnchorTag": evidenceExamples[0],
			},
		},
	}
}
