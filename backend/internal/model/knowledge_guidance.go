package model

import (
	"fmt"
	"strings"
)

// PromptGuidance renders the retrieved security-knowledge references into a
// compact, prompt-injectable text block so the AI can ground its vulnerability
// detection and tool/command selection in curated HackTricks /
// PayloadsAllTheThings guidance. It returns an empty string when there is no
// context. maxRefs bounds how many references are included (<=0 means all).
// perRefContent bounds how many characters of each reference's full-text body
// are included (<=0 omits bodies, keeping only the short curated passage).
func (c *SecurityKnowledgeContext) PromptGuidance(maxRefs, perRefContent int) string {
	if c == nil || len(c.References) == 0 {
		return ""
	}
	refs := c.References
	if maxRefs > 0 && len(refs) > maxRefs {
		refs = refs[:maxRefs]
	}
	var b strings.Builder
	b.WriteString("Security knowledge (curated references — use to choose techniques, payloads, and tool/command invocations):\n")
	for i, r := range refs {
		title := strings.TrimSpace(r.Title)
		if title == "" {
			title = strings.TrimSpace(r.ID)
		}
		b.WriteString(fmt.Sprintf("%d. %s", i+1, title))
		meta := make([]string, 0, 3)
		if v := strings.TrimSpace(r.VulnerabilityClass); v != "" {
			meta = append(meta, "class="+v)
		}
		if t := strings.TrimSpace(r.Technique); t != "" {
			meta = append(meta, "technique="+t)
		}
		if len(meta) > 0 {
			b.WriteString(" [" + strings.Join(meta, "; ") + "]")
		}
		b.WriteString("\n")
		if p := strings.TrimSpace(r.Passage); p != "" {
			b.WriteString("   note: " + p + "\n")
		}
		if perRefContent > 0 {
			if body := strings.TrimSpace(r.Content); body != "" {
				if len(body) > perRefContent {
					body = body[:perRefContent]
				}
				b.WriteString("   detail: " + strings.ReplaceAll(body, "\n", " ") + "\n")
			}
		}
		if u := strings.TrimSpace(r.URL); u != "" {
			b.WriteString("   source: " + u + "\n")
		}
	}
	if len(c.SuggestedActions) > 0 {
		b.WriteString("Suggested actions: " + strings.Join(c.SuggestedActions, "; ") + "\n")
	}
	if notice := strings.TrimSpace(c.LicenseNotice); notice != "" {
		b.WriteString("Attribution: " + notice + "\n")
	}
	return b.String()
}
