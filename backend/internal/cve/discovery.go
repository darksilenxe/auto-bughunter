package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

const (
	defaultRecentCVEFeedURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultRecentCVELookback = 14 * 24 * time.Hour
	defaultRecentCVELimit    = 12
)

var webRelevanceKeywords = []string{
	"web", "http", "https", "browser", "xss", "csrf", "sqli", "sql injection",
	"ssrf", "rce", "open redirect", "template injection", "deserialization",
	"path traversal", "directory traversal", "graphql", "oauth", "jwt",
	"cookie", "session", "cors", "apache", "nginx", "wordpress", "drupal",
	"joomla", "tomcat", "spring", "struts", "php", "django", "rails",
}

// DiscoveryOptions customizes recent CVE feed lookup.
type DiscoveryOptions struct {
	Client     *http.Client
	BaseURL    string
	Lookback   time.Duration
	MaxResults int
	Now        func() time.Time
}

// DiscoveredCVE is a recent feed record enriched with stack-match context.
type DiscoveredCVE struct {
	Record              Record
	MatchedTechnologies []string
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID             string `json:"id"`
	Published      string `json:"published"`
	Descriptions   []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Metrics nvdMetrics `json:"metrics"`
	Configs []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdMetrics struct {
	CVSSv31 []struct {
		CVSSData struct {
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CVSSv30 []struct {
		CVSSData struct {
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CVSSv2 []struct {
		CVSSData struct {
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
		} `json:"cvssData"`
	} `json:"cvssMetricV2"`
}

type scoredDiscovery struct {
	item          DiscoveredCVE
	publishedTime time.Time
	score         int
}

// DiscoverRecentWebCVEs fetches recently published CVEs and returns
// de-duplicated web-application-relevant records prioritized by observed stack
// technologies present in findings.
func DiscoverRecentWebCVEs(ctx context.Context, findings []model.Finding, opts DiscoveryOptions) ([]DiscoveredCVE, error) {
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	baseURL := strings.TrimSpace(opts.BaseURL)
	if baseURL == "" {
		baseURL = defaultRecentCVEFeedURL
	}
	lookback := opts.Lookback
	if lookback <= 0 {
		lookback = defaultRecentCVELookback
	}
	limit := opts.MaxResults
	if limit <= 0 {
		limit = defaultRecentCVELimit
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	requestURL, err := buildRecentCVERequestURL(baseURL, nowFn().UTC().Add(-lookback))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "auto-bughunter-cve-discovery")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("recent cve feed request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("recent cve feed returned status %d", resp.StatusCode)
	}

	var parsed nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("recent cve feed decode failed: %w", err)
	}

	knownCVEs := make(map[string]bool)
	for _, f := range findings {
		for _, id := range DetectFindingCVEs(f) {
			knownCVEs[id] = true
		}
	}
	observedTech := extractObservedTechnologies(findings)
	seen := make(map[string]bool)
	scored := make([]scoredDiscovery, 0, len(parsed.Vulnerabilities))

	for _, v := range parsed.Vulnerabilities {
		id := Normalize(v.CVE.ID)
		if id == "" || seen[id] || knownCVEs[id] {
			continue
		}
		seen[id] = true

		summary := pickEnglish(v.CVE.Descriptions)
		matchedTech := matchTechnologies(v.CVE, summary, observedTech)
		webRelevant := isWebRelevant(summary, v.CVE, matchedTech)
		if !webRelevant {
			continue
		}

		cwe := pickWeakness(v.CVE.Weaknesses)
		vector, score := pickCVSS(v.CVE.Metrics)
		refs := make([]string, 0, len(v.CVE.References))
		for _, r := range v.CVE.References {
			if u := strings.TrimSpace(r.URL); u != "" {
				refs = append(refs, u)
			}
		}
		refs = appendUniqueStrings(refs, "https://nvd.nist.gov/vuln/detail/"+id)

		record := Record{
			ID:                  id,
			Summary:             summary,
			CWE:                 cwe,
			CVSSVector:          vector,
			CVSSScore:           score,
			References:          refs,
			Source:              "nvd-recent",
			PublishedDate:       strings.TrimSpace(v.CVE.Published),
			MatchedTechnologies: append([]string{}, matchedTech...),
		}
		publishedAt, _ := time.Parse(time.RFC3339, record.PublishedDate)
		scoreBoost := len(matchedTech) * 100
		if score >= 9 {
			scoreBoost += 20
		} else if score >= 7 {
			scoreBoost += 10
		}
		scored = append(scored, scoredDiscovery{
			item: DiscoveredCVE{
				Record:              record,
				MatchedTechnologies: matchedTech,
			},
			publishedTime: publishedAt,
			score:         scoreBoost,
		})
	}

	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		if !scored[i].publishedTime.Equal(scored[j].publishedTime) {
			return scored[i].publishedTime.After(scored[j].publishedTime)
		}
		return scored[i].item.Record.ID < scored[j].item.Record.ID
	})

	if len(scored) > limit {
		scored = scored[:limit]
	}
	out := make([]DiscoveredCVE, 0, len(scored))
	for _, s := range scored {
		out = append(out, s.item)
	}
	return out, nil
}

func buildRecentCVERequestURL(baseURL string, publishedStart time.Time) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid recent cve base url: %w", err)
	}
	q := u.Query()
	q.Set("pubStartDate", publishedStart.UTC().Format(time.RFC3339))
	q.Set("resultsPerPage", "200")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func pickEnglish(items []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range items {
		if strings.EqualFold(strings.TrimSpace(d.Lang), "en") {
			if text := strings.TrimSpace(d.Value); text != "" {
				return text
			}
		}
	}
	for _, d := range items {
		if text := strings.TrimSpace(d.Value); text != "" {
			return text
		}
	}
	return ""
}

func pickWeakness(items []struct {
	Description []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
}) string {
	for _, w := range items {
		for _, d := range w.Description {
			if strings.EqualFold(strings.TrimSpace(d.Lang), "en") {
				value := strings.TrimSpace(d.Value)
				if strings.HasPrefix(strings.ToUpper(value), "CWE-") {
					return strings.ToUpper(value)
				}
			}
		}
	}
	return ""
}

func pickCVSS(m nvdMetrics) (string, float64) {
	if len(m.CVSSv31) > 0 {
		return strings.TrimSpace(m.CVSSv31[0].CVSSData.VectorString), m.CVSSv31[0].CVSSData.BaseScore
	}
	if len(m.CVSSv30) > 0 {
		return strings.TrimSpace(m.CVSSv30[0].CVSSData.VectorString), m.CVSSv30[0].CVSSData.BaseScore
	}
	if len(m.CVSSv2) > 0 {
		return strings.TrimSpace(m.CVSSv2[0].CVSSData.VectorString), m.CVSSv2[0].CVSSData.BaseScore
	}
	return "", 0
}

func extractObservedTechnologies(findings []model.Finding) []string {
	seen := map[string]bool{}
	out := make([]string, 0)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		lower := strings.ToLower(raw)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, raw)
	}

	for _, f := range findings {
		text := strings.TrimSpace(f.Evidence)
		if idx := strings.Index(strings.ToLower(text), "top="); idx >= 0 {
			top := text[idx+4:]
			if comma := strings.Index(top, ", "); comma >= 0 {
				top = top[:comma]
			}
			for _, part := range strings.Split(top, ",") {
				add(part)
			}
		}
		for _, textPart := range []string{f.Title, f.Description, f.Evidence} {
			for _, kw := range []string{"wordpress", "drupal", "joomla", "apache", "nginx", "tomcat", "spring", "struts", "php", "django", "rails"} {
				if strings.Contains(strings.ToLower(textPart), kw) {
					add(kw)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func matchTechnologies(cve nvdCVE, summary string, observed []string) []string {
	if len(observed) == 0 {
		return nil
	}
	text := strings.ToLower(summary)
	for _, cfg := range cve.Configs {
		for _, n := range cfg.Nodes {
			for _, cpe := range n.CPEMatch {
				text += " " + strings.ToLower(cpe.Criteria)
			}
		}
	}
	matched := make([]string, 0)
	for _, tech := range observed {
		t := strings.ToLower(strings.TrimSpace(tech))
		if t == "" {
			continue
		}
		if strings.Contains(text, t) {
			matched = append(matched, tech)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return strings.ToLower(matched[i]) < strings.ToLower(matched[j])
	})
	return matched
}

func isWebRelevant(summary string, cve nvdCVE, matchedTech []string) bool {
	if len(matchedTech) > 0 {
		return true
	}
	text := strings.ToLower(summary)
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			text += " " + strings.ToLower(strings.TrimSpace(d.Value))
		}
	}
	for _, kw := range webRelevanceKeywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	for _, cfg := range cve.Configs {
		for _, n := range cfg.Nodes {
			for _, cpe := range n.CPEMatch {
				c := strings.ToLower(cpe.Criteria)
				if strings.Contains(c, "a:httpd") || strings.Contains(c, "a:nginx") || strings.Contains(c, "a:wordpress") || strings.Contains(c, "a:drupal") {
					return true
				}
			}
		}
	}
	return false
}

func appendUniqueStrings(in []string, item string) []string {
	item = strings.TrimSpace(item)
	if item == "" {
		return in
	}
	for _, existing := range in {
		if strings.EqualFold(strings.TrimSpace(existing), item) {
			return in
		}
	}
	return append(in, item)
}
