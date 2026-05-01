// Package wpscan provides a native Go implementation of WordPress security scanning,
// equivalent in scope to the WPScan tool. No external binary is required.
package wpscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// httpClientTimeout is the per-request timeout applied to all HTTP calls in this package.
const httpClientTimeout = 12 * time.Second

// maxResponseBodySize caps the amount of response data read to prevent memory exhaustion.
const maxResponseBodySize = 64 * 1024

// maxRedirectBodySize caps the response body read during redirect-following calls.
const maxRedirectBodySize = 32 * 1024

// Result holds the outcome of a WPScan assessment.
type Result struct {
	IsWordPress bool
	Version     string
	Findings    []model.Finding
}

type detection struct {
	isWP    bool
	version string
}

// popularPlugins is a curated list of widely-used WordPress plugin slugs.
// Each is probed by checking /wp-content/plugins/<slug>/readme.txt.
var popularPlugins = []string{
	"akismet",
	"advanced-custom-fields",
	"bbpress",
	"broken-link-checker",
	"buddypress",
	"classic-editor",
	"contact-form-7",
	"duplicate-page",
	"elementor",
	"jetpack",
	"loginizer",
	"ninja-forms",
	"really-simple-ssl",
	"tablepress",
	"updraftplus",
	"user-role-editor",
	"wordpress-seo",
	"woocommerce",
	"wordfence",
	"wp-file-manager",
	"wp-mail-smtp",
	"wp-smushit",
	"wp-statistics",
	"wp-super-cache",
	"wpforms-lite",
	"w3-total-cache",
}

// popularThemes is a curated list of widely-used WordPress theme slugs.
// Each is probed by checking /wp-content/themes/<slug>/style.css.
var popularThemes = []string{
	"astra",
	"divi",
	"generatepress",
	"hello-elementor",
	"oceanwp",
	"storefront",
	"twentyeighteen",
	"twentynineteen",
	"twentytwenty",
	"twentytwentyone",
	"twentytwentytwo",
	"twentytwentythree",
	"twentytwentyfour",
}

// Scan performs a WPScan-equivalent assessment on target.
// authProfile credentials are applied to every outgoing HTTP request.
// Only http:// and https:// targets are accepted; all other schemes are rejected.
func Scan(ctx context.Context, target string, authProfile model.ScanAuthProfile) Result {
	// Validate that the target uses a safe scheme before making any outbound requests.
	// This is a defence-in-depth check; the caller (scanner.Service) also validates the
	// target URL at the API layer using an allowlist.
	parsed, parseErr := url.Parse(target)
	if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return Result{Findings: make([]model.Finding, 0)}
	}

	client := &http.Client{
		Timeout: httpClientTimeout,
		// Capture redirects but limit to 5 hops to avoid loops.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	result := Result{Findings: make([]model.Finding, 0)}
	base := strings.TrimRight(target, "/")

	d := detectWordPress(ctx, client, base, authProfile)
	result.IsWordPress = d.isWP
	result.Version = d.version

	if !result.IsWordPress {
		return result
	}

	if result.Version != "" {
		result.Findings = append(result.Findings, model.Finding{
			ID:             "wpscan-version-disclosed",
			Category:       "wordpress",
			Severity:       model.SeverityMedium,
			Title:          "WordPress version disclosed",
			Description:    fmt.Sprintf("WordPress version %s is publicly visible, aiding targeted exploitation.", result.Version),
			Evidence:       "version=" + result.Version,
			Recommendation: "Suppress version information from the generator meta tag, RSS feed, and asset query strings. Consider using a security hardening plugin.",
		})
	}

	checks := []func(context.Context, *http.Client, string, model.ScanAuthProfile) []model.Finding{
		checkReadmeHTML,
		checkLicenseTXT,
		checkXMLRPC,
		checkDebugLog,
		checkWPCron,
		checkInstallPHP,
		checkUploadsListing,
		checkUserEnumeration,
		checkPlugins,
		checkThemes,
	}
	for _, check := range checks {
		select {
		case <-ctx.Done():
			return result
		default:
		}
		result.Findings = append(result.Findings, check(ctx, client, base, authProfile)...)
	}

	return result
}

// detectWordPress fingerprints the target to determine whether it runs WordPress.
func detectWordPress(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) detection {
	// Signal 1: wp-login.php returns 200 with recognisable content.
	body, status, _ := getBody(ctx, client, base+"/wp-login.php", auth)
	if status == http.StatusOK && (strings.Contains(body, "wp-login") || strings.Contains(strings.ToLower(body), "wordpress")) {
		return detection{isWP: true, version: extractVersion(ctx, client, base, auth)}
	}

	// Signal 2: wp-content or wp-includes references in the main page, or REST API link header.
	homeBody, _, _ := getBody(ctx, client, base+"/", auth)
	if homeBody == "" {
		homeBody, _, _ = getBody(ctx, client, base, auth)
	}
	if strings.Contains(homeBody, "wp-content/") ||
		strings.Contains(homeBody, "wp-includes/") ||
		strings.Contains(homeBody, "https://api.w.org/") {
		ver := ""
		reGen := regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([0-9]+\.[0-9]+\.?[0-9]*)["']`)
		if m := reGen.FindStringSubmatch(homeBody); len(m) > 1 {
			ver = m[1]
		}
		return detection{isWP: true, version: ver}
	}

	// Signal 3: WordPress REST API root responds with 200.
	_, apiStatus, _ := getBody(ctx, client, base+"/wp-json/", auth)
	if apiStatus == http.StatusOK {
		return detection{isWP: true, version: extractVersion(ctx, client, base, auth)}
	}

	return detection{isWP: false}
}

// extractVersion attempts to discover the WordPress version from multiple passive sources.
func extractVersion(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) string {
	// Source 1: readme.html "Version X.Y.Z" line.
	body, status, _ := getBody(ctx, client, base+"/readme.html", auth)
	if status == http.StatusOK {
		re := regexp.MustCompile(`[Vv]ersion\s+([0-9]+\.[0-9]+\.?[0-9]*)`)
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			return m[1]
		}
	}

	// Source 2: Generator meta tag in the main page.
	body, _, _ = getBody(ctx, client, base+"/", auth)
	reGen := regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([0-9]+\.[0-9]+\.?[0-9]*)["']`)
	if m := reGen.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}

	// Source 3: RSS feed generator element.
	rssBody, _, _ := getBody(ctx, client, base+"/?feed=rss2", auth)
	reRSS := regexp.MustCompile(`<generator>https://wordpress\.org/\?v=([0-9]+\.[0-9]+\.?[0-9]*)</generator>`)
	if m := reRSS.FindStringSubmatch(rssBody); len(m) > 1 {
		return m[1]
	}

	return ""
}

func checkReadmeHTML(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	_, status, _ := getBody(ctx, client, base+"/readme.html", auth)
	if status != http.StatusOK {
		return nil
	}
	return []model.Finding{{
		ID:             "wpscan-readme-html",
		Category:       "wordpress",
		Severity:       model.SeverityMedium,
		Title:          "WordPress readme.html is publicly accessible",
		Description:    "readme.html discloses the WordPress version and installation details; it is not required in production.",
		Evidence:       "HTTP 200: " + base + "/readme.html",
		Recommendation: "Delete readme.html or block access to it via web server configuration.",
	}}
}

func checkLicenseTXT(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	_, status, _ := getBody(ctx, client, base+"/license.txt", auth)
	if status != http.StatusOK {
		return nil
	}
	return []model.Finding{{
		ID:             "wpscan-license-txt",
		Category:       "wordpress",
		Severity:       model.SeverityInfo,
		Title:          "WordPress license.txt is publicly accessible",
		Description:    "license.txt confirms the use of WordPress and may hint at the version.",
		Evidence:       "HTTP 200: " + base + "/license.txt",
		Recommendation: "Remove or block access to license.txt from the web root.",
	}}
}

func checkXMLRPC(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	body, status, _ := getBody(ctx, client, base+"/xmlrpc.php", auth)
	if status != http.StatusOK && status != http.StatusMethodNotAllowed {
		return nil
	}
	if status == http.StatusOK && !strings.Contains(body, "XML-RPC") {
		return nil
	}
	return []model.Finding{{
		ID:             "wpscan-xmlrpc-enabled",
		Category:       "wordpress",
		Severity:       model.SeverityMedium,
		Title:          "WordPress xmlrpc.php is enabled",
		Description:    "xmlrpc.php enables remote method calls and can be abused for credential brute-forcing (system.multicall) and DDoS amplification.",
		Evidence:       fmt.Sprintf("HTTP %d: %s/xmlrpc.php", status, base),
		Recommendation: "Disable XML-RPC with `add_filter('xmlrpc_enabled', '__return_false');` if it is not required, or restrict access via the web server.",
	}}
}

func checkDebugLog(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	body, status, _ := getBody(ctx, client, base+"/wp-content/debug.log", auth)
	if status != http.StatusOK || len(body) < 20 {
		return nil
	}
	return []model.Finding{{
		ID:             "wpscan-debug-log",
		Category:       "wordpress",
		Severity:       model.SeverityHigh,
		Title:          "WordPress debug.log is publicly accessible",
		Description:    "The WordPress debug log is reachable and may contain PHP errors, stack traces, file paths, database details, and credentials.",
		Evidence:       "HTTP 200: " + base + "/wp-content/debug.log",
		Recommendation: "Block web access to wp-content/debug.log, set WP_DEBUG_LOG to false in production, and move any log file outside the web root.",
	}}
}

func checkWPCron(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	_, status, _ := getBody(ctx, client, base+"/wp-cron.php", auth)
	if status != http.StatusOK {
		return nil
	}
	return []model.Finding{{
		ID:             "wpscan-wp-cron",
		Category:       "wordpress",
		Severity:       model.SeverityLow,
		Title:          "WordPress wp-cron.php is publicly accessible",
		Description:    "wp-cron.php is reachable without authentication and can be triggered repeatedly to cause a denial of service.",
		Evidence:       "HTTP 200: " + base + "/wp-cron.php",
		Recommendation: "Disable the default WordPress pseudo-cron by adding `define('DISABLE_WP_CRON', true);` to wp-config.php and use a real server-side cron job instead.",
	}}
}

func checkInstallPHP(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	body, status, _ := getBody(ctx, client, base+"/wp-admin/install.php", auth)
	if status != http.StatusOK {
		return nil
	}
	if !strings.Contains(strings.ToLower(body), "install") {
		return nil
	}
	return []model.Finding{{
		ID:             "wpscan-install-php",
		Category:       "wordpress",
		Severity:       model.SeverityHigh,
		Title:          "WordPress install.php is accessible",
		Description:    "The WordPress installation script is reachable, which could allow a full reinstallation and an attacker-controlled admin account.",
		Evidence:       "HTTP 200: " + base + "/wp-admin/install.php",
		Recommendation: "Block access to wp-admin/install.php via the web server configuration on production sites.",
	}}
}

func checkUploadsListing(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	body, status, _ := getBody(ctx, client, base+"/wp-content/uploads/", auth)
	if status != http.StatusOK {
		return nil
	}
	if !strings.Contains(body, "Index of") && !strings.Contains(body, "Parent Directory") && !strings.Contains(body, "<a href=") {
		return nil
	}
	return []model.Finding{{
		ID:             "wpscan-uploads-listing",
		Category:       "wordpress",
		Severity:       model.SeverityMedium,
		Title:          "WordPress uploads directory listing is enabled",
		Description:    "Directory listing is active on wp-content/uploads/, exposing all uploaded files.",
		Evidence:       "HTTP 200 with listing: " + base + "/wp-content/uploads/",
		Recommendation: "Disable directory listing in the web server configuration (e.g. `Options -Indexes` in Apache or `autoindex off` in Nginx).",
	}}
}

func checkUserEnumeration(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Method 1: REST API users endpoint.
	apiBody, apiStatus, _ := getBody(ctx, client, base+"/wp-json/wp/v2/users", auth)
	if apiStatus == http.StatusOK && strings.Contains(apiBody, `"slug"`) {
		findings = append(findings, model.Finding{
			ID:             "wpscan-user-enum-rest",
			Category:       "wordpress",
			Severity:       model.SeverityMedium,
			Title:          "WordPress user enumeration via REST API",
			Description:    "The /wp-json/wp/v2/users endpoint exposes WordPress usernames without authentication, aiding brute-force attacks.",
			Evidence:       "HTTP 200: " + base + "/wp-json/wp/v2/users",
			Recommendation: "Restrict the REST API users endpoint to authenticated users, or disable it via a security plugin.",
		})
	}

	// Method 2: /?author=N redirect leaks username in the Location header / final URL.
	_, authorStatus, finalURL := getBodyFollowRedirect(ctx, base+"/?author=1", auth)
	if authorStatus == http.StatusOK && strings.Contains(finalURL, "/author/") {
		findings = append(findings, model.Finding{
			ID:             "wpscan-user-enum-author",
			Category:       "wordpress",
			Severity:       model.SeverityMedium,
			Title:          "WordPress user enumeration via author parameter",
			Description:    "Requesting /?author=N redirects to /author/<username>, enabling systematic username enumeration.",
			Evidence:       "/?author=1 resolved to " + finalURL,
			Recommendation: "Block author enumeration by preventing /?author=N redirects, disabling author archives, or using a security plugin.",
		})
	}

	return findings
}

func checkPlugins(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)
	reVer := regexp.MustCompile(`(?i)[Ss]table\s+[Tt]ag:\s*([0-9]+\.[0-9]+\.?[0-9]*)`)

	for _, slug := range popularPlugins {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		body, status, _ := getBody(ctx, client, base+"/wp-content/plugins/"+slug+"/readme.txt", auth)
		if status != http.StatusOK || len(body) < 20 {
			continue
		}

		version := ""
		if m := reVer.FindStringSubmatch(body); len(m) > 1 {
			version = m[1]
		}

		evidence := "HTTP 200: " + base + "/wp-content/plugins/" + slug + "/readme.txt"
		if version != "" {
			evidence += " (version=" + version + ")"
		}

		findings = append(findings, model.Finding{
			ID:             "wpscan-plugin-" + slug,
			Category:       "wordpress",
			Severity:       model.SeverityInfo,
			Title:          "WordPress plugin detected: " + slug,
			Description:    fmt.Sprintf("Plugin '%s' is installed and its readme.txt is publicly readable, potentially disclosing the installed version.", slug),
			Evidence:       evidence,
			Recommendation: "Keep all plugins up to date. Block web access to plugin readme.txt files. Regularly audit installed plugins for known CVEs.",
		})
	}

	return findings
}

func checkThemes(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)
	reVer := regexp.MustCompile(`(?i)Version:\s*([0-9]+\.[0-9]+\.?[0-9]*)`)

	for _, slug := range popularThemes {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		body, status, _ := getBody(ctx, client, base+"/wp-content/themes/"+slug+"/style.css", auth)
		if status != http.StatusOK || len(body) < 20 {
			continue
		}

		version := ""
		if m := reVer.FindStringSubmatch(body); len(m) > 1 {
			version = m[1]
		}

		evidence := "HTTP 200: " + base + "/wp-content/themes/" + slug + "/style.css"
		if version != "" {
			evidence += " (version=" + version + ")"
		}

		findings = append(findings, model.Finding{
			ID:             "wpscan-theme-" + slug,
			Category:       "wordpress",
			Severity:       model.SeverityInfo,
			Title:          "WordPress theme detected: " + slug,
			Description:    fmt.Sprintf("Theme '%s' is installed and its style.css is publicly readable, potentially disclosing the installed version.", slug),
			Evidence:       evidence,
			Recommendation: "Keep all themes up to date. Remove unused themes. Check for known theme vulnerabilities.",
		})
	}

	return findings
}

// getBody performs an authenticated GET and returns the response body, HTTP status code, and any error.
// The body is capped at 64 KiB to avoid memory exhaustion on large responses.
func getBody(ctx context.Context, client *http.Client, target string, auth model.ScanAuthProfile) (body string, status int, err error) {
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if reqErr != nil {
		return "", 0, reqErr
	}
	applyAuthProfile(req, auth)
	resp, doErr := client.Do(req)
	if doErr != nil {
		return "", 0, doErr
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	return string(b), resp.StatusCode, nil
}

// getBodyFollowRedirect performs an authenticated GET, follows redirects, and returns the final
// response body, HTTP status code, and final URL (useful for detecting author-redirect enumeration).
func getBodyFollowRedirect(ctx context.Context, target string, auth model.ScanAuthProfile) (body string, status int, finalURL string) {
	client := &http.Client{
		Timeout: httpClientTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, ""
	}
	applyAuthProfile(req, auth)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRedirectBodySize))
	return string(b), resp.StatusCode, resp.Request.URL.String()
}

// applyAuthProfile applies the provided credentials to an outgoing HTTP request.
// This mirrors scanner.ApplyAuthProfile to avoid a circular import dependency,
// including its CRLF/NUL rejection on header names and values.
func applyAuthProfile(req *http.Request, profile model.ScanAuthProfile) {
	if req == nil {
		return
	}
	for key, value := range profile.Headers {
		key = strings.TrimSpace(key)
		if key == "" || !isSafeHeaderName(key) || !isSafeHeaderValue(value) {
			continue
		}
		req.Header.Set(key, value)
	}
	if profile.UserAgent != "" && isSafeHeaderValue(profile.UserAgent) {
		req.Header.Set("User-Agent", profile.UserAgent)
	}
	if profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "" {
		req.SetBasicAuth(profile.BasicAuthUsername, profile.BasicAuthPassword)
	}
	if len(profile.Cookies) > 0 {
		parts := make([]string, 0, len(profile.Cookies))
		for name, val := range profile.Cookies {
			if !isSafeHeaderValue(name) || !isSafeHeaderValue(val) {
				continue
			}
			parts = append(parts, name+"="+val)
		}
		if len(parts) > 0 {
			req.Header.Set("Cookie", strings.Join(parts, "; "))
		}
	}
}

func isSafeHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}

func isSafeHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\r' || c == '\n' || c == 0 {
			return false
		}
	}
	return true
}
