// Package nikto provides a native Go implementation of web application security
// scanning equivalent in scope to the Nikto CLI tool. No external binary is required.
package nikto

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
)

// httpTimeout is the per-request timeout applied to all HTTP calls in this package.
const httpTimeout = 10 * time.Second

// maxBodySize caps the amount of response data read to prevent memory exhaustion.
const maxBodySize = 64 * 1024

// workerCount is the number of concurrent goroutines used for path checks.
const workerCount = 15

// Result holds the outcome of a Nikto scan.
type Result struct {
	// ServerSoftware is the web server software identified from response headers.
	ServerSoftware string
	// Findings contains all security issues discovered during the scan.
	Findings []model.Finding
}

// interestingPath describes a URL path to probe and how to interpret the response.
type interestingPath struct {
	path           string
	id             string
	category       string
	severity       model.Severity
	title          string
	description    string
	recommendation string
	// bodyConfirm is a substring that must appear in the body for a 200 to be flagged.
	// If empty, any 200 is flagged.
	bodyConfirm string
	// flagProtected, when true, also flags 401 and 403 responses (protected resource exists).
	flagProtected bool
}

// interestingPaths is the master list of paths probed during a Nikto scan.
// It covers configuration files, admin panels, backup artifacts, version control
// leftovers, API documentation, CGI scripts, and monitoring endpoints.
var interestingPaths = []interestingPath{
	// ── Environment / Secrets ──────────────────────────────────────────────────
	{
		path: "/.env", id: "nikto-env-exposed", category: "config",
		severity: model.SeverityHigh, title: "Environment configuration file exposed",
		description:    "The .env file is publicly accessible and may contain database credentials, API keys, and other secrets.",
		recommendation: "Remove .env from the web root. Inject secrets via runtime environment variables instead.",
	},
	{
		path: "/.env.bak", id: "nikto-env-bak-exposed", category: "config",
		severity: model.SeverityHigh, title: "Environment configuration backup exposed",
		description:    "A backup of the .env file is publicly accessible.",
		recommendation: "Remove all .env backup files from the web root.",
	},
	{
		path: "/.env.local", id: "nikto-env-local-exposed", category: "config",
		severity: model.SeverityHigh, title: "Local environment configuration exposed",
		description:    "The .env.local file is publicly accessible.",
		recommendation: "Remove .env.local from the web root.",
	},
	{
		path: "/.env.production", id: "nikto-env-production-exposed", category: "config",
		severity: model.SeverityHigh, title: "Production environment configuration exposed",
		description:    "The .env.production file is publicly accessible.",
		recommendation: "Remove .env.production from the web root.",
	},
	// ── PHP Configuration ──────────────────────────────────────────────────────
	{
		path: "/config.php", id: "nikto-config-php", category: "config",
		severity: model.SeverityHigh, title: "PHP configuration file exposed",
		description:    "A PHP configuration file is accessible and may contain database credentials.",
		recommendation: "Move configuration files outside the document root.",
	},
	{
		path: "/configuration.php", id: "nikto-configuration-php", category: "config",
		severity: model.SeverityHigh, title: "PHP configuration file exposed",
		description:    "A PHP configuration file is accessible and may contain credentials.",
		recommendation: "Move configuration files outside the document root.",
	},
	{
		path: "/config.inc.php", id: "nikto-config-inc-php", category: "config",
		severity: model.SeverityHigh, title: "PHP configuration include file exposed",
		description:    "A PHP configuration include file is accessible.",
		recommendation: "Move configuration files outside the document root.",
	},
	{
		path: "/db.php", id: "nikto-db-php", category: "config",
		severity: model.SeverityHigh, title: "Database configuration file exposed",
		description:    "A PHP database configuration file is accessible.",
		recommendation: "Move database configuration outside the document root.",
	},
	{
		path: "/database.php", id: "nikto-database-php", category: "config",
		severity: model.SeverityHigh, title: "Database configuration file exposed",
		description:    "A PHP database configuration file is accessible.",
		recommendation: "Move database configuration outside the document root.",
	},
	{
		path: "/settings.php", id: "nikto-settings-php", category: "config",
		severity: model.SeverityHigh, title: "Settings configuration file exposed",
		description:    "An application settings file is accessible and may contain sensitive configuration.",
		recommendation: "Move settings files outside the document root.",
	},
	{
		path: "/wp-config.php", id: "nikto-wp-config", category: "config",
		severity: model.SeverityHigh, title: "WordPress configuration file exposed",
		description:    "wp-config.php contains database credentials and authentication keys.",
		recommendation: "Verify this returns 403. Consider moving wp-config.php one level above the document root.",
	},
	{
		path: "/wp-config.php.bak", id: "nikto-wp-config-bak", category: "config",
		severity: model.SeverityHigh, title: "WordPress configuration backup exposed",
		description:    "A backup of wp-config.php is accessible and contains database credentials.",
		recommendation: "Remove all wp-config backup files immediately.",
	},
	// ── ASP.NET / Spring ───────────────────────────────────────────────────────
	{
		path: "/web.config", id: "nikto-web-config", category: "config",
		severity: model.SeverityHigh, title: "ASP.NET web.config exposed",
		description:    "web.config may contain connection strings and sensitive application settings.",
		recommendation: "Restrict access to web.config. IIS protects it by default; verify custom handlers do not bypass this.",
	},
	{
		path: "/application.properties", id: "nikto-app-properties", category: "config",
		severity: model.SeverityHigh, title: "Spring Boot application.properties exposed",
		description:    "Spring Boot configuration file may contain database URLs, credentials, and API keys.",
		recommendation: "Do not serve configuration files from the document root.",
	},
	{
		path: "/application.yml", id: "nikto-app-yml", category: "config",
		severity: model.SeverityHigh, title: "Spring Boot application.yml exposed",
		description:    "Spring Boot YAML configuration may contain sensitive settings.",
		recommendation: "Do not serve configuration files from the document root.",
	},
	// ── Database Dumps ─────────────────────────────────────────────────────────
	{
		path: "/backup.sql", id: "nikto-backup-sql", category: "backup",
		severity: model.SeverityHigh, title: "SQL database dump exposed",
		description:    "A SQL dump file is publicly accessible and likely contains the entire database.",
		recommendation: "Remove all database dump files from the web root immediately.",
	},
	{
		path: "/database.sql", id: "nikto-database-sql", category: "backup",
		severity: model.SeverityHigh, title: "SQL database dump exposed",
		description:    "A SQL dump file is publicly accessible.",
		recommendation: "Remove all database dump files from the web root.",
	},
	{
		path: "/db.sql", id: "nikto-db-sql", category: "backup",
		severity: model.SeverityHigh, title: "SQL database dump exposed",
		description:    "A SQL dump file is publicly accessible.",
		recommendation: "Remove all database dump files from the web root.",
	},
	{
		path: "/dump.sql", id: "nikto-dump-sql", category: "backup",
		severity: model.SeverityHigh, title: "SQL database dump exposed",
		description:    "A SQL dump file is publicly accessible.",
		recommendation: "Remove all database dump files from the web root.",
	},
	// ── Version Control ────────────────────────────────────────────────────────
	{
		path: "/.git/config", id: "nikto-git-config", category: "vcs",
		severity: model.SeverityHigh, title: "Git repository configuration exposed",
		description:    "The .git/config file is accessible, potentially exposing repository URLs and stored credentials.",
		recommendation: "Block access to .git directories via web server rules (e.g. Deny from all or a location block).",
		bodyConfirm:    "[core]",
	},
	{
		path: "/.git/HEAD", id: "nikto-git-head", category: "vcs",
		severity: model.SeverityHigh, title: "Git repository HEAD file exposed",
		description:    ".git/HEAD is accessible, confirming an exposed git repository in the web root.",
		recommendation: "Block access to .git directories via web server configuration.",
		bodyConfirm:    "ref:",
	},
	{
		path: "/.svn/entries", id: "nikto-svn-entries", category: "vcs",
		severity: model.SeverityHigh, title: "SVN repository entries file exposed",
		description:    "The Subversion repository entries file is accessible.",
		recommendation: "Block access to .svn directories via web server configuration.",
	},
	{
		path: "/.hg/store/00manifest.i", id: "nikto-hg-store", category: "vcs",
		severity: model.SeverityMedium, title: "Mercurial repository data exposed",
		description:    "Mercurial repository store data appears to be accessible.",
		recommendation: "Block access to .hg directories via web server configuration.",
	},
	// ── PHP Info & Debug ───────────────────────────────────────────────────────
	{
		path: "/phpinfo.php", id: "nikto-phpinfo", category: "disclosure",
		severity: model.SeverityHigh, title: "PHP info page exposed (phpinfo.php)",
		description:    "phpinfo.php exposes detailed PHP configuration including loaded modules, environment variables, and server paths.",
		recommendation: "Remove phpinfo.php from production servers.",
		bodyConfirm:    "phpinfo",
	},
	{
		path: "/info.php", id: "nikto-info-php", category: "disclosure",
		severity: model.SeverityHigh, title: "PHP info page exposed (info.php)",
		description:    "info.php likely calls phpinfo() and exposes detailed PHP and server configuration.",
		recommendation: "Remove info.php from production servers.",
		bodyConfirm:    "phpinfo",
	},
	{
		path: "/php_info.php", id: "nikto-php-info", category: "disclosure",
		severity: model.SeverityHigh, title: "PHP info page exposed (php_info.php)",
		description:    "php_info.php exposes detailed PHP configuration.",
		recommendation: "Remove phpinfo pages from production servers.",
		bodyConfirm:    "phpinfo",
	},
	{
		path: "/test.php", id: "nikto-test-php", category: "disclosure",
		severity: model.SeverityMedium, title: "PHP test page exposed",
		description:    "A PHP test page is accessible and may expose server configuration.",
		recommendation: "Remove test pages from production servers.",
	},
	{
		path: "/debug.php", id: "nikto-debug-php", category: "disclosure",
		severity: model.SeverityMedium, title: "Debug page exposed",
		description:    "A debug page is publicly accessible and may expose application internals.",
		recommendation: "Remove debug pages from production environments.",
	},
	// ── Apache Status ──────────────────────────────────────────────────────────
	{
		path: "/server-status", id: "nikto-server-status", category: "disclosure",
		severity: model.SeverityHigh, title: "Apache server-status page exposed",
		description:    "Apache mod_status is publicly accessible, exposing request activity, client IP addresses, and processing state.",
		recommendation: "Restrict /server-status to localhost: add 'Require local' inside a <Location /server-status> block.",
		bodyConfirm:    "Apache",
	},
	{
		path: "/server-info", id: "nikto-server-info", category: "disclosure",
		severity: model.SeverityHigh, title: "Apache server-info page exposed",
		description:    "Apache mod_info exposes detailed server configuration including installed modules.",
		recommendation: "Restrict /server-info to localhost or disable mod_info.",
	},
	// ── Admin Panels ───────────────────────────────────────────────────────────
	{
		path: "/admin", id: "nikto-admin", category: "admin",
		severity: model.SeverityHigh, title: "Admin panel path accessible",
		description:    "An admin panel path is accessible (or protected, confirming its existence).",
		recommendation: "Restrict admin panels to specific IPs and require multi-factor authentication.",
		flagProtected:  true,
	},
	{
		path: "/admin/", id: "nikto-admin-slash", category: "admin",
		severity: model.SeverityHigh, title: "Admin panel path accessible",
		description:    "An admin panel path is accessible.",
		recommendation: "Restrict admin panels to specific IPs and require MFA.",
		flagProtected:  true,
	},
	{
		path: "/admin.php", id: "nikto-admin-php", category: "admin",
		severity: model.SeverityHigh, title: "Admin panel PHP script accessible",
		description:    "An admin panel PHP script is accessible.",
		recommendation: "Restrict admin panels to specific IPs and require MFA.",
		flagProtected:  true,
	},
	{
		path: "/administrator", id: "nikto-administrator", category: "admin",
		severity: model.SeverityHigh, title: "Administrator panel accessible",
		description:    "An administrator panel path is accessible.",
		recommendation: "Restrict admin panels to specific IPs.",
		flagProtected:  true,
	},
	{
		path: "/administrator/", id: "nikto-administrator-slash", category: "admin",
		severity: model.SeverityHigh, title: "Administrator panel accessible",
		description:    "An administrator panel path is accessible.",
		recommendation: "Restrict admin panels to specific IPs.",
		flagProtected:  true,
	},
	{
		path: "/phpmyadmin", id: "nikto-phpmyadmin", category: "admin",
		severity: model.SeverityHigh, title: "phpMyAdmin accessible",
		description:    "phpMyAdmin is accessible and represents a critical attack surface for database compromise.",
		recommendation: "Restrict phpMyAdmin to localhost or a VPN. Implement IP allowlisting.",
		flagProtected:  true,
	},
	{
		path: "/phpmyadmin/", id: "nikto-phpmyadmin-slash", category: "admin",
		severity: model.SeverityHigh, title: "phpMyAdmin accessible",
		description:    "phpMyAdmin is accessible.",
		recommendation: "Restrict phpMyAdmin to localhost or a VPN.",
		flagProtected:  true,
	},
	{
		path: "/adminer.php", id: "nikto-adminer", category: "admin",
		severity: model.SeverityHigh, title: "Adminer database admin tool exposed",
		description:    "Adminer is a single-file database administration tool that provides full database access.",
		recommendation: "Remove Adminer from production. Access database tools only through a VPN.",
	},
	{
		path: "/manager/html", id: "nikto-tomcat-manager", category: "admin",
		severity: model.SeverityHigh, title: "Apache Tomcat Manager accessible",
		description:    "The Tomcat Manager can be used to deploy and undeploy web applications remotely.",
		recommendation: "Restrict Tomcat Manager to localhost and change default credentials.",
		flagProtected:  true,
	},
	{
		path: "/console", id: "nikto-console", category: "admin",
		severity: model.SeverityMedium, title: "Admin console path accessible",
		description:    "An admin console path is accessible.",
		recommendation: "Restrict admin consoles to internal networks.",
		flagProtected:  true,
	},
	{
		path: "/wp-login.php", id: "nikto-wp-login", category: "admin",
		severity: model.SeverityMedium, title: "WordPress login page exposed",
		description:    "The WordPress login page is accessible and may be subject to brute-force attacks.",
		recommendation: "Implement rate limiting and lockout policies on wp-login.php. Consider relocating the login URL.",
		bodyConfirm:    "WordPress",
	},
	// ── Archives & Backups ────────────────────────────────────────────────────
	{
		path: "/backup.zip", id: "nikto-backup-zip", category: "backup",
		severity: model.SeverityHigh, title: "Backup ZIP archive exposed",
		description:    "A ZIP backup archive is publicly accessible.",
		recommendation: "Remove backup archives from the web root. Store backups in restricted, non-web-accessible locations.",
	},
	{
		path: "/backup.tar.gz", id: "nikto-backup-targz", category: "backup",
		severity: model.SeverityHigh, title: "Backup tar.gz archive exposed",
		description:    "A tar.gz backup archive is publicly accessible.",
		recommendation: "Remove backup archives from the web root.",
	},
	{
		path: "/backup.tar", id: "nikto-backup-tar", category: "backup",
		severity: model.SeverityHigh, title: "Backup tar archive exposed",
		description:    "A tar backup archive is publicly accessible.",
		recommendation: "Remove backup archives from the web root.",
	},
	{
		path: "/.DS_Store", id: "nikto-ds-store", category: "disclosure",
		severity: model.SeverityLow, title: ".DS_Store file exposed",
		description:    "A macOS .DS_Store file is accessible, which may reveal directory structure and file names.",
		recommendation: "Add .DS_Store to .gitignore and remove DS_Store files from the server.",
	},
	// ── API Documentation ─────────────────────────────────────────────────────
	{
		path: "/swagger.json", id: "nikto-swagger-json", category: "api",
		severity: model.SeverityMedium, title: "Swagger API specification exposed",
		description:    "The Swagger/OpenAPI JSON specification is publicly accessible, revealing all API endpoints, parameters, and authentication requirements.",
		recommendation: "Restrict API documentation to authenticated users or internal networks.",
		bodyConfirm:    "swagger",
	},
	{
		path: "/swagger.yaml", id: "nikto-swagger-yaml", category: "api",
		severity: model.SeverityMedium, title: "Swagger API specification exposed",
		description:    "The Swagger/OpenAPI YAML specification is publicly accessible.",
		recommendation: "Restrict API documentation to authenticated users.",
	},
	{
		path: "/swagger-ui.html", id: "nikto-swagger-ui-html", category: "api",
		severity: model.SeverityMedium, title: "Swagger UI exposed",
		description:    "Swagger UI is publicly accessible, providing an interactive API browser.",
		recommendation: "Restrict Swagger UI to internal networks or require authentication.",
	},
	{
		path: "/swagger-ui/", id: "nikto-swagger-ui-dir", category: "api",
		severity: model.SeverityMedium, title: "Swagger UI directory accessible",
		description:    "The Swagger UI directory is accessible.",
		recommendation: "Restrict Swagger UI to internal networks or require authentication.",
	},
	{
		path: "/api-docs", id: "nikto-api-docs", category: "api",
		severity: model.SeverityMedium, title: "API documentation exposed",
		description:    "API documentation is publicly accessible.",
		recommendation: "Restrict API documentation to authenticated users.",
	},
	{
		path: "/v1/api-docs", id: "nikto-v1-api-docs", category: "api",
		severity: model.SeverityMedium, title: "API v1 documentation exposed",
		description:    "API v1 documentation is publicly accessible.",
		recommendation: "Restrict API documentation to authenticated users.",
	},
	{
		path: "/openapi.json", id: "nikto-openapi-json", category: "api",
		severity: model.SeverityMedium, title: "OpenAPI specification exposed",
		description:    "The OpenAPI JSON specification is publicly accessible.",
		recommendation: "Restrict API documentation to authenticated users.",
	},
	{
		path: "/openapi.yaml", id: "nikto-openapi-yaml", category: "api",
		severity: model.SeverityMedium, title: "OpenAPI specification exposed",
		description:    "The OpenAPI YAML specification is publicly accessible.",
		recommendation: "Restrict API documentation to authenticated users.",
	},
	{
		path: "/redoc", id: "nikto-redoc", category: "api",
		severity: model.SeverityMedium, title: "ReDoc API documentation exposed",
		description:    "ReDoc API documentation is publicly accessible.",
		recommendation: "Restrict API documentation to authenticated users.",
	},
	// ── CGI Scripts ───────────────────────────────────────────────────────────
	{
		path: "/cgi-bin/test-cgi", id: "nikto-cgi-test", category: "cgi",
		severity: model.SeverityHigh, title: "Dangerous CGI test script accessible",
		description:    "The test-cgi script is accessible and may expose environment variables including system paths.",
		recommendation: "Remove test CGI scripts from production servers.",
	},
	{
		path: "/cgi-bin/printenv", id: "nikto-cgi-printenv", category: "cgi",
		severity: model.SeverityHigh, title: "CGI printenv script accessible",
		description:    "The printenv CGI script is accessible and exposes server environment variables.",
		recommendation: "Remove printenv CGI from production servers.",
		bodyConfirm:    "SERVER_SOFTWARE",
	},
	// ── Monitoring & Metrics ──────────────────────────────────────────────────
	{
		path: "/metrics", id: "nikto-metrics", category: "monitoring",
		severity: model.SeverityHigh, title: "Prometheus metrics endpoint exposed",
		description:    "A Prometheus metrics endpoint is publicly accessible, exposing application internals and potentially sensitive operational data.",
		recommendation: "Restrict /metrics to internal networks or monitoring infrastructure only.",
	},
	{
		path: "/actuator", id: "nikto-actuator", category: "monitoring",
		severity: model.SeverityHigh, title: "Spring Boot Actuator exposed",
		description:    "Spring Boot Actuator endpoints are publicly accessible and may expose environment variables, bean configurations, and allow application management.",
		recommendation: "Restrict all actuator endpoints. Expose only /actuator/health externally if needed.",
		bodyConfirm:    "_links",
	},
	{
		path: "/actuator/env", id: "nikto-actuator-env", category: "monitoring",
		severity: model.SeverityHigh, title: "Spring Boot Actuator /env exposed",
		description:    "The Actuator /env endpoint exposes all application properties, which may include secrets.",
		recommendation: "Disable or restrict /actuator/env immediately.",
	},
	{
		path: "/actuator/mappings", id: "nikto-actuator-mappings", category: "monitoring",
		severity: model.SeverityMedium, title: "Spring Boot Actuator /mappings exposed",
		description:    "The Actuator /mappings endpoint reveals all HTTP endpoints and their handlers.",
		recommendation: "Restrict actuator endpoints to internal networks.",
	},
	{
		path: "/actuator/beans", id: "nikto-actuator-beans", category: "monitoring",
		severity: model.SeverityMedium, title: "Spring Boot Actuator /beans exposed",
		description:    "The Actuator /beans endpoint reveals the Spring application context.",
		recommendation: "Restrict actuator endpoints to internal networks.",
	},
	{
		path: "/actuator/health", id: "nikto-actuator-health", category: "monitoring",
		severity: model.SeverityLow, title: "Spring Boot Actuator /health accessible",
		description:    "The Actuator /health endpoint is publicly accessible.",
		recommendation: "Review what data the health endpoint exposes; limit details to unauthenticated callers.",
	},
	// ── Framework-specific Configuration ──────────────────────────────────────
	{
		path: "/config/database.yml", id: "nikto-db-yml", category: "config",
		severity: model.SeverityHigh, title: "Database configuration YAML exposed",
		description:    "A database configuration YAML file is accessible and may contain credentials.",
		recommendation: "Move configuration files outside the document root.",
		bodyConfirm:    "adapter",
	},
	// ── Informational / Disclosure ────────────────────────────────────────────
	{
		path: "/robots.txt", id: "nikto-robots-txt", category: "info",
		severity: model.SeverityInfo, title: "robots.txt present",
		description:    "The robots.txt file is accessible. Disallowed paths may inadvertently reveal sensitive application areas.",
		recommendation: "Review robots.txt to ensure it does not disclose sensitive path names.",
	},
	{
		path: "/sitemap.xml", id: "nikto-sitemap-xml", category: "info",
		severity: model.SeverityInfo, title: "Sitemap accessible",
		description:    "An XML sitemap is accessible and lists application pages.",
		recommendation: "Ensure the sitemap does not list sensitive or private pages.",
	},
	{
		path: "/crossdomain.xml", id: "nikto-crossdomain", category: "config",
		severity: model.SeverityLow, title: "Flash cross-domain policy present",
		description:    "A Flash cross-domain policy file is present. Overly permissive policies can allow unauthorised cross-domain requests.",
		recommendation: "Review the cross-domain policy and restrict allowed domains.",
	},
	{
		path: "/.well-known/security.txt", id: "nikto-security-txt", category: "info",
		severity: model.SeverityInfo, title: "security.txt present",
		description:    "A security.txt file is present, providing a standard way to report vulnerabilities.",
		recommendation: "No action required; this is good security practice.",
	},
	{
		path: "/README.md", id: "nikto-readme-md", category: "info",
		severity: model.SeverityLow, title: "README file exposed",
		description:    "A README file is publicly accessible and may reveal application details or version information.",
		recommendation: "Remove README files from production web roots.",
	},
	{
		path: "/CHANGELOG.txt", id: "nikto-changelog", category: "info",
		severity: model.SeverityLow, title: "Changelog exposed",
		description:    "A changelog is publicly accessible and may reveal version history and known vulnerabilities.",
		recommendation: "Remove changelog files from production web roots.",
	},
	{
		path: "/INSTALL.txt", id: "nikto-install-txt", category: "info",
		severity: model.SeverityLow, title: "Installation documentation exposed",
		description:    "Installation documentation is accessible and may reveal system requirements or default credentials.",
		recommendation: "Remove installation documentation from production web roots.",
	},
}

// dangerousMethod describes an HTTP method to test along with finding metadata.
type dangerousMethod struct {
	method         string
	id             string
	title          string
	description    string
	recommendation string
}

// dangerousMethods lists HTTP methods that should not be enabled on a web server.
var dangerousMethods = []dangerousMethod{
	{
		method:         "TRACE",
		id:             "nikto-http-trace",
		title:          "HTTP TRACE method enabled (XST risk)",
		description:    "The HTTP TRACE method is enabled. Combined with a Cross-Site Scripting vulnerability this enables Cross-Site Tracing (XST) attacks, which can steal HTTP-only cookies.",
		recommendation: "Disable the TRACE method in the web server configuration.",
	},
	{
		method:         "PUT",
		id:             "nikto-http-put",
		title:          "HTTP PUT method enabled",
		description:    "The HTTP PUT method is enabled, which may allow an attacker to upload arbitrary files to the server.",
		recommendation: "Disable PUT unless explicitly required by the application. Restrict to authenticated, authorised requests only.",
	},
	{
		method:         "DELETE",
		id:             "nikto-http-delete",
		title:          "HTTP DELETE method enabled",
		description:    "The HTTP DELETE method is enabled, which may allow deletion of server resources.",
		recommendation: "Disable DELETE unless explicitly required. Restrict to authenticated, authorised requests only.",
	},
	{
		method:         "DEBUG",
		id:             "nikto-http-debug",
		title:          "HTTP DEBUG method enabled (ASP.NET)",
		description:    "The HTTP DEBUG method is enabled. This is an ASP.NET-specific method that can be exploited to attach a debugger and obtain the application's machine key.",
		recommendation: "Disable the DEBUG method in IIS by adding a denyVerbs rule in requestFiltering.",
	},
	{
		method:         "CONNECT",
		id:             "nikto-http-connect",
		title:          "HTTP CONNECT method enabled",
		description:    "The HTTP CONNECT method is enabled and may allow the server to be used as an open proxy.",
		recommendation: "Disable CONNECT unless the server is explicitly operating as a proxy.",
	},
}

// serverVersionRe matches common patterns of web server version strings.
var serverVersionRe = regexp.MustCompile(`(?i)(Apache|nginx|IIS|lighttpd|Kestrel|Tomcat|Jetty|Caddy|Cowboy|WEBrick|OpenResty)[/\s]*([\d.]+)`)

// sensitiveDisallowRe matches Disallow lines that reference security-relevant paths.
var sensitiveDisallowRe = regexp.MustCompile(`(?i)Disallow:\s*(/(?:admin|backup|config|db|database|secret|private|internal|manage|cgi-bin)[^\s]*)`)

// Scan performs a Nikto-equivalent automated web application security scan against target.
// authProfile credentials are applied to every outgoing HTTP request.
// Only http:// and https:// targets are accepted; all other schemes are rejected.
func Scan(ctx context.Context, target string, authProfile model.ScanAuthProfile) Result {
	parsed, parseErr := url.Parse(target)
	if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return Result{Findings: make([]model.Finding, 0)}
	}

	// Normalise the base URL: scheme + host only (no path, no trailing slash).
	base := strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/")

	client := &http.Client{
		Timeout: httpTimeout,
		// Do not follow redirects automatically; we handle them where needed.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	result := Result{Findings: make([]model.Finding, 0)}

	// Phase 1: fingerprint the server and check for information-disclosing headers.
	serverSoftware, headerFindings := probeServer(ctx, client, base, authProfile)
	result.ServerSoftware = serverSoftware
	result.Findings = append(result.Findings, headerFindings...)

	// Phase 2: concurrent interesting-path enumeration.
	result.Findings = append(result.Findings, checkPaths(ctx, client, base, authProfile)...)

	// Phase 3: HTTP method testing.
	result.Findings = append(result.Findings, checkHTTPMethods(ctx, client, base, authProfile)...)

	// Phase 4: robots.txt sensitive-path analysis.
	result.Findings = append(result.Findings, analyzeRobotsTxt(ctx, client, base, authProfile)...)

	return result
}

// probeServer makes a HEAD (falling back to GET) against the base URL, returns
// the identified server software, and produces findings for version-disclosing headers.
func probeServer(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) (string, []model.Finding) {
	findings := make([]model.Finding, 0)

	req, err := newSafeRequest(ctx, http.MethodHead, base+"/")
	if err != nil {
		return "", findings
	}
	applyAuthProfile(req, auth)
	resp, err := client.Do(req)
	if err != nil {
		// Fall back to GET if HEAD fails.
		req2, reqErr := newSafeRequest(ctx, http.MethodGet, base+"/")
		if reqErr != nil {
			return "", findings
		}
		applyAuthProfile(req2, auth)
		resp, err = client.Do(req2)
		if err != nil {
			return "", findings
		}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize))

	serverSoftware := ""

	// Server header — detect version disclosure.
	if sv := resp.Header.Get("Server"); sv != "" {
		if m := serverVersionRe.FindStringSubmatch(sv); len(m) >= 3 {
			serverSoftware = m[1] + "/" + m[2]
			findings = append(findings, model.Finding{
				ID:             "nikto-server-version-disclosure",
				Category:       "disclosure",
				Severity:       model.SeverityLow,
				Title:          "Web server version disclosed in Server header",
				Description:    "The Server response header reveals the web server software name and version, aiding attacker reconnaissance.",
				Evidence:       "Server: " + sv,
				Recommendation: "Configure the web server to suppress or genericise the Server header.",
			})
		} else {
			serverSoftware = sv
		}
	}

	// X-Powered-By header.
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		findings = append(findings, model.Finding{
			ID:             "nikto-x-powered-by",
			Category:       "disclosure",
			Severity:       model.SeverityLow,
			Title:          "Technology stack disclosed via X-Powered-By header",
			Description:    "The X-Powered-By header reveals the server-side technology (e.g. PHP version, ASP.NET version).",
			Evidence:       "X-Powered-By: " + xpb,
			Recommendation: "Remove or suppress the X-Powered-By header.",
		})
	}

	// X-AspNet-Version header.
	if xav := resp.Header.Get("X-AspNet-Version"); xav != "" {
		findings = append(findings, model.Finding{
			ID:             "nikto-x-aspnet-version",
			Category:       "disclosure",
			Severity:       model.SeverityLow,
			Title:          "ASP.NET version disclosed",
			Description:    "The X-AspNet-Version header exposes the exact ASP.NET version in use.",
			Evidence:       "X-AspNet-Version: " + xav,
			Recommendation: "Add <httpRuntime enableVersionHeader=\"false\" /> to web.config to suppress this header.",
		})
	}

	// X-Generator header.
	if xgen := resp.Header.Get("X-Generator"); xgen != "" {
		findings = append(findings, model.Finding{
			ID:             "nikto-x-generator",
			Category:       "disclosure",
			Severity:       model.SeverityLow,
			Title:          "CMS/framework generator disclosed",
			Description:    "The X-Generator header reveals the CMS or framework used to generate the page.",
			Evidence:       "X-Generator: " + xgen,
			Recommendation: "Configure the CMS or framework to suppress the X-Generator header.",
		})
	}

	return serverSoftware, findings
}

// pathResult is the internal result type passed back from path-checking workers.
type pathResult struct {
	finding *model.Finding
}

// checkPaths probes all entries in interestingPaths concurrently and returns findings.
func checkPaths(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	jobs := make(chan interestingPath, len(interestingPaths))
	results := make(chan pathResult, len(interestingPaths))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				f := probePath(ctx, client, base, p, auth)
				results <- pathResult{finding: f}
			}
		}()
	}

	for _, p := range interestingPaths {
		jobs <- p
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	findings := make([]model.Finding, 0)
	for r := range results {
		if r.finding != nil {
			findings = append(findings, *r.finding)
		}
	}
	return findings
}

// probePath checks a single interestingPath entry and returns a Finding if the
// resource is accessible (or protected for flagProtected entries).
func probePath(ctx context.Context, client *http.Client, base string, p interestingPath, auth model.ScanAuthProfile) *model.Finding {
	fullURL := base + p.path

	req, err := newSafeRequest(ctx, http.MethodGet, fullURL)
	if err != nil {
		return nil
	}
	applyAuthProfile(req, auth)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	body := string(bodyBytes)

	status := resp.StatusCode

	shouldFlag := false
	evidenceSuffix := ""

	switch {
	case status == http.StatusOK:
		if p.bodyConfirm == "" || strings.Contains(body, p.bodyConfirm) {
			shouldFlag = true
			if p.bodyConfirm != "" {
				evidenceSuffix = fmt.Sprintf("HTTP 200 — body contains %q at %s", p.bodyConfirm, fullURL)
			} else {
				evidenceSuffix = fmt.Sprintf("HTTP 200 at %s", fullURL)
			}
		}
		// Directory listing detection regardless of bodyConfirm.
		if !shouldFlag && detectDirectoryListing(body) {
			shouldFlag = true
			evidenceSuffix = fmt.Sprintf("Directory listing detected at %s", fullURL)
		}
	case (status == http.StatusUnauthorized || status == http.StatusForbidden) && p.flagProtected:
		shouldFlag = true
		evidenceSuffix = fmt.Sprintf("HTTP %d at %s (resource exists but is access-controlled)", status, fullURL)
	}

	if !shouldFlag {
		return nil
	}

	return &model.Finding{
		ID:             p.id,
		Category:       p.category,
		Severity:       p.severity,
		Title:          p.title,
		Description:    p.description,
		Evidence:       evidenceSuffix,
		Recommendation: p.recommendation,
	}
}

// checkHTTPMethods tests each entry in dangerousMethods against target.
func checkHTTPMethods(ctx context.Context, client *http.Client, target string, auth model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Issue OPTIONS first to enumerate allowed methods.
	optReq, err := newSafeRequest(ctx, http.MethodOptions, target+"/")
	if err == nil {
		applyAuthProfile(optReq, auth)
		if optResp, optErr := client.Do(optReq); optErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(optResp.Body, maxBodySize))
			optResp.Body.Close()
			if allow := optResp.Header.Get("Allow"); allow != "" {
				findings = append(findings, model.Finding{
					ID:             "nikto-http-options",
					Category:       "config",
					Severity:       model.SeverityInfo,
					Title:          "HTTP OPTIONS lists allowed methods",
					Description:    "The OPTIONS method returned an Allow header enumerating all permitted HTTP methods.",
					Evidence:       "Allow: " + allow,
					Recommendation: "Review the listed methods and disable any not required by the application.",
				})
			}
		}
	}

	for _, m := range dangerousMethods {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		req, err := newSafeRequest(ctx, m.method, target+"/")
		if err != nil {
			continue
		}
		applyAuthProfile(req, auth)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		// A non-405/501 response suggests the method is at least partially accepted.
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotImplemented {
			findings = append(findings, model.Finding{
				ID:             m.id,
				Category:       "config",
				Severity:       model.SeverityMedium,
				Title:          m.title,
				Description:    m.description,
				Evidence:       fmt.Sprintf("%s %s/ → HTTP %d", m.method, target, resp.StatusCode),
				Recommendation: m.recommendation,
			})
		}
	}

	return findings
}

// analyzeRobotsTxt fetches robots.txt and flags any Disallow entries that suggest
// the existence of sensitive application areas.
func analyzeRobotsTxt(ctx context.Context, client *http.Client, base string, auth model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	body, status, err := getBody(ctx, client, base+"/robots.txt", auth)
	if err != nil || status != http.StatusOK {
		return findings
	}

	matches := sensitiveDisallowRe.FindAllStringSubmatch(body, -1)
	seen := make(map[string]struct{})
	sensitiveDisallowed := make([]string, 0)

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		p := strings.TrimSpace(m[1])
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		sensitiveDisallowed = append(sensitiveDisallowed, p)
	}

	if len(sensitiveDisallowed) > 0 {
		findings = append(findings, model.Finding{
			ID:             "nikto-robots-sensitive-paths",
			Category:       "info",
			Severity:       model.SeverityLow,
			Title:          "Potentially sensitive paths listed in robots.txt",
			Description:    "robots.txt disallows paths that suggest the existence of sensitive application areas (admin panels, backups, configuration directories).",
			Evidence:       strings.Join(sensitiveDisallowed, ", "),
			Recommendation: "Review whether listing these paths in robots.txt inadvertently guides attackers. Consider removing security-sensitive path names.",
		})
	}

	return findings
}

// detectDirectoryListing returns true if the body resembles an Apache/nginx directory index.
func detectDirectoryListing(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "index of /") ||
		(strings.Contains(lower, "directory listing for") && strings.Contains(lower, "<a href="))
}

// getBody performs an authenticated GET and returns the response body, HTTP status, and any error.
func getBody(ctx context.Context, client *http.Client, target string, auth model.ScanAuthProfile) (string, int, error) {
	req, err := newSafeRequest(ctx, http.MethodGet, target)
	if err != nil {
		return "", 0, err
	}
	applyAuthProfile(req, auth)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return string(b), resp.StatusCode, nil
}

// applyAuthProfile applies the provided credentials to an outgoing HTTP request.
// This mirrors scanner.ApplyAuthProfile to avoid a circular import dependency.
func applyAuthProfile(req *http.Request, profile model.ScanAuthProfile) {
	if req == nil {
		return
	}
	for key, value := range profile.Headers {
		if strings.TrimSpace(key) != "" {
			req.Header.Set(key, value)
		}
	}
	if profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}
	if profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "" {
		req.SetBasicAuth(profile.BasicAuthUsername, profile.BasicAuthPassword)
	}
	if len(profile.Cookies) > 0 {
		parts := make([]string, 0, len(profile.Cookies))
		for name, val := range profile.Cookies {
			parts = append(parts, name+"="+val)
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}

// newSafeRequest creates an HTTP request after validating that rawURL uses only the
// http or https scheme. This defence-in-depth check prevents SSRF from arbitrary
// schemes even when the caller has already validated the base URL.
func newSafeRequest(ctx context.Context, method, rawURL string) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	return http.NewRequestWithContext(ctx, method, rawURL, nil)
}
