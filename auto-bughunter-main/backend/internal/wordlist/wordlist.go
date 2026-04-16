package wordlist

import (
	"context"
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
