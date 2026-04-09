package api

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

var (
	urlPattern         = regexp.MustCompile(`https?://[^\s,;]+`)
	hostPortPattern    = regexp.MustCompile(`\b([a-zA-Z0-9.-]+):(\d{1,5})\b`)
	serverHeaderPrefix = "server:"
	poweredByPrefix    = "x-powered-by:"
)

func extractAssets(target string, findings []model.Finding) []model.ScanAsset {
	now := time.Now().UTC()
	seen := map[string]model.ScanAsset{}
	add := func(assetType, key, value string) {
		assetType = strings.TrimSpace(strings.ToLower(assetType))
		key = strings.TrimSpace(strings.ToLower(key))
		if assetType == "" || key == "" {
			return
		}
		seen[assetType+"|"+key] = model.ScanAsset{
			AssetType:    assetType,
			AssetKey:     key,
			AssetValue:   strings.TrimSpace(value),
			DiscoveredAt: now,
		}
	}

	if u, err := url.Parse(target); err == nil {
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host != "" {
			add("host", host, "target")
		}
		if p := u.Port(); p != "" {
			add("port", host+":"+p, p)
		}
		add("endpoint", strings.ToLower(strings.TrimSpace(u.Path)), target)
	}

	for _, f := range findings {
		ev := strings.TrimSpace(f.Evidence)
		if ev == "" {
			continue
		}
		lowerEv := strings.ToLower(ev)

		if strings.Contains(lowerEv, serverHeaderPrefix) {
			add("header", "server", strings.TrimSpace(strings.TrimPrefix(lowerEv, serverHeaderPrefix)))
		}
		if strings.Contains(lowerEv, poweredByPrefix) {
			add("header", "x-powered-by", strings.TrimSpace(strings.TrimPrefix(lowerEv, poweredByPrefix)))
		}
		if strings.Contains(lowerEv, "wp-") || strings.Contains(lowerEv, "wordpress") {
			add("tech", "wordpress", f.Title)
		}
		if strings.Contains(lowerEv, "graphql") {
			add("endpoint", "/graphql", f.Title)
		}
		if strings.Contains(lowerEv, "/api/") || strings.Contains(lowerEv, "api ") {
			add("endpoint", "/api", f.Title)
		}

		for _, match := range urlPattern.FindAllString(ev, -1) {
			parsed, err := url.Parse(strings.TrimSpace(match))
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			host := strings.ToLower(parsed.Hostname())
			add("host", host, "from finding evidence")
			path := strings.TrimSpace(strings.ToLower(parsed.Path))
			if path != "" && path != "/" {
				add("endpoint", path, host)
			}
			if p := parsed.Port(); p != "" {
				add("port", host+":"+p, p)
			}
		}
		for _, match := range hostPortPattern.FindAllStringSubmatch(ev, -1) {
			if len(match) != 3 {
				continue
			}
			port, err := strconv.Atoi(match[2])
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			host := strings.ToLower(strings.TrimSpace(match[1]))
			add("host", host, "from finding evidence")
			add("port", host+":"+match[2], match[2])
		}
	}

	out := make([]model.ScanAsset, 0, len(seen))
	for _, asset := range seen {
		out = append(out, asset)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AssetType == out[j].AssetType {
			return out[i].AssetKey < out[j].AssetKey
		}
		return out[i].AssetType < out[j].AssetType
	})
	return out
}
