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

func extractAssetLinks(target string, assets []model.ScanAsset, findings []model.Finding) []model.ScanAssetLink {
	links := map[string]model.ScanAssetLink{}
	add := func(fromType, fromKey, toType, toKey, relation string) {
		fromType = strings.TrimSpace(strings.ToLower(fromType))
		toType = strings.TrimSpace(strings.ToLower(toType))
		fromKey = strings.TrimSpace(strings.ToLower(fromKey))
		toKey = strings.TrimSpace(strings.ToLower(toKey))
		relation = strings.TrimSpace(strings.ToLower(relation))
		if fromType == "" || toType == "" || fromKey == "" || toKey == "" || relation == "" {
			return
		}
		k := fromType + "|" + fromKey + "|" + relation + "|" + toType + "|" + toKey
		links[k] = model.ScanAssetLink{
			FromType: fromType,
			FromKey:  fromKey,
			ToType:   toType,
			ToKey:    toKey,
			Relation: relation,
		}
	}

	targetHost := ""
	if u, err := url.Parse(target); err == nil {
		targetHost = strings.ToLower(strings.TrimSpace(u.Hostname()))
	}
	for _, a := range assets {
		switch a.AssetType {
		case "port":
			h, _, ok := strings.Cut(a.AssetKey, ":")
			if ok {
				add("host", h, "port", a.AssetKey, "exposes")
			}
		case "endpoint":
			if targetHost != "" {
				add("host", targetHost, "endpoint", a.AssetKey, "hosts")
			}
		}
	}
	for _, f := range findings {
		ev := strings.TrimSpace(strings.ToLower(f.Evidence))
		if ev == "" {
			continue
		}
		if strings.Contains(ev, "server:") {
			add("host", targetHost, "header", "server", "emits")
		}
		if strings.Contains(ev, "x-powered-by:") {
			add("host", targetHost, "header", "x-powered-by", "emits")
		}
		if strings.Contains(ev, "wordpress") || strings.Contains(ev, "wp-") {
			add("host", targetHost, "tech", "wordpress", "runs")
		}
	}

	out := make([]model.ScanAssetLink, 0, len(links))
	for _, link := range links {
		out = append(out, link)
	}
	sort.Slice(out, func(i, j int) bool {
		li := out[i].FromType + "|" + out[i].FromKey + "|" + out[i].Relation + "|" + out[i].ToType + "|" + out[i].ToKey
		lj := out[j].FromType + "|" + out[j].FromKey + "|" + out[j].Relation + "|" + out[j].ToType + "|" + out[j].ToKey
		return li < lj
	})
	return out
}
