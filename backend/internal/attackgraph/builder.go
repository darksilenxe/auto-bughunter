package attackgraph

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

const scannerNodeID = "__scanner__"

func Build(job *model.ScanJob) *model.AttackGraphData {
	if job == nil {
		return nil
	}

	graph := &model.AttackGraphData{
		Source: "backend",
		Status: strings.ToLower(strings.TrimSpace(job.Status)),
		Nodes:  []model.AttackGraphNode{},
		Edges:  []model.AttackGraphEdge{},
	}

	nodeMap := map[string]model.AttackGraphNode{}
	edgeSet := map[string]struct{}{}

	addNode := func(n model.AttackGraphNode) {
		if n.ID == "" {
			return
		}
		if _, exists := nodeMap[n.ID]; exists {
			return
		}
		nodeMap[n.ID] = n
	}
	addEdge := func(from, to string) {
		if from == "" || to == "" || from == to {
			return
		}
		key := from + "->" + to
		if _, exists := edgeSet[key]; exists {
			return
		}
		edgeSet[key] = struct{}{}
	}

	targetHost := job.Target
	if parsed, err := url.Parse(job.Target); err == nil && parsed.Hostname() != "" {
		targetHost = parsed.Hostname()
	}
	scanEnd := time.Now().UTC()
	if job.CompletedAt != nil {
		scanEnd = *job.CompletedAt
	}

	addNode(model.AttackGraphNode{
		ID:       scannerNodeID,
		Type:     "scanner",
		Label:    "Auto BugHunter",
		Sublabel: targetHost,
		TS:       job.StartedAt.UTC().UnixMilli(),
	})

	hosts := make([]model.ScanAsset, 0)
	services := make([]model.ScanAsset, 0)
	for _, asset := range job.Assets {
		assetType := strings.ToLower(strings.TrimSpace(asset.AssetType))
		switch assetType {
		case "host", "subdomain", "domain":
			hosts = append(hosts, asset)
		case "endpoint", "url", "port", "service", "path":
			services = append(services, asset)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].DiscoveredAt.Before(hosts[j].DiscoveredAt) })
	sort.Slice(services, func(i, j int) bool { return services[i].DiscoveredAt.Before(services[j].DiscoveredAt) })

	for _, host := range hosts {
		addNode(model.AttackGraphNode{
			ID:       host.AssetKey,
			Type:     "host",
			Label:    "Found Host",
			Sublabel: host.AssetKey,
			TS:       clampTS(host.DiscoveredAt, job.StartedAt, scanEnd),
		})
	}
	for _, service := range services {
		addNode(model.AttackGraphNode{
			ID:       service.AssetKey,
			Type:     "service",
			Label:    "Found Service",
			Sublabel: service.AssetKey,
			TS:       clampTS(service.DiscoveredAt, job.StartedAt, scanEnd),
		})
	}

	for i, finding := range job.Findings {
		nodeID := strings.TrimSpace(finding.ID)
		if nodeID == "" {
			nodeID = fmt.Sprintf("__f%d__", i)
		}
		t := job.StartedAt.Add(scanEnd.Sub(job.StartedAt) / 2)
		addNode(model.AttackGraphNode{
			ID:       nodeID,
			Type:     classifyFinding(finding),
			Label:    finding.Title,
			Sublabel: finding.AffectedURL,
			Severity: string(finding.Severity),
			TS:       clampTS(t, job.StartedAt, scanEnd),
		})
	}

	for _, link := range job.AssetLinks {
		addEdge(strings.TrimSpace(link.FromKey), strings.TrimSpace(link.ToKey))
	}

	if len(hosts) > 0 {
		addEdge(scannerNodeID, hosts[0].AssetKey)
	}
	for _, service := range services {
		for _, host := range hosts {
			if strings.Contains(service.AssetKey, host.AssetKey) {
				addEdge(host.AssetKey, service.AssetKey)
				break
			}
		}
	}

	for i, finding := range job.Findings {
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			id = fmt.Sprintf("__f%d__", i)
		}
		if hasIncoming(edgeSet, id) {
			continue
		}
		if anchor := findAnchor(finding.AffectedURL, hosts, services); anchor != "" {
			addEdge(anchor, id)
		} else {
			addEdge(scannerNodeID, id)
		}
	}

	graph.Nodes = make([]model.AttackGraphNode, 0, len(nodeMap))
	for _, node := range nodeMap {
		graph.Nodes = append(graph.Nodes, node)
	}
	sort.Slice(graph.Nodes, func(i, j int) bool {
		if graph.Nodes[i].TS == graph.Nodes[j].TS {
			return graph.Nodes[i].ID < graph.Nodes[j].ID
		}
		return graph.Nodes[i].TS < graph.Nodes[j].TS
	})

	graph.Edges = make([]model.AttackGraphEdge, 0, len(edgeSet))
	for key := range edgeSet {
		parts := strings.SplitN(key, "->", 2)
		if len(parts) != 2 {
			continue
		}
		graph.Edges = append(graph.Edges, model.AttackGraphEdge{From: parts[0], To: parts[1]})
	}
	sort.Slice(graph.Edges, func(i, j int) bool {
		if graph.Edges[i].From == graph.Edges[j].From {
			return graph.Edges[i].To < graph.Edges[j].To
		}
		return graph.Edges[i].From < graph.Edges[j].From
	})

	return graph
}

func classifyFinding(f model.Finding) string {
	title := strings.ToLower(f.Title)
	category := strings.ToLower(f.Category)
	if (f.Severity == model.SeverityHigh && f.Exploitability != nil && f.Exploitability.Reachable) ||
		strings.Contains(title, "rce") ||
		strings.Contains(title, "remote code") ||
		strings.Contains(title, "takeover") ||
		strings.Contains(title, "bypass") ||
		strings.Contains(title, "injection") {
		return "compromise"
	}
	if strings.Contains(category, "exposure") ||
		strings.Contains(title, "credential") ||
		strings.Contains(title, "password") ||
		strings.Contains(title, "token") ||
		strings.Contains(title, "secret") ||
		strings.Contains(title, "api key") {
		return "credential"
	}
	return "finding"
}

func hasIncoming(edgeSet map[string]struct{}, to string) bool {
	for key := range edgeSet {
		if strings.HasSuffix(key, "->"+to) {
			return true
		}
	}
	return false
}

func findAnchor(affectedURL string, hosts, services []model.ScanAsset) string {
	au := strings.TrimSpace(affectedURL)
	for _, service := range services {
		if au != "" && (strings.HasPrefix(au, service.AssetKey) || strings.HasPrefix(service.AssetKey, strings.Split(au, "?")[0])) {
			return service.AssetKey
		}
	}
	for _, host := range hosts {
		if au != "" && strings.Contains(au, host.AssetKey) {
			return host.AssetKey
		}
	}
	if len(hosts) > 0 {
		return hosts[0].AssetKey
	}
	return ""
}

func clampTS(value, min, max time.Time) int64 {
	v := value.UTC()
	if v.Before(min.UTC()) {
		v = min.UTC()
	}
	if v.After(max.UTC()) {
		v = max.UTC()
	}
	return v.UnixMilli()
}
