// Package metrics implements a lightweight Prometheus-compatible metrics
// registry using only the Go standard library.  It exposes a /metrics HTTP
// handler that renders counters, gauges, and histograms in the Prometheus text
// exposition format (v0.0.4), compatible with any Prometheus scrape config.
package metrics

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

// Counter is a monotonically increasing uint64 metric.
type Counter struct {
	name   string
	help   string
	labels map[string]string
	value  atomic.Uint64
}

func (c *Counter) Inc()          { c.value.Add(1) }
func (c *Counter) Add(n uint64)  { c.value.Add(n) }
func (c *Counter) Value() uint64 { return c.value.Load() }

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

// Gauge is a float64 metric that can go up and down.
type Gauge struct {
	name   string
	help   string
	labels map[string]string
	bits   atomic.Uint64 // stores math.Float64bits
}

func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }
func (g *Gauge) Inc()          { g.add(1) }
func (g *Gauge) Dec()          { g.add(-1) }
func (g *Gauge) add(d float64) {
	for {
		old := g.bits.Load()
		nw := math.Float64bits(math.Float64frombits(old) + d)
		if g.bits.CompareAndSwap(old, nw) {
			return
		}
	}
}
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

// Histogram observes float64 values and accumulates them in configurable
// buckets.  Suitable for latency (use seconds as unit).
type Histogram struct {
	name   string
	help   string
	labels map[string]string
	bounds []float64 // upper bounds, sorted ascending
	mu     sync.Mutex
	counts []uint64 // len == len(bounds)+1, last bucket is +Inf
	sum    float64
	total  uint64
}

// Observe records one observation.
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	h.sum += v
	h.total++
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i]++
			h.mu.Unlock()
			return
		}
	}
	h.counts[len(h.bounds)]++ // +Inf bucket
	h.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// Registry holds all registered metrics and can render them as Prometheus text.
type Registry struct {
	mu         sync.RWMutex
	counters   []*Counter
	gauges     []*Gauge
	histograms []*Histogram
}

// DefaultRegistry is the package-level registry used by the package-level
// helper functions (ScanStarted, FindingRecorded, etc.).
var DefaultRegistry = &Registry{}

// NewCounter registers and returns a Counter.
func (r *Registry) NewCounter(name, help string, labels map[string]string) *Counter {
	c := &Counter{name: name, help: help, labels: copyLabels(labels)}
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// NewGauge registers and returns a Gauge.
func (r *Registry) NewGauge(name, help string, labels map[string]string) *Gauge {
	g := &Gauge{name: name, help: help, labels: copyLabels(labels)}
	r.mu.Lock()
	r.gauges = append(r.gauges, g)
	r.mu.Unlock()
	return g
}

// DefaultBuckets are the default histogram upper bounds (seconds).
var DefaultBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// NewHistogram registers and returns a Histogram.
func (r *Registry) NewHistogram(name, help string, labels map[string]string, buckets []float64) *Histogram {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	b := make([]float64, len(buckets))
	copy(b, buckets)
	sort.Float64s(b)
	h := &Histogram{
		name:   name,
		help:   help,
		labels: copyLabels(labels),
		bounds: b,
		counts: make([]uint64, len(b)+1),
	}
	r.mu.Lock()
	r.histograms = append(r.histograms, h)
	r.mu.Unlock()
	return h
}

// WriteTo renders the registry in Prometheus text format to w.
func (r *Registry) WriteTo(w http.ResponseWriter) {
	r.mu.RLock()
	counters := append([]*Counter(nil), r.counters...)
	gauges := append([]*Gauge(nil), r.gauges...)
	histograms := append([]*Histogram(nil), r.histograms...)
	r.mu.RUnlock()

	for _, c := range counters {
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		fmt.Fprintf(w, "%s%s %d\n", c.name, labelsStr(c.labels), c.Value())
	}
	for _, g := range gauges {
		fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
		fmt.Fprintf(w, "%s%s %g\n", g.name, labelsStr(g.labels), g.Value())
	}
	for _, h := range histograms {
		h.mu.Lock()
		sum := h.sum
		total := h.total
		counts := append([]uint64(nil), h.counts...)
		h.mu.Unlock()

		fmt.Fprintf(w, "# HELP %s %s\n", h.name, h.help)
		fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)
		var cumulative uint64
		for i, b := range h.bounds {
			cumulative += counts[i]
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, mergeLabels(h.labels, map[string]string{"le": fmt.Sprintf("%g", b)}), cumulative)
		}
		cumulative += counts[len(h.bounds)]
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, mergeLabels(h.labels, map[string]string{"le": "+Inf"}), cumulative)
		fmt.Fprintf(w, "%s_sum%s %g\n", h.name, labelsStr(h.labels), sum)
		fmt.Fprintf(w, "%s_count%s %d\n", h.name, labelsStr(h.labels), total)
	}
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

// Handler returns an http.HandlerFunc that serves Prometheus-format metrics.
func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// text/plain + nosniff prevents browsers from treating the response
		// as HTML even when label values contain special characters.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.WriteTo(w)
	}
}

// ---------------------------------------------------------------------------
// Package-level pre-registered metrics
// ---------------------------------------------------------------------------

var (
	ScansTotal = DefaultRegistry.NewCounter(
		"autobughunter_scans_total",
		"Total number of scans started.",
		nil,
	)
	ScanDuration = DefaultRegistry.NewHistogram(
		"autobughunter_scan_duration_seconds",
		"Scan wall-clock duration in seconds.",
		nil, nil,
	)
	ActiveScans = DefaultRegistry.NewGauge(
		"autobughunter_active_scans",
		"Number of scans currently in progress.",
		nil,
	)
	ScanQueueDepth = DefaultRegistry.NewGauge(
		"autobughunter_scan_queue_depth",
		"Number of scan jobs currently queued but not yet started.",
		nil,
	)
	PostProcessDuration = DefaultRegistry.NewHistogram(
		"autobughunter_scan_postprocess_seconds",
		"Time spent in post-scan processing (enrichment, AI summary, ML) in seconds.",
		nil,
		[]float64{0.1, 0.5, 1, 2.5, 5, 10, 20, 30, 60},
	)
	FindingsTotal = DefaultRegistry.NewCounter(
		"autobughunter_findings_total",
		"Total findings emitted across all scans.",
		nil,
	)
	AgentsTotal = DefaultRegistry.NewCounter(
		"autobughunter_agents_total",
		"Total agent executions.",
		nil,
	)
	// AgentDuration is a legacy aggregate histogram kept for backward compat.
	// Per-agent durations are tracked via AgentDurationByName.
	AgentDuration = DefaultRegistry.NewHistogram(
		"autobughunter_agent_duration_seconds",
		"Overall agent execution duration in seconds (all agents combined).",
		nil, nil,
	)
	ProbeErrorsTotal = DefaultRegistry.NewCounter(
		"autobughunter_probe_errors_total",
		"Total scanner probe errors.",
		nil,
	)
	OutboundProbeRequests = DefaultRegistry.NewCounter(
		"autobughunter_outbound_probe_requests_total",
		"Total outbound HTTP requests made by the scanner to target applications.",
		nil,
	)
	AICallsTotal = DefaultRegistry.NewCounter(
		"autobughunter_ai_calls_total",
		"Total AI/LLM API calls made (all call types combined).",
		nil,
	)
	AICallDuration = DefaultRegistry.NewHistogram(
		"autobughunter_ai_call_duration_seconds",
		"Latency of AI/LLM API calls in seconds.",
		nil,
		[]float64{0.1, 0.5, 1, 2, 5, 10, 20, 30},
	)
	AICallErrorsTotal = DefaultRegistry.NewCounter(
		"autobughunter_ai_call_errors_total",
		"Total AI/LLM API call errors.",
		nil,
	)
)

// Per-label counter maps keep label cardinality bounded.  Each map is lazily
// populated and uses a dedicated mutex.

var (
	findingsBySeverity   = map[string]*Counter{}
	findingsBySeverityMu sync.Mutex

	agentsByName   = map[string]*Counter{}
	agentsByNameMu sync.Mutex

	agentDurationByName   = map[string]*Histogram{}
	agentFindingsByName   = map[string]*Histogram{}
	agentStatusByKey      = map[string]*Counter{}
	agentDetailMetricsMu  sync.Mutex

	toolRunsByKey     = map[string]*Counter{}
	toolDurationByKey = map[string]*Histogram{}
	toolMetricsMu     sync.Mutex

	aiCallsByType        = map[string]*Counter{}
	aiDurationByType     = map[string]*Histogram{}
	aiErrorsByType       = map[string]*Counter{}
	aiCallMetricsMu      sync.Mutex
)

// FindingRecorded increments the findings counter for the given severity label.
func FindingRecorded(severity string) {
	FindingsTotal.Inc()
	findingsBySeverityMu.Lock()
	c, ok := findingsBySeverity[severity]
	if !ok {
		c = DefaultRegistry.NewCounter(
			"autobughunter_findings_by_severity_total",
			"Findings broken down by severity.",
			map[string]string{"severity": severity},
		)
		findingsBySeverity[severity] = c
	}
	findingsBySeverityMu.Unlock()
	c.Inc()
}

// AgentRun records one agent execution with its outcome.
func AgentRun(agentName string) {
	AgentsTotal.Inc()
	agentsByNameMu.Lock()
	c, ok := agentsByName[agentName]
	if !ok {
		c = DefaultRegistry.NewCounter(
			"autobughunter_agent_runs_total",
			"Agent executions broken down by agent name.",
			map[string]string{"agent": agentName},
		)
		agentsByName[agentName] = c
	}
	agentsByNameMu.Unlock()
	c.Inc()
}

// AgentCompleted records detailed per-agent telemetry: duration, finding count, and
// outcome status (completed / error / timed_out).
func AgentCompleted(agentName, status string, durationSecs float64, findingsCount int) {
	agent := strings.TrimSpace(agentName)
	if agent == "" {
		agent = "unknown"
	}
	stat := strings.TrimSpace(status)
	if stat == "" {
		stat = "unknown"
	}

	// Aggregate histogram (all agents).
	AgentDuration.Observe(durationSecs)

	agentDetailMetricsMu.Lock()

	// Per-agent duration histogram.
	durHist, ok := agentDurationByName[agent]
	if !ok {
		durHist = DefaultRegistry.NewHistogram(
			"autobughunter_agent_duration_seconds_by_name",
			"Per-agent execution duration in seconds.",
			map[string]string{"agent": agent},
			nil,
		)
		agentDurationByName[agent] = durHist
	}
	durHist.Observe(durationSecs)

	// Per-agent findings-produced histogram.
	findHist, ok := agentFindingsByName[agent]
	if !ok {
		findHist = DefaultRegistry.NewHistogram(
			"autobughunter_agent_findings_per_run",
			"Number of findings produced per agent run.",
			map[string]string{"agent": agent},
			[]float64{0, 1, 2, 5, 10, 20, 50, 100},
		)
		agentFindingsByName[agent] = findHist
	}
	findHist.Observe(float64(findingsCount))

	// Per-agent status counter.
	statusKey := agent + "|" + stat
	statusCounter, ok := agentStatusByKey[statusKey]
	if !ok {
		statusCounter = DefaultRegistry.NewCounter(
			"autobughunter_agent_runs_by_status_total",
			"Agent executions broken down by agent name and outcome status.",
			map[string]string{"agent": agent, "status": stat},
		)
		agentStatusByKey[statusKey] = statusCounter
	}

	agentDetailMetricsMu.Unlock()

	statusCounter.Inc()
}

// AICall records one AI/LLM API call with its call type, duration, and whether it errored.
func AICall(callType string, durationSecs float64, failed bool) {
	ct := strings.TrimSpace(callType)
	if ct == "" {
		ct = "unknown"
	}

	AICallsTotal.Inc()
	AICallDuration.Observe(durationSecs)
	if failed {
		AICallErrorsTotal.Inc()
	}

	aiCallMetricsMu.Lock()

	callCounter, ok := aiCallsByType[ct]
	if !ok {
		callCounter = DefaultRegistry.NewCounter(
			"autobughunter_ai_calls_by_type_total",
			"AI/LLM API calls broken down by call type.",
			map[string]string{"call_type": ct},
		)
		aiCallsByType[ct] = callCounter
	}
	callCounter.Inc()

	durHist, ok := aiDurationByType[ct]
	if !ok {
		durHist = DefaultRegistry.NewHistogram(
			"autobughunter_ai_call_duration_seconds_by_type",
			"AI/LLM API call latency in seconds broken down by call type.",
			map[string]string{"call_type": ct},
			[]float64{0.1, 0.5, 1, 2, 5, 10, 20, 30},
		)
		aiDurationByType[ct] = durHist
	}
	durHist.Observe(durationSecs)

	if failed {
		errCounter, ok := aiErrorsByType[ct]
		if !ok {
			errCounter = DefaultRegistry.NewCounter(
				"autobughunter_ai_call_errors_by_type_total",
				"AI/LLM API call errors broken down by call type.",
				map[string]string{"call_type": ct},
			)
			aiErrorsByType[ct] = errCounter
		}
		aiCallMetricsMu.Unlock()
		errCounter.Inc()
		return
	}

	aiCallMetricsMu.Unlock()
}

// ToolRun records one scanner-tool execution with tool/agent/status labels and duration.
func ToolRun(toolName, agentName, status string, duration time.Duration) {
	tool := strings.TrimSpace(toolName)
	if tool == "" {
		tool = "unknown"
	}
	agent := strings.TrimSpace(agentName)
	if agent == "" {
		agent = "unknown"
	}
	state := strings.TrimSpace(status)
	if state == "" {
		state = "unknown"
	}
	if duration < 0 {
		duration = 0
	}
	key := tool + "|" + agent + "|" + state
	labels := map[string]string{
		"tool":   tool,
		"agent":  agent,
		"status": state,
	}

	toolMetricsMu.Lock()
	runCounter, ok := toolRunsByKey[key]
	if !ok {
		runCounter = DefaultRegistry.NewCounter(
			"autobughunter_tool_runs_total",
			"Scanner tool runs broken down by tool, agent, and status.",
			labels,
		)
		toolRunsByKey[key] = runCounter
	}
	durationHistogram, ok := toolDurationByKey[key]
	if !ok {
		durationHistogram = DefaultRegistry.NewHistogram(
			"autobughunter_tool_duration_seconds",
			"Scanner tool execution duration broken down by tool, agent, and status.",
			labels,
			nil,
		)
		toolDurationByKey[key] = durationHistogram
	}
	toolMetricsMu.Unlock()

	runCounter.Inc()
	durationHistogram.Observe(duration.Seconds())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func labelsStr(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	return renderLabels(labels)
}

func mergeLabels(base, extra map[string]string) string {
	merged := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	return renderLabels(merged)
}

func renderLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+`="`+escapeLabel(labels[k])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
