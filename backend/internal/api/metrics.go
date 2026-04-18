package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// metricsRegistry collects a small set of Prometheus-style counters and
// gauges that are useful for operating the service. It intentionally uses
// only the standard library to avoid a Prometheus client dependency.
type metricsRegistry struct {
	httpRequests     sync.Map // map[string]*int64 (key = method|status)
	scansTotal       int64
	scansSucceeded   int64
	scansFailed      int64
	findingsBySev    sync.Map // map[string]*int64 (key = severity)
	webhookSuccess   int64
	webhookFailures  int64
	rateLimitedReqs  int64
	authRejectedReqs int64
}

var metrics = &metricsRegistry{}

func (m *metricsRegistry) recordHTTP(method string, status int) {
	key := fmt.Sprintf("%s|%d", strings.ToUpper(method), status)
	if status == http.StatusTooManyRequests {
		atomic.AddInt64(&m.rateLimitedReqs, 1)
	}
	if status == http.StatusUnauthorized {
		atomic.AddInt64(&m.authRejectedReqs, 1)
	}
	v, _ := m.httpRequests.LoadOrStore(key, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

func (m *metricsRegistry) recordScanStarted() { atomic.AddInt64(&m.scansTotal, 1) }
func (m *metricsRegistry) recordScanCompleted(success bool) {
	if success {
		atomic.AddInt64(&m.scansSucceeded, 1)
	} else {
		atomic.AddInt64(&m.scansFailed, 1)
	}
}
func (m *metricsRegistry) recordFindings(severityCounts map[string]int) {
	for sev, n := range severityCounts {
		if n <= 0 {
			continue
		}
		v, _ := m.findingsBySev.LoadOrStore(strings.ToLower(sev), new(int64))
		atomic.AddInt64(v.(*int64), int64(n))
	}
}
func (m *metricsRegistry) recordWebhook(success bool) {
	if success {
		atomic.AddInt64(&m.webhookSuccess, 1)
	} else {
		atomic.AddInt64(&m.webhookFailures, 1)
	}
}

// metricsResponseWriter captures the response status so that the metrics
// middleware can record it after the handler returns.
type metricsResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (mw *metricsResponseWriter) WriteHeader(status int) {
	if mw.wroteHeader {
		return
	}
	mw.status = status
	mw.wroteHeader = true
	mw.ResponseWriter.WriteHeader(status)
}

func (mw *metricsResponseWriter) Write(b []byte) (int, error) {
	if !mw.wroteHeader {
		mw.status = http.StatusOK
		mw.wroteHeader = true
	}
	return mw.ResponseWriter.Write(b)
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't count the metrics endpoint itself to avoid noise.
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		mw := &metricsResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(mw, r)
		metrics.recordHTTP(r.Method, mw.status)
	})
}

// handleMetrics renders the registry in the Prometheus text exposition format.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder
	b.WriteString("# HELP auto_bughunter_http_requests_total Total HTTP requests by method and status code.\n")
	b.WriteString("# TYPE auto_bughunter_http_requests_total counter\n")
	type httpRow struct {
		method string
		status string
		count  int64
	}
	rows := make([]httpRow, 0)
	metrics.httpRequests.Range(func(k, v any) bool {
		key := k.(string)
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			return true
		}
		rows = append(rows, httpRow{method: parts[0], status: parts[1], count: atomic.LoadInt64(v.(*int64))})
		return true
	})
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].method != rows[j].method {
			return rows[i].method < rows[j].method
		}
		return rows[i].status < rows[j].status
	})
	for _, row := range rows {
		fmt.Fprintf(&b, "auto_bughunter_http_requests_total{method=%q,status=%q} %d\n", row.method, row.status, row.count)
	}

	b.WriteString("# HELP auto_bughunter_scans_total Total scans started.\n")
	b.WriteString("# TYPE auto_bughunter_scans_total counter\n")
	fmt.Fprintf(&b, "auto_bughunter_scans_total %d\n", atomic.LoadInt64(&metrics.scansTotal))

	b.WriteString("# HELP auto_bughunter_scans_completed_total Scans completed by outcome.\n")
	b.WriteString("# TYPE auto_bughunter_scans_completed_total counter\n")
	fmt.Fprintf(&b, "auto_bughunter_scans_completed_total{outcome=%q} %d\n", "succeeded", atomic.LoadInt64(&metrics.scansSucceeded))
	fmt.Fprintf(&b, "auto_bughunter_scans_completed_total{outcome=%q} %d\n", "failed", atomic.LoadInt64(&metrics.scansFailed))

	b.WriteString("# HELP auto_bughunter_findings_total Findings produced by severity.\n")
	b.WriteString("# TYPE auto_bughunter_findings_total counter\n")
	sevs := []string{}
	metrics.findingsBySev.Range(func(k, _ any) bool { sevs = append(sevs, k.(string)); return true })
	sort.Strings(sevs)
	for _, sev := range sevs {
		v, _ := metrics.findingsBySev.Load(sev)
		fmt.Fprintf(&b, "auto_bughunter_findings_total{severity=%q} %d\n", sev, atomic.LoadInt64(v.(*int64)))
	}

	b.WriteString("# HELP auto_bughunter_webhook_deliveries_total Outbound webhook deliveries by outcome.\n")
	b.WriteString("# TYPE auto_bughunter_webhook_deliveries_total counter\n")
	fmt.Fprintf(&b, "auto_bughunter_webhook_deliveries_total{outcome=%q} %d\n", "success", atomic.LoadInt64(&metrics.webhookSuccess))
	fmt.Fprintf(&b, "auto_bughunter_webhook_deliveries_total{outcome=%q} %d\n", "failure", atomic.LoadInt64(&metrics.webhookFailures))

	b.WriteString("# HELP auto_bughunter_rate_limited_requests_total Requests rejected by the API rate limiter.\n")
	b.WriteString("# TYPE auto_bughunter_rate_limited_requests_total counter\n")
	fmt.Fprintf(&b, "auto_bughunter_rate_limited_requests_total %d\n", atomic.LoadInt64(&metrics.rateLimitedReqs))

	b.WriteString("# HELP auto_bughunter_auth_rejected_requests_total Requests rejected for missing or invalid API token.\n")
	b.WriteString("# TYPE auto_bughunter_auth_rejected_requests_total counter\n")
	fmt.Fprintf(&b, "auto_bughunter_auth_rejected_requests_total %d\n", atomic.LoadInt64(&metrics.authRejectedReqs))

	_, _ = w.Write([]byte(b.String()))
}
