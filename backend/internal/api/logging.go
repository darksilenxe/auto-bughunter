package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// requestIDHeader is the HTTP header used to propagate the per-request
// correlation ID. If a caller already supplied a value (e.g. an upstream
// gateway) it is preserved; otherwise a fresh UUIDv4 is generated.
const requestIDHeader = "X-Request-ID"

// requestLoggingMiddleware emits a single structured JSON log line per
// request capturing method, path, status, byte count, duration and the
// correlation ID. It is intentionally minimal — production deployments
// can ship the lines straight into any log aggregator (Loki, ELK, etc.).
//
// Health and metrics endpoints are exempt to avoid drowning the logs in
// probe traffic; they remain countable via the Prometheus metrics.
func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLogExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		rid := r.Header.Get(requestIDHeader)
		if rid == "" {
			rid = uuid.NewString()
		}
		w.Header().Set(requestIDHeader, rid)

		lw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(lw, r)
		entry := map[string]any{
			"ts":         start.UTC().Format(time.RFC3339Nano),
			"level":      "info",
			"msg":        "http_request",
			"requestId":  rid,
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     lw.status,
			"bytes":      lw.bytes,
			"durationMs": time.Since(start).Milliseconds(),
			"remote":     clientKey(r),
		}
		if ua := r.UserAgent(); ua != "" {
			entry["userAgent"] = ua
		}
		// Use the standard logger so output goes through the same sink as
		// the rest of the application; the payload itself is JSON.
		if buf, err := json.Marshal(entry); err == nil {
			log.Println(string(buf))
		}
	})
}

func isLogExemptPath(p string) bool {
	switch p {
	case "/api/health", "/api/ready", "/metrics":
		return true
	}
	return false
}

// loggingResponseWriter captures the status code and number of bytes
// written so the logging middleware can report them. It deliberately
// does not buffer the body.
type loggingResponseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (lw *loggingResponseWriter) WriteHeader(status int) {
	if lw.wroteHeader {
		return
	}
	lw.status = status
	lw.wroteHeader = true
	lw.ResponseWriter.WriteHeader(status)
}

func (lw *loggingResponseWriter) Write(b []byte) (int, error) {
	if !lw.wroteHeader {
		lw.status = http.StatusOK
		lw.wroteHeader = true
	}
	n, err := lw.ResponseWriter.Write(b)
	lw.bytes += n
	return n, err
}

// Flush forwards Flush calls so SSE handlers continue to work when this
// middleware is in the chain.
func (lw *loggingResponseWriter) Flush() {
	if f, ok := lw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
