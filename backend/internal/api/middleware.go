package api

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// authMiddleware enforces a static bearer token if configured. Health and
// metrics endpoints are exempt so that liveness probes and Prometheus scrapes
// continue to work without credentials.
func authMiddleware(token string, next http.Handler) http.Handler {
	token = strings.TrimSpace(token)
	if token == "" {
		return next
	}
	expected := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAuthExemptPath(r.URL.Path) || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		provided := extractBearerToken(r)
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), expected) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="auto-bughunter"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid API token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAuthExemptPath(p string) bool {
	switch p {
	case "/api/health", "/api/ready", "/api/openapi.json", "/metrics":
		return true
	}
	return false
}

func extractBearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h != "" {
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			return strings.TrimSpace(h[7:])
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-API-Token")); v != "" {
		return v
	}
	return ""
}

// rateLimiter implements a simple per-client token-bucket-style limiter using a
// fixed window. It is intentionally minimal and dependency-free; for very high
// volumes a dedicated limiter library should be used.
type rateLimiter struct {
	limit   int
	window  time.Duration
	mu      sync.Mutex
	clients map[string]*rateState
	lastGC  time.Time
}

type rateState struct {
	count     int
	windowEnd time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	return &rateLimiter{
		limit:   perMinute,
		window:  time.Minute,
		clients: map[string]*rateState{},
		lastGC:  time.Now(),
	}
}

// allow returns true if the given client key may proceed. It also reports the
// number of remaining requests and the time when the window resets.
func (rl *rateLimiter) allow(key string, now time.Time) (bool, int, time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	st, ok := rl.clients[key]
	if !ok || now.After(st.windowEnd) {
		st = &rateState{count: 0, windowEnd: now.Add(rl.window)}
		rl.clients[key] = st
	}
	st.count++
	if now.Sub(rl.lastGC) > 5*time.Minute {
		for k, v := range rl.clients {
			if now.After(v.windowEnd) {
				delete(rl.clients, k)
			}
		}
		rl.lastGC = now
	}
	remaining := rl.limit - st.count
	if remaining < 0 {
		remaining = 0
	}
	return st.count <= rl.limit, remaining, st.windowEnd
}

func rateLimitMiddleware(rl *rateLimiter, next http.Handler) http.Handler {
	if rl == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health and metrics are exempt to avoid breaking probes/scrapers.
		if isAuthExemptPath(r.URL.Path) || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		key := clientKey(r)
		ok, remaining, reset := rl.allow(key, time.Now())
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", reset.UTC().Format(time.RFC3339))
		if !ok {
			retryAfter := int(time.Until(reset).Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientKey(r *http.Request) string {
	// Honor X-Forwarded-For when present (first hop) so that deployments
	// behind a reverse proxy still get per-client limits.
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if comma := strings.Index(xff, ","); comma >= 0 {
			xff = xff[:comma]
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
