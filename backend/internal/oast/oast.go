// Package oast implements a small, self-hosted out-of-band application security
// testing (OAST) service. Scanners ask the service for a single-use callback
// URL via Issue, embed that URL in payloads (HTTP headers, request bodies,
// SSRF-prone parameters, blind RCE commands, etc.) sent to the target, and
// later call Hits/Wait to check whether the target — or anything it caused —
// fetched the URL. A confirmed callback is strong evidence of an out-of-band
// vulnerability such as SSRF, blind XXE, blind RCE or log4shell-style
// resolution.
//
// Only HTTP(S) callbacks are recorded by this package; OOB DNS interactions
// require infrastructure that is intentionally out of scope here.
package oast

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Hit represents a single recorded interaction with a callback URL.
type Hit struct {
	Token      string            `json:"token"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query,omitempty"`
	RemoteAddr string            `json:"remoteAddr"`
	UserAgent  string            `json:"userAgent,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	ReceivedAt time.Time         `json:"receivedAt"`
}

// Token is a handle returned by Issue.
type Token struct {
	Token       string    `json:"token"`
	CallbackURL string    `json:"callbackUrl"`
	ScanID      string    `json:"scanId,omitempty"`
	Label       string    `json:"label,omitempty"`
	IssuedAt    time.Time `json:"issuedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// Config configures a Service.
type Config struct {
	// PublicBaseURL is the externally reachable URL prefix that the
	// callback listener serves. Example: "http://oast.example.com:9000".
	// Tokens will be embedded as PublicBaseURL + "/" + token.
	PublicBaseURL string
	// TTL is how long a token (and its hits) is retained. Defaults to 1h.
	TTL time.Duration
	// MaxBodyBytes is the maximum number of body bytes captured per hit.
	// Defaults to 4096.
	MaxBodyBytes int64
	// MaxHitsPerToken caps memory growth per token. Defaults to 25.
	MaxHitsPerToken int
}

// Service is an in-memory OAST registry plus an http.Handler that records
// callback interactions. It is safe for concurrent use.
type Service struct {
	cfg    Config
	mu     sync.RWMutex
	tokens map[string]*tokenState
	now    func() time.Time // overridable for tests
}

type tokenState struct {
	meta Token
	hits []Hit
	// signal is closed when at least one hit has been recorded. Subsequent
	// hits also broadcast on this channel by replacing it, so Wait can
	// observe new hits beyond the first.
	signal chan struct{}
}

// NewService constructs a Service. PublicBaseURL must be set for Issue to
// return usable callback URLs, but the Service is otherwise functional.
func NewService(cfg Config) *Service {
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 4096
	}
	if cfg.MaxHitsPerToken <= 0 {
		cfg.MaxHitsPerToken = 25
	}
	cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	return &Service{
		cfg:    cfg,
		tokens: map[string]*tokenState{},
		now:    time.Now,
	}
}

// Issue creates a new token associated with the given scan ID and label.
// Either may be empty. The returned Token's CallbackURL is empty when the
// service has no PublicBaseURL configured.
func (s *Service) Issue(scanID, label string) Token {
	tok := newToken()
	now := s.now()
	meta := Token{
		Token:     tok,
		ScanID:    scanID,
		Label:     label,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.cfg.TTL),
	}
	if s.cfg.PublicBaseURL != "" {
		meta.CallbackURL = s.cfg.PublicBaseURL + "/" + tok
	}
	s.mu.Lock()
	s.gcLocked(now)
	s.tokens[tok] = &tokenState{meta: meta, signal: make(chan struct{})}
	s.mu.Unlock()
	return meta
}

// Hits returns a copy of the hits recorded for a token. The boolean reports
// whether the token is known (and unexpired).
func (s *Service) Hits(token string) ([]Hit, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.tokens[token]
	if !ok {
		return nil, false
	}
	if s.now().After(st.meta.ExpiresAt) {
		// Known but expired tokens are reported as unknown so callers can't
		// distinguish "never issued" from "TTL elapsed".
		return nil, false
	}
	out := make([]Hit, len(st.hits))
	copy(out, st.hits)
	return out, true
}

// Tokens returns metadata for every active token, optionally filtered by
// scanID. Pass an empty scanID to list all.
func (s *Service) Tokens(scanID string) []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := make([]Token, 0, len(s.tokens))
	for _, st := range s.tokens {
		if now.After(st.meta.ExpiresAt) {
			continue
		}
		if scanID != "" && st.meta.ScanID != scanID {
			continue
		}
		out = append(out, st.meta)
	}
	return out
}

// Wait blocks until the token receives at least one hit, the timeout
// elapses, or the request context is cancelled. It returns the slice of
// hits recorded so far. An unknown token returns immediately with an empty
// slice.
func (s *Service) Wait(token string, timeout time.Duration) []Hit {
	s.mu.RLock()
	st, ok := s.tokens[token]
	if !ok {
		s.mu.RUnlock()
		return nil
	}
	if len(st.hits) > 0 {
		out := make([]Hit, len(st.hits))
		copy(out, st.hits)
		s.mu.RUnlock()
		return out
	}
	signal := st.signal
	s.mu.RUnlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-signal:
	case <-timer.C:
	}
	hits, _ := s.Hits(token)
	return hits
}

// Handler returns an http.Handler that records callback interactions on
// paths of the form "/{token}" or "/{token}/...". Any HTTP method is
// accepted; the response is a small, neutral text body and never echoes the
// token. Unknown tokens get a 404.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip the leading slash and pull the first path segment as the token.
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}
	segments := strings.SplitN(path, "/", 2)
	tok := segments[0]
	rest := ""
	if len(segments) == 2 {
		rest = segments[1]
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes))
	_ = r.Body.Close()

	headers := map[string]string{}
	for k, v := range r.Header {
		if len(v) == 0 {
			continue
		}
		// Skip noisy hop-by-hop headers; keep one value per name to bound size.
		switch strings.ToLower(k) {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			continue
		}
		headers[k] = v[0]
	}

	hit := Hit{
		Token:      tok,
		Method:     r.Method,
		Path:       "/" + rest,
		Query:      r.URL.RawQuery,
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Headers:    headers,
		Body:       string(body),
		ReceivedAt: s.now(),
	}

	if !s.record(hit) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

// record stores the hit if its token is known and unexpired. Returns true
// if recorded.
func (s *Service) record(hit Hit) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tokens[hit.Token]
	if !ok || s.now().After(st.meta.ExpiresAt) {
		return false
	}
	if len(st.hits) >= s.cfg.MaxHitsPerToken {
		// Drop the oldest to keep memory bounded.
		st.hits = st.hits[1:]
	}
	st.hits = append(st.hits, hit)
	// Broadcast: close the current signal and install a fresh one so future
	// Wait callers can also observe new hits.
	old := st.signal
	st.signal = make(chan struct{})
	close(old)
	return true
}

// gcLocked evicts expired tokens. The caller must hold s.mu.
func (s *Service) gcLocked(now time.Time) {
	for k, st := range s.tokens {
		if now.After(st.meta.ExpiresAt) {
			delete(s.tokens, k)
		}
	}
}

// Configured reports whether the service has a public base URL set, i.e.
// can issue usable callback URLs.
func (s *Service) Configured() bool { return s.cfg.PublicBaseURL != "" }

// PublicBaseURL returns the configured public base URL.
func (s *Service) PublicBaseURL() string { return s.cfg.PublicBaseURL }

func newToken() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a time-based identifier; collisions are extraordinarily
		// unlikely for the brief TTLs we use, but rand failing is itself
		// noteworthy. Use nanos to avoid duplicates.
		return hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(b[:])
}
