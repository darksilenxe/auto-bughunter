package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
)

type principal struct {
	KeyID       string
	WorkspaceID string
	Role        model.APIKeyRole
	Name        string
	SuperAdmin  bool
}

type contextKey string

const principalContextKey contextKey = "apiPrincipal"

type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, workspaceID, name string, role model.APIKeyRole) (*model.APIKeyRecord, string, error)
	ListAPIKeys(ctx context.Context, workspaceID string) ([]model.APIKeyRecord, error)
	RotateAPIKey(ctx context.Context, id string) (*model.APIKeyRecord, string, error)
	RevokeAPIKey(ctx context.Context, id string) error
	AuthenticateAPIKey(ctx context.Context, rawKey string) (*model.APIKeyRecord, error)
}

type apiRateLimiter struct {
	mu                sync.Mutex
	userWindowStart   time.Time
	perUserCount      map[string]int
	targetWindowStart time.Time
	perTargetCount    map[string]int
	maxPerUser        int
	maxPerTarget      int
}

func newAPIRateLimiter() *apiRateLimiter {
	return &apiRateLimiter{
		perUserCount:   map[string]int{},
		perTargetCount: map[string]int{},
		maxPerUser:     maxInt(1, intFromEnv("API_RATE_LIMIT_PER_USER_PER_MINUTE", 300)),
		maxPerTarget:   maxInt(1, intFromEnv("API_RATE_LIMIT_PER_TARGET_PER_MINUTE", 120)),
	}
}

func (l *apiRateLimiter) allow(p principal, target string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	minute := now.Truncate(time.Minute)
	if l.userWindowStart.IsZero() || !l.userWindowStart.Equal(minute) {
		l.userWindowStart = minute
		l.perUserCount = map[string]int{}
	}
	userKey := p.KeyID
	if userKey == "" {
		userKey = p.Name
	}
	l.perUserCount[userKey]++
	if l.perUserCount[userKey] > l.maxPerUser {
		return errors.New("per-user API rate limit exceeded")
	}

	if strings.TrimSpace(target) == "" {
		return nil
	}
	if l.targetWindowStart.IsZero() || !l.targetWindowStart.Equal(minute) {
		l.targetWindowStart = minute
		l.perTargetCount = map[string]int{}
	}
	targetKey := strings.ToLower(strings.TrimSpace(target))
	l.perTargetCount[targetKey]++
	if l.perTargetCount[targetKey] > l.maxPerTarget {
		return errors.New("per-target API rate limit exceeded")
	}
	return nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		rawKey := extractAPIKey(r)
		if rawKey == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing API key"})
			return
		}
		p, err := s.authenticatePrincipal(r.Context(), rawKey)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		target := targetForRateLimit(r)
		if s.apiRateLimiter != nil {
			if err := s.apiRateLimiter.allow(p, target, time.Now().UTC()); err != nil {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func targetForRateLimit(r *http.Request) string {
	if r.Method != http.MethodPost {
		return strings.TrimSpace(r.URL.Query().Get("target"))
	}
	if !strings.HasPrefix(r.URL.Path, "/api/scan") && !strings.HasPrefix(r.URL.Path, "/api/automation/event") {
		return ""
	}
	if r.Body == nil {
		return ""
	}
	raw, err := ioReadAllLimited(r.Body, 1<<20)
	if err != nil {
		return ""
	}
	r.Body = ioNopCloserFromBytes(raw)
	var payload struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.Target)
}

func ioReadAllLimited(body io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, max))
}

func ioNopCloserFromBytes(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}

func principalFromContext(ctx context.Context) (principal, bool) {
	v := ctx.Value(principalContextKey)
	if v == nil {
		return principal{}, false
	}
	p, ok := v.(principal)
	return p, ok
}

func (s *Server) authenticatePrincipal(ctx context.Context, rawKey string) (principal, error) {
	bootstrap := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_API_KEY"))
	if bootstrap == "" {
		bootstrap = "dev-admin-key"
	}
	if bootstrap != "" && subtleConstantTimeEq(rawKey, bootstrap) {
		return principal{
			KeyID:       "bootstrap-admin",
			WorkspaceID: "*",
			Role:        model.APIKeyRoleAdmin,
			Name:        "bootstrap-admin",
			SuperAdmin:  true,
		}, nil
	}
	store, ok := s.repo.(APIKeyStore)
	if !ok {
		return principal{}, errors.New("api key store unavailable")
	}
	record, err := store.AuthenticateAPIKey(ctx, rawKey)
	if err != nil {
		return principal{}, err
	}
	return principal{
		KeyID:       record.ID,
		WorkspaceID: record.WorkspaceID,
		Role:        record.Role,
		Name:        record.Name,
	}, nil
}

func workspaceFromRequest(r *http.Request) string {
	if p, ok := principalFromContext(r.Context()); ok {
		return p.WorkspaceID
	}
	return ""
}

func requesterFromRequest(r *http.Request) string {
	if p, ok := principalFromContext(r.Context()); ok {
		return p.Name
	}
	return ""
}

func hasRole(ctx context.Context, allowed ...model.APIKeyRole) bool {
	p, ok := principalFromContext(ctx)
	if !ok {
		return false
	}
	if p.SuperAdmin {
		return true
	}
	for _, role := range allowed {
		if p.Role == role {
			return true
		}
	}
	return false
}

func canAccessWorkspace(ctx context.Context, workspaceID string) bool {
	p, ok := principalFromContext(ctx)
	if !ok {
		return false
	}
	if p.SuperAdmin {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(p.WorkspaceID), strings.TrimSpace(workspaceID))
}

func canAccessWorkspaceForRequest(ctx context.Context, workspaceID string) bool {
	if _, ok := principalFromContext(ctx); !ok {
		return false
	}
	return canAccessWorkspace(ctx, workspaceID)
}

func extractAPIKey(r *http.Request) string {
	if h := strings.TrimSpace(r.Header.Get("X-API-Key")); h != "" {
		return h
	}
	if q := strings.TrimSpace(r.URL.Query().Get("api_key")); q != "" {
		return q
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

func normalizeAPIKeyRole(raw string) model.APIKeyRole {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(model.APIKeyRoleAdmin):
		return model.APIKeyRoleAdmin
	case string(model.APIKeyRoleTriager):
		return model.APIKeyRoleTriager
	case string(model.APIKeyRoleAnalyst):
		return model.APIKeyRoleAnalyst
	default:
		return model.APIKeyRoleViewer
	}
}

func subtleConstantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := 0; i < len(a); i++ {
		out |= a[i] ^ b[i]
	}
	return out == 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func defaultPolicyPack() string {
	pack := strings.TrimSpace(os.Getenv("DEFAULT_POLICY_PACK"))
	if pack == "" {
		pack = "internal"
	}
	return pack
}

func workspaceFromHeader(r *http.Request) string {
	return firstNonEmpty(r.Header.Get("X-Workspace-ID"), r.URL.Query().Get("workspaceId"))
}
