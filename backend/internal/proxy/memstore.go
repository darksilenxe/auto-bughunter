package proxy

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"

	"auto-bughunter/backend/internal/model"
)

type MemStore struct {
	mu    sync.RWMutex
	items map[string]model.ProxyRequest
}

var proxySensitiveKV = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s&;]+)`)

func NewMemStore() *MemStore {
	return &MemStore{items: map[string]model.ProxyRequest{}}
}

func (s *MemStore) SaveProxyRequest(ctx context.Context, req *model.ProxyRequest) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if req == nil {
		return errors.New("proxy request is required")
	}
	copyReq := *req
	copyReq.RequestHeaders = redactProxyHeaders(req.RequestHeaders)
	copyReq.ResponseHeaders = redactProxyHeaders(req.ResponseHeaders)
	copyReq.RequestBody = redactProxyText(req.RequestBody)
	copyReq.ResponseBody = redactProxyText(req.ResponseBody)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[copyReq.ID] = copyReq
	return nil
}

func (s *MemStore) ListProxyRequests(ctx context.Context) ([]*model.ProxyRequest, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ProxyRequest, 0, len(s.items))
	for _, item := range s.items {
		out = append(out, cloneProxyRequest(item))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CapturedAt.After(out[j].CapturedAt) })
	result := make([]*model.ProxyRequest, 0, len(out))
	for _, item := range out {
		copyItem := item
		result = append(result, &copyItem)
	}
	return result, nil
}

func (s *MemStore) GetProxyRequest(ctx context.Context, id string) (*model.ProxyRequest, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.items[strings.TrimSpace(id)]
	if !ok {
		return nil, sql.ErrNoRows
	}
	copyItem := cloneProxyRequest(item)
	return &copyItem, nil
}

func (s *MemStore) ClearProxyRequests(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = map[string]model.ProxyRequest{}
	return nil
}

func cloneProxyRequest(item model.ProxyRequest) model.ProxyRequest {
	copyItem := item
	copyItem.RequestHeaders = cloneHeaderMap(item.RequestHeaders)
	copyItem.ResponseHeaders = cloneHeaderMap(item.ResponseHeaders)
	return copyItem
}

func cloneHeaderMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func redactProxyHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "authorization" || lower == "cookie" || lower == "set-cookie" || strings.Contains(lower, "token") || strings.Contains(lower, "secret") {
			out[k] = "[redacted]"
			continue
		}
		out[k] = redactProxyText(v)
	}
	return out
}

func redactProxyText(value string) string {
	value = proxySensitiveKV.ReplaceAllString(value, "$1=[redacted]")
	return strings.ReplaceAll(value, "Bearer ", "Bearer [redacted]")
}
