package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/google/uuid"
)

// RecordingTransport is an http.RoundTripper that captures every
// request/response pair made by the scanner and persists them in the proxy
// Store so that the Network Graph UI (which reads /api/proxy/requests) can
// visualise scanner-generated traffic even when the MITM proxy is disabled.
//
// Bodies are capped at maxCaptureBody bytes; all saves are fire-and-forget
// goroutines so they never block the scanner's critical path.
type RecordingTransport struct {
	Wrapped      http.RoundTripper
	Store        Store
	PassiveStore *PassiveScanStore
}

// RoundTrip implements http.RoundTripper.
func (rt *RecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Read and restore request body.
	var reqBodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		limited, _ := io.ReadAll(io.LimitReader(req.Body, maxCaptureBody))
		reqBodyBytes = limited
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
	}

	transport := rt.Wrapped
	if transport == nil {
		transport = http.DefaultTransport
	}
	resp, err := transport.RoundTrip(req)

	method := req.Method
	rawURL := req.URL.String()
	reqHeaders := flattenHeaders(req.Header)
	capturedAt := time.Now().UTC()

	if err != nil {
		// Record the failed attempt so it appears in the graph.
		go rt.save(&model.ProxyRequest{
			ID:             uuid.NewString(),
			CapturedAt:     capturedAt,
			Method:         method,
			URL:            rawURL,
			RequestHeaders: reqHeaders,
			RequestBody:    string(reqBodyBytes),
			ResponseStatus: 0,
			Notes:          "scanner request failed: " + err.Error(),
		})
		return nil, err
	}

	// Read and restore response body.
	var respBodyBytes []byte
	if resp.Body != nil {
		respBodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody))
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(respBodyBytes))
	}

	captured := &model.ProxyRequest{
		ID:              uuid.NewString(),
		CapturedAt:      capturedAt,
		Method:          method,
		URL:             rawURL,
		RequestHeaders:  reqHeaders,
		RequestBody:     string(reqBodyBytes),
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: flattenHeaders(resp.Header),
		ResponseBody:    string(respBodyBytes),
	}
	// Feed scanner-generated traffic into the passive findings store so live
	// scans can consume proxy-derived findings in the same run.
	if rt.PassiveStore != nil {
		rt.PassiveStore.Analyze(captured)
	}
	go rt.save(captured)

	return resp, nil
}

func (rt *RecordingTransport) save(pr *model.ProxyRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = rt.Store.SaveProxyRequest(ctx, pr)
}
