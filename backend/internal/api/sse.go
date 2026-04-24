package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// handleScanEvents implements GET /api/scan/{id}/events as a Server-Sent Events
// (SSE) endpoint. It replays the full event history for the scan and then streams
// live events in real-time until the client disconnects or the context is cancelled.
func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract scan ID from path: /api/scan/{id}/events
	path := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	path = strings.TrimSuffix(path, "/events")
	id := strings.TrimSpace(path)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	// Verify the scan exists.
	if _, err := s.repo.GetJob(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	// SSE requires specific headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_ = applyCORSHeaders(w, r)
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	sendEvent := func(data []byte) {
		fmt.Fprintf(w, "data: %s\n\n", data)
		if canFlush {
			flusher.Flush()
		}
	}

	// 1. Replay all historical events so that clients connecting after a scan
	//    has already started still see the full picture.
	for _, evt := range s.eventBus.History(id) {
		b, err := json.Marshal(evt)
		if err == nil {
			sendEvent(b)
		}
	}

	// 2. Subscribe for future events.
	ch, unsub := s.eventBus.Subscribe(id)
	defer unsub()

	// 3. Keep-alive ticker so that reverse proxies and browsers do not time out
	//    the connection while waiting for the next event.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(evt)
			if err == nil {
				sendEvent(b)
			}
		case <-ticker.C:
			// Send a comment to keep the connection alive.
			fmt.Fprintf(w, ": keep-alive\n\n")
			if canFlush {
				flusher.Flush()
			}
		}
	}
}
