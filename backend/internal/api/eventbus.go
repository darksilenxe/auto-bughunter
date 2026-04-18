package api

import (
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
)

// EventBus is a thread-safe, per-scan publish/subscribe hub.
// Publishers (agents, the scanner) call Publish to broadcast events.
// SSE connections Subscribe to receive them in real-time.
// History is retained so late-joining clients can replay past events.
type EventBus struct {
	mu          sync.Mutex
	history     map[string][]model.ScanEvent
	subscribers map[string][]chan model.ScanEvent
}

// NewEventBus creates an empty EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		history:     make(map[string][]model.ScanEvent),
		subscribers: make(map[string][]chan model.ScanEvent),
	}
}

// Publish broadcasts event to all current subscribers for scanID and appends it to
// the per-scan history so that future SSE subscribers can replay missed events.
func (b *EventBus) Publish(scanID string, event model.ScanEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	b.mu.Lock()
	b.history[scanID] = append(b.history[scanID], event)
	subs := make([]chan model.ScanEvent, len(b.subscribers[scanID]))
	copy(subs, b.subscribers[scanID])
	b.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- event:
		default:
			// Subscriber is slow; drop rather than block.
		}
	}
}

// Subscribe registers a new subscriber for scanID and returns a channel that
// receives future events and an unsubscribe function that must be called by the
// caller when done (e.g., when the SSE connection closes).
// History events are NOT replayed here; call History first.
func (b *EventBus) Subscribe(scanID string) (<-chan model.ScanEvent, func()) {
	ch := make(chan model.ScanEvent, 64)
	b.mu.Lock()
	b.subscribers[scanID] = append(b.subscribers[scanID], ch)
	b.mu.Unlock()

	unsub := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		subs := b.subscribers[scanID]
		newSubs := make([]chan model.ScanEvent, 0, len(subs))
		for _, s := range subs {
			if s != ch {
				newSubs = append(newSubs, s)
			}
		}
		b.subscribers[scanID] = newSubs
	}
	return ch, unsub
}

// History returns a copy of all events recorded for scanID so far.
// Callers should read History before calling Subscribe to avoid race-missing events.
func (b *EventBus) History(scanID string) []model.ScanEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	events := b.history[scanID]
	out := make([]model.ScanEvent, len(events))
	copy(out, events)
	return out
}

// Cleanup removes all history and subscribers for scanID. Call after the scan
// is fully complete and all SSE subscribers have disconnected.
func (b *EventBus) Cleanup(scanID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.history, scanID)
	delete(b.subscribers, scanID)
}

// EmitterFor returns a closure that publishes events for the given scanID.
func (b *EventBus) EmitterFor(scanID string) func(model.ScanEvent) {
	return func(event model.ScanEvent) {
		b.Publish(scanID, event)
	}
}
