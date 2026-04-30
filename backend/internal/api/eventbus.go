package api

import (
	"log"
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
		// Use a closure with recover so that sending to a channel closed by
		// Cleanup does not panic; treat it the same as a slow subscriber.
		func(c chan model.ScanEvent) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("eventbus: recovered panic publishing to subscriber: %v", r)
				}
			}()
			select {
			case c <- event:
			default:
				// Subscriber is slow; drop rather than block.
			}
		}(ch)
	}
}

// Subscribe registers a new subscriber for scanID and returns a channel that
// receives future events and an unsubscribe function that must be called by the
// caller when done (e.g., when the SSE connection closes).
// History events are NOT replayed here; call History first.
func (b *EventBus) Subscribe(scanID string) (<-chan model.ScanEvent, func()) {
	_, ch, unsub := b.SubscribeWithHistory(scanID)
	return ch, unsub
}

// SubscribeWithHistory atomically returns the full event history for scanID
// and registers a new live subscriber in a single lock acquisition.  This
// eliminates the race between a separate History+Subscribe call pair where
// events published between the two calls would otherwise be missed.
func (b *EventBus) SubscribeWithHistory(scanID string) ([]model.ScanEvent, <-chan model.ScanEvent, func()) {
	ch := make(chan model.ScanEvent, 64)
	b.mu.Lock()
	events := b.history[scanID]
	out := make([]model.ScanEvent, len(events))
	copy(out, events)
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
	return out, ch, unsub
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

// Cleanup removes all history and subscribers for scanID. It closes all
// subscriber channels so that SSE handler goroutines can exit cleanly rather
// than waiting indefinitely for events that will never arrive.
func (b *EventBus) Cleanup(scanID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subscribers[scanID] {
		close(ch)
	}
	delete(b.history, scanID)
	delete(b.subscribers, scanID)
}

// EmitterFor returns a closure that publishes events for the given scanID.
func (b *EventBus) EmitterFor(scanID string) func(model.ScanEvent) {
	return func(event model.ScanEvent) {
		b.Publish(scanID, event)
	}
}
