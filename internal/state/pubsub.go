package state

// subscriber holds one consumer's delivery channel + the unsubscribe
// closure. Channels are buffered (Options.SubscriberBuffer) so a slow
// reader doesn't block the writer goroutine. When the buffer would
// overflow, we close the channel — the reader detects the close and
// reconnects via SSE.
type subscriber struct {
	ch chan Event
}

// Subscribe returns a channel of events plus an unsubscribe func the
// caller MUST call (typically via defer) when done. The channel is
// buffered; on overflow it closes — the caller's range loop ends,
// signaling "you fell behind, reconnect."
//
// Used by the HTTP server's /api/events SSE handler: each connected
// browser tab subscribes, the handler forwards events as text/event-
// stream frames until the request context cancels (tab close, ctx
// cancel from daemon shutdown, etc.).
func (s *Store) Subscribe() (<-chan Event, func()) {
	sub := &subscriber{ch: make(chan Event, s.opts.SubscriberBuffer)}
	s.subsMu.Lock()
	s.subs[sub] = struct{}{}
	s.subsMu.Unlock()

	unsub := func() {
		s.subsMu.Lock()
		if _, ok := s.subs[sub]; ok {
			delete(s.subs, sub)
			close(sub.ch)
		}
		s.subsMu.Unlock()
	}
	return sub.ch, unsub
}

// publish fans an event out to every current subscriber, non-blocking.
// If a subscriber's channel is full (consumer fell behind), we drop
// the subscription rather than block — the consumer's SSE retry will
// reconnect them.
//
// Note: publish runs under the writer goroutine (after commit). It must
// stay fast — no I/O, no allocations beyond the slice copy.
func (s *Store) publish(e Event) {
	s.subsMu.RLock()
	// Copy the subscriber list so we don't hold the lock during channel
	// sends. The send is non-blocking; on full channel we'll close +
	// remove the subscriber in a second pass under the write lock.
	subs := make([]*subscriber, 0, len(s.subs))
	for sub := range s.subs {
		subs = append(subs, sub)
	}
	s.subsMu.RUnlock()

	var slow []*subscriber
	for _, sub := range subs {
		select {
		case sub.ch <- e:
		default:
			slow = append(slow, sub)
		}
	}
	if len(slow) > 0 {
		s.subsMu.Lock()
		for _, sub := range slow {
			if _, ok := s.subs[sub]; ok {
				delete(s.subs, sub)
				close(sub.ch)
			}
		}
		s.subsMu.Unlock()
	}
}
