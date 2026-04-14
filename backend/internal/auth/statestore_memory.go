package auth

import (
	"context"
	"sync"
	"time"
)

// MemoryStateStore implements StateStore using an in-process map.
// Suitable for single-instance deployments only — state is not shared
// across pods. For multi-pod HA deployments use RedisStateStore.
type MemoryStateStore struct {
	mu      sync.Mutex
	entries map[string]*memoryEntry
	stopCh  chan struct{}
}

type memoryEntry struct {
	data      *SessionState
	expiresAt time.Time
}

// NewMemoryStateStore creates a new in-memory state store and starts a
// background goroutine that removes expired entries every cleanupInterval.
func NewMemoryStateStore(cleanupInterval time.Duration) *MemoryStateStore {
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}
	s := &MemoryStateStore{
		entries: make(map[string]*memoryEntry),
		stopCh:  make(chan struct{}),
	}
	go s.cleanup(cleanupInterval)
	return s
}

func (s *MemoryStateStore) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, e := range s.entries {
				if now.After(e.expiresAt) {
					delete(s.entries, k)
				}
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

// Save stores a session state with a TTL.
func (s *MemoryStateStore) Save(_ context.Context, state string, data *SessionState, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[state] = &memoryEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// Load retrieves and returns a session state. Returns nil, nil if not found or expired.
func (s *MemoryStateStore) Load(_ context.Context, state string) (*SessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[state]
	if !ok {
		return nil, nil
	}
	if time.Now().After(e.expiresAt) {
		delete(s.entries, state)
		return nil, nil
	}
	return e.data, nil
}

// Delete removes a session state entry.
func (s *MemoryStateStore) Delete(_ context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, state)
	return nil
}

// Close stops the cleanup goroutine.
func (s *MemoryStateStore) Close() error {
	close(s.stopCh)
	return nil
}
