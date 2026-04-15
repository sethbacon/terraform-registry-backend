// Package auth provides authentication primitives (JWT, API keys) and the
// StateStore interface for OIDC session state management.
package auth

import (
	"context"
	"time"
)

// SessionState represents OAuth state during the authentication flow.
// It is stored temporarily between the login redirect and the callback.
type SessionState struct {
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"created_at"`
	RedirectURL  string    `json:"redirect_url"`
	ProviderType string    `json:"provider_type"` // "oidc" or "azuread"
}

// StateStore is the interface for OIDC session state persistence.
// Implementations must be safe for concurrent use.
type StateStore interface {
	// Save persists a session state with the given TTL. After the TTL expires
	// the entry should be automatically removed.
	Save(ctx context.Context, state string, data *SessionState, ttl time.Duration) error
	// Load retrieves a previously saved session state. Returns nil, nil when
	// the key does not exist (expired or never saved).
	Load(ctx context.Context, state string) (*SessionState, error)
	// Delete removes a session state entry. Implementations should treat
	// deleting a non-existent key as a no-op.
	Delete(ctx context.Context, state string) error
	// Close releases resources held by the store (stop goroutines, close connections).
	Close() error
}
