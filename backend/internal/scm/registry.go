// registry.go implements ConnectorRegistry, which stores and retrieves SCM connector
// builder functions keyed by ProviderType for use during provider instantiation.
package scm

import (
	"fmt"
	"sync"
)

// ConnectorBuilder is a function that constructs a Connector
type ConnectorBuilder func(settings *ConnectorSettings) (Connector, error)

// ConnectorRegistry manages available SCM connector implementations
type ConnectorRegistry struct {
	mu       sync.RWMutex
	builders map[ProviderType]ConnectorBuilder
}

// NewConnectorRegistry creates an empty registry
func NewConnectorRegistry() *ConnectorRegistry {
	return &ConnectorRegistry{
		builders: make(map[ProviderType]ConnectorBuilder),
	}
}

// Register adds a connector builder for a provider kind
func (r *ConnectorRegistry) Register(kind ProviderType, builder ConnectorBuilder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.builders[kind] = builder
}

// Build creates a connector instance for the given settings
func (r *ConnectorRegistry) Build(settings *ConnectorSettings) (Connector, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}

	r.mu.RLock()
	builder, found := r.builders[settings.Kind]
	r.mu.RUnlock()

	if !found {
		return nil, fmt.Errorf("%w: %s", ErrConnectorUnavailable, settings.Kind)
	}

	return builder(settings)
}

// AvailableKinds returns all registered provider kinds
func (r *ConnectorRegistry) AvailableKinds() []ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]ProviderType, 0, len(r.builders))
	for k := range r.builders {
		kinds = append(kinds, k)
	}
	return kinds
}

// HasKind checks if a provider kind is registered
func (r *ConnectorRegistry) HasKind(kind ProviderType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, found := r.builders[kind]
	return found
}

// GlobalRegistry is the default connector registry
var GlobalRegistry = NewConnectorRegistry()

// RegisterConnector adds a builder to the global registry
func RegisterConnector(kind ProviderType, builder ConnectorBuilder) {
	GlobalRegistry.Register(kind, builder)
}

// BuildConnector creates a connector using the global registry
func BuildConnector(settings *ConnectorSettings) (Connector, error) {
	return GlobalRegistry.Build(settings)
}
