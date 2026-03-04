// factory.go implements ProviderFactory, which maps SCM ProviderType values to registered
// constructor functions and instantiates the correct Provider implementation on demand.
package scm

import (
	"fmt"
	"sync"
)

// ProviderFactory creates SCM provider instances
type ProviderFactory struct {
	mu       sync.RWMutex
	creators map[ProviderType]ProviderCreator
}

// ProviderCreator is a function that creates a new Provider instance
type ProviderCreator func(config *ProviderConfig) (Provider, error)

// NewProviderFactory creates a new provider factory
func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{
		creators: make(map[ProviderType]ProviderCreator),
	}
}

// Register registers a provider creator for a given type
func (f *ProviderFactory) Register(providerType ProviderType, creator ProviderCreator) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creators[providerType] = creator
}

// Create creates a new provider instance
func (f *ProviderFactory) Create(config *ProviderConfig) (Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	f.mu.RLock()
	creator, ok := f.creators[config.Type]
	f.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotSupported, config.Type)
	}

	return creator(config)
}

// SupportedTypes returns a list of supported provider types
func (f *ProviderFactory) SupportedTypes() []ProviderType {
	f.mu.RLock()
	defer f.mu.RUnlock()

	types := make([]ProviderType, 0, len(f.creators))
	for t := range f.creators {
		types = append(types, t)
	}
	return types
}

// IsSupported checks if a provider type is supported
func (f *ProviderFactory) IsSupported(providerType ProviderType) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.creators[providerType]
	return ok
}

// DefaultFactory is the default provider factory with all providers registered
var DefaultFactory = NewProviderFactory()

// RegisterProvider registers a provider with the default factory
func RegisterProvider(providerType ProviderType, creator ProviderCreator) {
	DefaultFactory.Register(providerType, creator)
}

// CreateProvider creates a provider using the default factory
func CreateProvider(config *ProviderConfig) (Provider, error) {
	return DefaultFactory.Create(config)
}
