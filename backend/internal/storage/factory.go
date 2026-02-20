// factory.go implements the storage backend registry and factory, mapping backend type
// strings (local, s3, azure, gcs) to constructor functions and dispatching NewStorage calls.
package storage

import (
	"fmt"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Factory function type for creating storage backends
type FactoryFunc func(*config.Config) (Storage, error)

var factories = make(map[string]FactoryFunc)

// Register registers a storage backend factory
func Register(name string, factory FactoryFunc) {
	factories[name] = factory
}

// NewStorage creates a new storage backend based on configuration
func NewStorage(cfg *config.Config) (Storage, error) {
	factory, ok := factories[cfg.Storage.DefaultBackend]
	if !ok {
		return nil, fmt.Errorf("unsupported storage backend: %s (must be 'local', 'azure', 's3', or 'gcs')", cfg.Storage.DefaultBackend)
	}

	return factory(cfg)
}
