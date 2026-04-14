package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// stateKeyPrefix is prepended to state tokens to namespace them in Redis.
const stateKeyPrefix = "oidc_state:"

// RedisStateStore implements StateStore using Redis. Session state is stored
// with a TTL via SET EX, and Load + Delete are executed atomically using a
// Lua script to guarantee single-use semantics.
type RedisStateStore struct {
	client *redis.Client
}

// NewRedisStateStore creates a Redis-backed state store.
// coverage:skip:requires-redis-connection
func NewRedisStateStore(cfg *config.RedisConfig) (*RedisStateStore, error) {
	opts := &redis.Options{
		Addr:        fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:    cfg.Password,
		DB:          cfg.DB,
		PoolSize:    cfg.PoolSize,
		DialTimeout: cfg.DialTimeout,
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis state store: failed to connect: %w", err)
	}

	slog.Info("redis OIDC state store initialized", "addr", opts.Addr)

	return &RedisStateStore{client: client}, nil
}

// Save stores session state as JSON in Redis with the given TTL.
// coverage:skip:requires-redis-connection
func (s *RedisStateStore) Save(ctx context.Context, state string, data *SessionState, ttl time.Duration) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis state store: marshal error: %w", err)
	}
	return s.client.Set(ctx, stateKeyPrefix+state, payload, ttl).Err()
}

// getAndDeleteScript atomically fetches and deletes a key (single-use guarantee).
var getAndDeleteScript = redis.NewScript(`
local val = redis.call("GET", KEYS[1])
if val then
	redis.call("DEL", KEYS[1])
end
return val
`)

// Load retrieves and atomically deletes the session state (single-use token).
// Returns nil, nil when the key does not exist.
// coverage:skip:requires-redis-connection
func (s *RedisStateStore) Load(ctx context.Context, state string) (*SessionState, error) {
	key := stateKeyPrefix + state
	result, err := getAndDeleteScript.Run(ctx, s.client, []string{key}).Result()
	if err == redis.Nil || result == nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis state store: load error: %w", err)
	}

	var data SessionState
	if err := json.Unmarshal([]byte(result.(string)), &data); err != nil {
		return nil, fmt.Errorf("redis state store: unmarshal error: %w", err)
	}
	return &data, nil
}

// Delete removes a session state entry from Redis.
// coverage:skip:requires-redis-connection
func (s *RedisStateStore) Delete(ctx context.Context, state string) error {
	return s.client.Del(ctx, stateKeyPrefix+state).Err()
}

// Close shuts down the Redis connection.
// coverage:skip:requires-redis-connection
func (s *RedisStateStore) Close() error {
	return s.client.Close()
}
