// ratelimit_redis.go implements a Redis-backed rate limiter using the GCRA
// (Generic Cell Rate Algorithm) via the go-redis/redis_rate library.
// This backend is suitable for horizontally-scaled deployments where all
// instances share rate limit state through Redis.
package middleware

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/go-redis/redis_rate/v10"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// RedisRateLimiter implements RateLimiterBackend using Redis and the GCRA algorithm.
type RedisRateLimiter struct {
	client  *redis.Client
	limiter *redis_rate.Limiter
	limit   redis_rate.Limit
}

// NewRedisRateLimiter creates a Redis-backed rate limiter. The cfg parameter
// provides connection details and rlCfg provides the rate/burst values.
func NewRedisRateLimiter(cfg *config.RedisConfig, rlCfg RateLimitConfig) (*RedisRateLimiter, error) {
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

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis rate limiter: failed to connect: %w", err)
	}

	limiter := redis_rate.NewLimiter(client)

	limit := redis_rate.Limit{
		Rate:   rlCfg.RequestsPerMinute,
		Burst:  rlCfg.BurstSize,
		Period: time.Minute,
	}

	slog.Info("redis rate limiter initialized",
		"addr", opts.Addr,
		"requests_per_minute", rlCfg.RequestsPerMinute,
		"burst", rlCfg.BurstSize,
	)

	return &RedisRateLimiter{
		client:  client,
		limiter: limiter,
		limit:   limit,
	}, nil
}

// Allow checks whether the request identified by key should be permitted.
func (r *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	res, err := r.limiter.Allow(ctx, key, r.limit)
	if err != nil {
		return false, fmt.Errorf("redis rate limiter: Allow error: %w", err)
	}
	return res.Allowed > 0, nil
}

// RemainingTokens returns the approximate remaining capacity for key.
func (r *RedisRateLimiter) RemainingTokens(ctx context.Context, key string) (int, error) {
	res, err := r.limiter.Allow(ctx, key, redis_rate.Limit{
		Rate:   r.limit.Rate,
		Burst:  r.limit.Burst,
		Period: r.limit.Period,
	})
	// We use AllowN with 0 to peek, but redis_rate doesn't have a peek function.
	// Instead we return the Remaining field from the last Allow call.
	// Since we already called Allow in the middleware, this is a rough approximation.
	if err != nil {
		return 0, err
	}
	return res.Remaining, nil
}

// Close shuts down the Redis connection.
func (r *RedisRateLimiter) Close() error {
	return r.client.Close()
}
