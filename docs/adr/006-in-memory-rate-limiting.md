# 6. In-Memory Rate Limiting

**Status**: Superseded by Redis-backed rate limiting (Phase 1.1)

## Context

The registry needs rate limiting to protect against abuse, brute-force attacks on authentication endpoints, and resource exhaustion from misbehaving clients. Three tiers exist:

1. **Auth endpoints** (10 req/min): Login, token exchange -- protects against credential stuffing.
2. **Upload endpoints** (30 req/min): Module/provider publishing -- protects storage backend.
3. **General API** (200 req/min): All other endpoints -- protects database and compute.

The initial implementation in `internal/middleware/ratelimit.go` uses an in-process token bucket algorithm. Each `MemoryRateLimiter` instance maintains a `sync.Map` of per-client token buckets, with a background goroutine cleaning up expired entries. The rate limit key is derived from `user_id` (JWT), `api_key_id`, or `client_ip` in that priority order.

The code itself documents the limitation at the top of `ratelimit.go`: "This is not suitable for horizontally scaled deployments -- each instance maintains independent state, allowing clients to exceed limits by rotating across pods."

## Decision

Initially implement rate limiting using in-memory token buckets:

- **`MemoryRateLimiter`** implements the `RateLimiterBackend` interface with `Allow()`, `RemainingTokens()`, and `Close()` methods.
- Token buckets refill at `RequestsPerMinute / 60` tokens per second, with a maximum burst of `BurstSize`.
- A cleanup goroutine runs every `CleanupInterval` (default 5 minutes) to remove stale entries.
- Three preset configurations (`DefaultRateLimitConfig`, `AuthRateLimitConfig`, `UploadRateLimitConfig`) define the tiers.
- Per-organization rate limiting adds a second check using `org:<orgID>` as the bucket key.

This was chosen as the initial implementation because:
1. Zero external dependencies -- no Redis required for simple deployments.
2. Correct behavior for single-instance deployments.
3. The `RateLimiterBackend` interface was designed from the start to allow swapping in a Redis backend later.

## Consequences

**Easier**:
- No Redis dependency for development or single-instance production deployments.
- Sub-microsecond rate limit checks (no network round-trip).
- Simple operational model -- no additional infrastructure to manage.

**Harder**:
- Rate limits are per-pod, not global. A client can multiply their effective limit by the number of backend replicas.
- No shared state across pods -- cannot enforce organization-level limits accurately in multi-pod deployments.
- The Redis-backed implementation (`RedisRateLimiter` in `ratelimit_redis.go`) was added in Phase 1.1 to address these limitations, using the GCRA algorithm via `go-redis/redis_rate`.
- The factory in `router.go` now selects the backend based on `cfg.Redis.Host`: Redis when available, in-memory as fallback with a startup warning log.
