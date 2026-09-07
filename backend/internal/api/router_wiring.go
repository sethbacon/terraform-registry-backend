package api

import (
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// Wiring phases lifted out of NewRouter (issue #565 finding [39]), which mixed
// dependency construction, key material, job orchestration and ~150 route
// registrations in one function. Route registration already moved to
// router_routes.go and the persisted-config reloads to router_startup.go; this
// file holds the two remaining blocks that construct something self-contained
// from configuration alone, so each can be read -- and changed -- without
// reading the startup order around it.

// encryptionKeys is the ENCRYPTION_KEY material, already validated. It carries
// the raw strings as well as knowing how to build a cipher because two
// different ciphers are built from the same pair: registry's own
// crypto.TokenCipher, and the shared identity one via buildIdentityTokenCipher.
type encryptionKeys struct {
	current  string
	previous string
}

// encryptionKeysFromEnv reads and validates the key material, or refuses to
// start. It does not return an error: every failure here is a configuration
// fault that must stop the process, and NewRouter's callers cannot do anything
// useful with one.
func encryptionKeysFromEnv() encryptionKeys {
	current := os.Getenv("ENCRYPTION_KEY")
	if current == "" {
		log.Fatal("ENCRYPTION_KEY environment variable must be set for SCM integration")
	}
	// ENCRYPTION_KEY is used directly as raw AES-256 key bytes (no KDF/hashing), so its
	// real-world entropy determines the actual strength of the cipher. Fail closed by
	// default when the key looks human-typed rather than CSPRNG-generated (issue #560):
	// this key encrypts every stored OAuth/SCM token suite-wide, and warning without
	// enforcing left every installation free to run indefinitely on a guessable key.
	// TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY provides a migration-safe bridge so an
	// existing deployment can restart once to rotate its key instead of being unable
	// to start at all.
	if shouldRejectLowEntropyEncryptionKey([]byte(current), allowLowEntropyEncryptionKey()) {
		log.Fatal("ENCRYPTION_KEY has low estimated entropy and may not have been generated with a CSPRNG. Refusing to start (issue #560). Generate one with: openssl rand -base64 32. Set TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY=true to start once and rotate.")
	}
	if crypto.IsLikelyLowEntropySecret([]byte(current)) {
		log.Printf("WARNING: ENCRYPTION_KEY has low estimated entropy and may not have been generated with a CSPRNG. Generate one with: openssl rand -base64 32")
	}
	return encryptionKeys{current: current, previous: os.Getenv("ENCRYPTION_KEY_PREVIOUS")}
}

// newTokenCipher builds registry's own token cipher. When
// ENCRYPTION_KEY_PREVIOUS is set the cipher supports dual-key decryption for
// zero-downtime key rotation.
func (k encryptionKeys) newTokenCipher() *crypto.TokenCipher {
	if k.previous != "" {
		cipher, err := crypto.NewTokenCipherWithPrevious([]byte(k.current), []byte(k.previous))
		if err != nil {
			log.Fatalf("Failed to initialize dual-key token cipher: %v", err)
		}
		slog.Info("token cipher initialized with previous key for rotation support")
		return cipher
	}
	cipher, err := crypto.NewTokenCipher([]byte(k.current))
	if err != nil {
		log.Fatalf("Failed to initialize token cipher: %v", err)
	}
	return cipher
}

// rateLimiters is the set of backends route registration selects between. Each
// is nil when rate limiting is disabled, which the middleware treats as "no
// limit" -- so the zero value is the disabled configuration rather than a bug.
type rateLimiters struct {
	auth     middleware.RateLimiterBackend
	general  middleware.RateLimiterBackend
	upload   middleware.RateLimiterBackend
	protocol middleware.RateLimiterBackend
	org      middleware.RateLimiterBackend
}

// newRateLimiters constructs them ahead of route registration, because the
// route groups take a backend rather than building their own. A Redis failure
// falls back to the in-memory backend and says so, rather than starting with no
// limit at all.
func newRateLimiters(cfg *config.Config) rateLimiters {
	var r rateLimiters
	if !cfg.Security.RateLimiting.Enabled {
		return r
	}

	generalCfg := middleware.DefaultRateLimitConfig()
	if cfg.Security.RateLimiting.RequestsPerMinute > 0 {
		generalCfg.RequestsPerMinute = cfg.Security.RateLimiting.RequestsPerMinute
	}
	if cfg.Security.RateLimiting.Burst > 0 {
		generalCfg.BurstSize = cfg.Security.RateLimiting.Burst
	}
	authCfg := middleware.AuthRateLimitConfig()
	uploadCfg := middleware.UploadRateLimitConfig()
	protocolCfg := middleware.ProtocolRateLimitConfig()

	orgCfg, orgWanted := orgRateLimitConfig(cfg)

	if cfg.Redis.Host == "" {
		slog.Warn("redis.host not configured: rate limiting will use in-memory backend (not suitable for multi-pod HA)")
		r.general = middleware.NewRateLimiter(generalCfg)
		r.auth = middleware.NewRateLimiter(authCfg)
		r.upload = middleware.NewRateLimiter(uploadCfg)
		r.protocol = middleware.NewRateLimiter(protocolCfg)
		if orgWanted {
			r.org = middleware.NewRateLimiter(orgCfg)
		}
		return r
	}

	r.general = redisLimiterOrMemory(cfg, generalCfg, "general")
	r.auth = redisLimiterOrMemory(cfg, authCfg, "auth")
	r.upload = redisLimiterOrMemory(cfg, uploadCfg, "upload")
	r.protocol = redisLimiterOrMemory(cfg, protocolCfg, "protocol routes")
	if orgWanted {
		r.org = redisLimiterOrMemory(cfg, orgCfg, "org")
	}
	log.Println("Rate limiting enabled with Redis backend")
	return r
}

// orgRateLimitConfig reports the per-organization limit and whether one is
// configured at all. The burst default was duplicated in both backend branches.
func orgRateLimitConfig(cfg *config.Config) (middleware.RateLimitConfig, bool) {
	if cfg.Security.RateLimiting.OrgRequestsPerMinute <= 0 {
		return middleware.RateLimitConfig{}, false
	}
	orgCfg := middleware.RateLimitConfig{
		RequestsPerMinute: cfg.Security.RateLimiting.OrgRequestsPerMinute,
		BurstSize:         cfg.Security.RateLimiting.OrgBurst,
		CleanupInterval:   5 * time.Minute,
	}
	if orgCfg.BurstSize == 0 {
		orgCfg.BurstSize = orgCfg.RequestsPerMinute / 4
	}
	return orgCfg, true
}

// redisLimiterOrMemory keeps the fallback identical for every limiter: the
// five call sites above each repeated the same warn-and-degrade block, which is
// exactly where one of them would eventually be left silently returning nil.
func redisLimiterOrMemory(cfg *config.Config, limitCfg middleware.RateLimitConfig, name string) middleware.RateLimiterBackend {
	backend, err := middleware.NewRedisRateLimiter(&cfg.Redis, limitCfg)
	if err != nil {
		slog.Warn("failed to create Redis rate limiter, falling back to in-memory", "limiter", name, "error", err)
		return middleware.NewRateLimiter(limitCfg)
	}
	return backend
}
