# ADR-0011: Password and API Key Hashing

**Status:** Accepted
**Date:** 2026-04-17
**Deciders:** @sethbacon

## Context

The registry hashes API keys (and the one-time setup token) before storing them in PostgreSQL. We need a hashing algorithm that is:

1. **Computationally expensive** — resists offline brute-force attacks if the database is compromised.
2. **Tunable** — cost can be increased over time as hardware improves.
3. **Widely audited** — no novel cryptography.
4. **Available in the Go standard library** — no third-party dependency.

## Decision

Use **bcrypt** (`golang.org/x/crypto/bcrypt`) with a cost factor of **12**.

### Why cost 12?

| Cost | ~Time per hash (2026 hardware) | Notes |
|------|-------------------------------|-------|
| 10   | ~70 ms                        | Go default; fast enough for brute-force at scale |
| 12   | ~290 ms                       | Good balance: tolerable for login/API-key-creation; expensive for attackers |
| 14   | ~1.2 s                        | Noticeable latency on every API key creation or setup token generation |

Cost 12 is the OWASP minimum recommendation (as of 2024). It imposes ~290 ms per hash on a single core, making offline attacks against a leaked database computationally expensive (~3,400 guesses/core/hour) while keeping user-facing latency acceptable.

### Hash upgrade path

When increasing the cost factor in the future:

1. Bump the `BcryptCost` constant in `internal/auth/apikey.go`.
2. On **next successful API key validation**, check if the stored hash uses the old cost via `bcrypt.Cost(hash)`. If it does, re-hash with the new cost and update the row. This is a transparent, zero-downtime migration.
3. The setup token is single-use and does not need re-hashing.

### Alternatives considered

| Algorithm | Verdict |
|-----------|---------|
| **Argon2id** | Stronger (memory-hard), but not in Go stdlib; would add a C dependency or pure-Go implementation with less audit history. Revisit if FIPS requirements mandate it. |
| **scrypt** | Memory-hard, available in `golang.org/x/crypto`. Viable alternative but less widely adopted in the Go ecosystem than bcrypt. |
| **PBKDF2** | FIPS-approved but CPU-only; weaker against GPU attacks at equivalent time cost. |

## Consequences

- API key hashing uses `bcrypt.GenerateFromPassword([]byte(key), 12)`.
- The `BcryptCost` constant is defined in `internal/auth/apikey.go` and must be used consistently (no hardcoded literals elsewhere).
- Cost can be increased in a future ADR without a database migration — the upgrade-on-verify pattern handles it transparently.
- If FIPS-140-3 compliance requires NIST-approved algorithms only, bcrypt is **not** FIPS-approved. The FIPS build variant (see ADR-0012) would need to switch to PBKDF2-SHA256 or Argon2 when a FIPS-validated implementation becomes available.
