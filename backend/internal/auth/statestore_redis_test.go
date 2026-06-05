package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// newTestRedisStore starts an in-process miniredis and returns a RedisStateStore
// wired to it. The store and miniredis are cleaned up via t.Cleanup.
func newTestRedisStore(t *testing.T) (*RedisStateStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	port, err := strconv.Atoi(mr.Port())
	if err != nil {
		t.Fatalf("parse miniredis port: %v", err)
	}
	store, err := NewRedisStateStore(&config.RedisConfig{Host: mr.Host(), Port: port})
	if err != nil {
		t.Fatalf("NewRedisStateStore: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
		mr.Close()
	})
	return store, mr
}

func TestRedisStateStore_SaveLoadSingleUse(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	in := &SessionState{
		State:        "abc",
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
		RedirectURL:  "/dashboard",
		ProviderType: "oidc",
	}
	if err := store.Save(ctx, "abc", in, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Load(ctx, "abc")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil for a saved state")
	}
	if got.RedirectURL != "/dashboard" || got.ProviderType != "oidc" || got.State != "abc" {
		t.Errorf("Load mismatch: %+v", got)
	}

	// Load is single-use (atomic get+delete): a second Load must return nil.
	again, err := store.Load(ctx, "abc")
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if again != nil {
		t.Errorf("expected nil on second Load (single-use), got %+v", again)
	}
}

func TestRedisStateStore_LoadNonExistent(t *testing.T) {
	store, _ := newTestRedisStore(t)
	got, err := store.Load(context.Background(), "missing")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for a missing key, got %+v", got)
	}
}

func TestRedisStateStore_Delete(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	if err := store.Save(ctx, "d1", &SessionState{State: "d1"}, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Delete(ctx, "d1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := store.Load(ctx, "d1")
	if err != nil {
		t.Fatalf("Load after delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after Delete, got %+v", got)
	}

	// Deleting a non-existent key is a no-op (no error).
	if err := store.Delete(ctx, "never-existed"); err != nil {
		t.Errorf("Delete of missing key should be a no-op, got: %v", err)
	}
}

func TestRedisStateStore_SaveTTLExpiry(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()

	if err := store.Save(ctx, "ttl", &SessionState{State: "ttl"}, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Advance miniredis' clock past the TTL; the entry should be gone.
	mr.FastForward(2 * time.Minute)

	got, err := store.Load(ctx, "ttl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after TTL expiry, got %+v", got)
	}
}

func TestNewRedisStateStore_ConnectionError(t *testing.T) {
	// Point at a port with nothing listening; the constructor's Ping must fail.
	_, err := NewRedisStateStore(&config.RedisConfig{
		Host:        "127.0.0.1",
		Port:        1, // unused, refused
		DialTimeout: time.Second,
	})
	if err == nil {
		t.Error("expected a connection error from NewRedisStateStore")
	}
}
