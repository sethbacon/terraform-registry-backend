package auth

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestMemoryStateStore_ImplementsInterface(t *testing.T) {
	var _ StateStore = (*MemoryStateStore)(nil)
}

// ---------------------------------------------------------------------------
// MemoryStateStore
// ---------------------------------------------------------------------------

func TestMemoryStateStore_SaveAndLoad(t *testing.T) {
	store := NewMemoryStateStore(time.Hour)
	defer store.Close()
	ctx := context.Background()

	data := &SessionState{
		State:        "abc123",
		CreatedAt:    time.Now(),
		ProviderType: "oidc",
	}

	if err := store.Save(ctx, "abc123", data, 10*time.Minute); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := store.Load(ctx, "abc123")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() returned nil, want non-nil")
	}
	if loaded.State != "abc123" {
		t.Errorf("Load().State = %q, want %q", loaded.State, "abc123")
	}
	if loaded.ProviderType != "oidc" {
		t.Errorf("Load().ProviderType = %q, want %q", loaded.ProviderType, "oidc")
	}
}

func TestMemoryStateStore_LoadNonExistent(t *testing.T) {
	store := NewMemoryStateStore(time.Hour)
	defer store.Close()

	loaded, err := store.Load(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded != nil {
		t.Errorf("Load() = %v, want nil for non-existent key", loaded)
	}
}

func TestMemoryStateStore_Delete(t *testing.T) {
	store := NewMemoryStateStore(time.Hour)
	defer store.Close()
	ctx := context.Background()

	data := &SessionState{State: "del-test", ProviderType: "azuread"}
	store.Save(ctx, "del-test", data, 10*time.Minute)

	if err := store.Delete(ctx, "del-test"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	loaded, _ := store.Load(ctx, "del-test")
	if loaded != nil {
		t.Error("Load() returned non-nil after Delete()")
	}
}

func TestMemoryStateStore_DeleteNonExistent(t *testing.T) {
	store := NewMemoryStateStore(time.Hour)
	defer store.Close()

	// Should not error
	if err := store.Delete(context.Background(), "no-such-key"); err != nil {
		t.Errorf("Delete() error: %v", err)
	}
}

func TestMemoryStateStore_TTLExpiry(t *testing.T) {
	store := NewMemoryStateStore(time.Hour)
	defer store.Close()
	ctx := context.Background()

	data := &SessionState{State: "expire-test", ProviderType: "oidc"}
	// Use very short TTL
	store.Save(ctx, "expire-test", data, 1*time.Millisecond)

	time.Sleep(10 * time.Millisecond)

	loaded, err := store.Load(ctx, "expire-test")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded != nil {
		t.Error("Load() returned non-nil after TTL expiry")
	}
}

func TestMemoryStateStore_CleanupRemovesExpired(t *testing.T) {
	store := NewMemoryStateStore(10 * time.Millisecond)
	defer store.Close()
	ctx := context.Background()

	data := &SessionState{State: "cleanup-test", ProviderType: "oidc"}
	store.Save(ctx, "cleanup-test", data, 1*time.Millisecond)

	// Wait for cleanup to run
	time.Sleep(50 * time.Millisecond)

	store.mu.Lock()
	_, found := store.entries["cleanup-test"]
	store.mu.Unlock()

	if found {
		t.Error("expired entry still present after cleanup")
	}
}

func TestMemoryStateStore_DefaultCleanupInterval(t *testing.T) {
	// Zero interval should default to 5 minutes internally
	store := NewMemoryStateStore(0)
	defer store.Close()
	ctx := context.Background()

	data := &SessionState{State: "default-test", ProviderType: "oidc", CreatedAt: time.Now()}
	if err := store.Save(ctx, "default-test", data, time.Hour); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := store.Load(ctx, "default-test")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() returned nil, want non-nil")
	}
	if loaded.State != "default-test" {
		t.Errorf("Load().State = %q, want %q", loaded.State, "default-test")
	}
}

func TestMemoryStateStore_NegativeCleanupInterval(t *testing.T) {
	// Negative interval should also default to 5 minutes
	store := NewMemoryStateStore(-1 * time.Second)
	defer store.Close()
	ctx := context.Background()

	data := &SessionState{State: "neg-test", ProviderType: "azuread", CreatedAt: time.Now()}
	if err := store.Save(ctx, "neg-test", data, time.Hour); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := store.Load(ctx, "neg-test")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() returned nil, want non-nil")
	}
}
