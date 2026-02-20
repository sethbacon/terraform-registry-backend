package scm

import (
	"context"
	"errors"
	"io"
	"testing"
)

// mockProvider is a minimal Provider implementation for factory tests.
type mockProvider struct {
	kind ProviderType
}

func (m *mockProvider) GetType() ProviderType { return m.kind }
func (m *mockProvider) GetAuthorizationURL(string, []string) string { return "" }
func (m *mockProvider) ExchangeCode(_ context.Context, _ string) (*OAuthToken, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) RefreshToken(_ context.Context, _ string) (*OAuthToken, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) ListRepositories(_ context.Context, _ *OAuthToken, _ *ListOptions) (*RepositoryList, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) GetRepository(_ context.Context, _ *OAuthToken, _, _ string) (*Repository, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) SearchRepositories(_ context.Context, _ *OAuthToken, _ string, _ *ListOptions) (*RepositoryList, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) ListBranches(_ context.Context, _ *OAuthToken, _, _ string, _ *ListOptions) ([]*Branch, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) GetBranch(_ context.Context, _ *OAuthToken, _, _, _ string) (*Branch, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) ListTags(_ context.Context, _ *OAuthToken, _, _ string, _ *ListOptions) ([]*Tag, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) GetTag(_ context.Context, _ *OAuthToken, _, _, _ string) (*Tag, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) GetCommit(_ context.Context, _ *OAuthToken, _, _, _ string) (*Commit, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) DownloadArchive(_ context.Context, _ *OAuthToken, _, _, _ string, _ ArchiveFormat) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) CreateWebhook(_ context.Context, _ *OAuthToken, _, _ string, _ *WebhookConfig) (*Webhook, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) UpdateWebhook(_ context.Context, _ *OAuthToken, _, _, _ string, _ *WebhookConfig) (*Webhook, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) DeleteWebhook(_ context.Context, _ *OAuthToken, _, _, _ string) error {
	return errors.New("not implemented")
}
func (m *mockProvider) ListWebhooks(_ context.Context, _ *OAuthToken, _, _ string) ([]*Webhook, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) ParseWebhookEvent(_ []byte, _ map[string]string) (*WebhookEvent, error) {
	return nil, errors.New("not implemented")
}
func (m *mockProvider) ValidateWebhookSignature(_ []byte, _, _ string) bool { return false }

// ---------------------------------------------------------------------------
// ProviderFactory tests
// ---------------------------------------------------------------------------

func TestNewProviderFactory(t *testing.T) {
	f := NewProviderFactory()
	if f == nil {
		t.Fatal("NewProviderFactory() returned nil")
	}
	if len(f.SupportedTypes()) != 0 {
		t.Errorf("new factory should have 0 registered types, got %d", len(f.SupportedTypes()))
	}
}

func TestProviderFactoryRegisterAndIsSupported(t *testing.T) {
	f := NewProviderFactory()

	f.Register(ProviderGitHub, func(cfg *ProviderConfig) (Provider, error) {
		return &mockProvider{kind: ProviderGitHub}, nil
	})

	if !f.IsSupported(ProviderGitHub) {
		t.Error("IsSupported(ProviderGitHub) = false after Register, want true")
	}
	if f.IsSupported(ProviderGitLab) {
		t.Error("IsSupported(ProviderGitLab) = true, want false (never registered)")
	}
}

func TestProviderFactorySupportedTypes(t *testing.T) {
	f := NewProviderFactory()
	f.Register(ProviderGitHub, func(_ *ProviderConfig) (Provider, error) {
		return &mockProvider{}, nil
	})
	f.Register(ProviderGitLab, func(_ *ProviderConfig) (Provider, error) {
		return &mockProvider{}, nil
	})

	types := f.SupportedTypes()
	if len(types) != 2 {
		t.Errorf("SupportedTypes() len = %d, want 2", len(types))
	}
}

func TestProviderFactoryCreate(t *testing.T) {
	f := NewProviderFactory()
	f.Register(ProviderGitHub, func(cfg *ProviderConfig) (Provider, error) {
		return &mockProvider{kind: cfg.Type}, nil
	})

	validCfg := &ProviderConfig{
		Type:         ProviderGitHub,
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://example.com/cb",
	}

	t.Run("creates registered provider", func(t *testing.T) {
		p, err := f.Create(validCfg)
		if err != nil {
			t.Fatalf("Create() error: %v", err)
		}
		if p == nil {
			t.Fatal("Create() returned nil provider")
		}
	})

	t.Run("unsupported type returns error", func(t *testing.T) {
		cfg := *validCfg
		cfg.Type = ProviderGitLab // not registered
		_, err := f.Create(&cfg)
		if err == nil {
			t.Error("Create() expected error for unregistered type, got nil")
		}
		if !errors.Is(err, ErrProviderNotSupported) {
			t.Errorf("Create() error = %v, want to wrap %v", err, ErrProviderNotSupported)
		}
	})

	t.Run("invalid config returns validation error", func(t *testing.T) {
		cfg := &ProviderConfig{
			Type:     ProviderGitHub,
			ClientID: "", // missing
		}
		_, err := f.Create(cfg)
		if err == nil {
			t.Error("Create() expected error for invalid config, got nil")
		}
	})
}

// TestGlobalFactory tests the package-level RegisterProvider and CreateProvider
// functions that delegate to DefaultFactory.
func TestGlobalFactoryRegisterAndCreate(t *testing.T) {
	// Register a provider type in DefaultFactory.
	RegisterProvider(ProviderGitHub, func(cfg *ProviderConfig) (Provider, error) {
		return &mockProvider{kind: ProviderGitHub}, nil
	})

	cfg := &ProviderConfig{
		Type:         ProviderGitHub,
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://example.com/cb",
	}
	p, err := CreateProvider(cfg)
	if err != nil {
		t.Fatalf("CreateProvider() error: %v", err)
	}
	if p == nil {
		t.Fatal("CreateProvider() returned nil provider")
	}
}

func TestProviderFactoryRegisterOverwritesSameType(t *testing.T) {
	f := NewProviderFactory()

	callCount := 0
	f.Register(ProviderGitHub, func(_ *ProviderConfig) (Provider, error) {
		callCount++
		return &mockProvider{kind: ProviderGitHub}, nil
	})
	// Re-register same type with a new creator
	f.Register(ProviderGitHub, func(_ *ProviderConfig) (Provider, error) {
		callCount += 100
		return &mockProvider{kind: ProviderGitHub}, nil
	})

	cfg := &ProviderConfig{
		Type:         ProviderGitHub,
		ClientID:     "id",
		ClientSecret: "s",
		RedirectURL:  "https://x.com",
	}
	f.Create(cfg)
	if callCount != 100 {
		t.Errorf("expected second creator to be called (callCount=100), got %d", callCount)
	}
}
