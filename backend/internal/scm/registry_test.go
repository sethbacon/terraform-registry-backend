package scm

import (
	"context"
	"errors"
	"io"
	"testing"
)

// mockConnector is a minimal Connector implementation for registry tests.
type mockConnector struct {
	kind ProviderKind
}

func (m *mockConnector) Platform() ProviderKind { return m.kind }
func (m *mockConnector) AuthorizationEndpoint(string, []string) string { return "" }
func (m *mockConnector) CompleteAuthorization(_ context.Context, _ string) (*AccessToken, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) RenewToken(_ context.Context, _ string) (*AccessToken, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) FetchRepositories(_ context.Context, _ *AccessToken, _ Pagination) (*RepoListResult, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) FetchRepository(_ context.Context, _ *AccessToken, _, _ string) (*SourceRepo, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) SearchRepositories(_ context.Context, _ *AccessToken, _ string, _ Pagination) (*RepoListResult, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) FetchBranches(_ context.Context, _ *AccessToken, _, _ string, _ Pagination) ([]*GitBranch, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) FetchTags(_ context.Context, _ *AccessToken, _, _ string, _ Pagination) ([]*GitTag, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) FetchTagByName(_ context.Context, _ *AccessToken, _, _, _ string) (*GitTag, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) FetchCommit(_ context.Context, _ *AccessToken, _, _, _ string) (*GitCommit, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) DownloadSourceArchive(_ context.Context, _ *AccessToken, _, _, _ string, _ ArchiveKind) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) RegisterWebhook(_ context.Context, _ *AccessToken, _, _ string, _ WebhookSetup) (*WebhookInfo, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) RemoveWebhook(_ context.Context, _ *AccessToken, _, _, _ string) error {
	return errors.New("not implemented")
}
func (m *mockConnector) ParseDelivery(_ []byte, _ map[string]string) (*IncomingHook, error) {
	return nil, errors.New("not implemented")
}
func (m *mockConnector) VerifyDeliverySignature(_ []byte, _, _ string) bool { return false }

// ---------------------------------------------------------------------------
// ConnectorRegistry tests
// ---------------------------------------------------------------------------

func TestNewConnectorRegistry(t *testing.T) {
	r := NewConnectorRegistry()
	if r == nil {
		t.Fatal("NewConnectorRegistry() returned nil")
	}
	if len(r.AvailableKinds()) != 0 {
		t.Errorf("new registry should have 0 registered kinds, got %d", len(r.AvailableKinds()))
	}
}

func TestConnectorRegistryRegisterAndHasKind(t *testing.T) {
	r := NewConnectorRegistry()

	r.Register(ProviderGitHub, func(s *ConnectorSettings) (Connector, error) {
		return &mockConnector{kind: s.Kind}, nil
	})

	if !r.HasKind(ProviderGitHub) {
		t.Error("HasKind(ProviderGitHub) = false after Register, want true")
	}
	if r.HasKind(ProviderGitLab) {
		t.Error("HasKind(ProviderGitLab) = true, want false (never registered)")
	}
}

func TestConnectorRegistryAvailableKinds(t *testing.T) {
	r := NewConnectorRegistry()
	r.Register(ProviderGitHub, func(_ *ConnectorSettings) (Connector, error) {
		return &mockConnector{}, nil
	})
	r.Register(ProviderAzureDevOps, func(_ *ConnectorSettings) (Connector, error) {
		return &mockConnector{}, nil
	})

	kinds := r.AvailableKinds()
	if len(kinds) != 2 {
		t.Errorf("AvailableKinds() len = %d, want 2", len(kinds))
	}
}

func TestConnectorRegistryBuild(t *testing.T) {
	r := NewConnectorRegistry()
	r.Register(ProviderGitHub, func(s *ConnectorSettings) (Connector, error) {
		return &mockConnector{kind: s.Kind}, nil
	})

	validSettings := &ConnectorSettings{
		Kind:         ProviderGitHub,
		ClientID:     "id",
		ClientSecret: "secret",
		CallbackURL:  "https://example.com/callback",
	}

	t.Run("builds registered connector", func(t *testing.T) {
		c, err := r.Build(validSettings)
		if err != nil {
			t.Fatalf("Build() error: %v", err)
		}
		if c == nil {
			t.Fatal("Build() returned nil connector")
		}
		if c.Platform() != ProviderGitHub {
			t.Errorf("Platform() = %q, want %q", c.Platform(), ProviderGitHub)
		}
	})

	t.Run("unregistered kind returns error", func(t *testing.T) {
		s := *validSettings
		s.Kind = ProviderGitLab // not registered
		_, err := r.Build(&s)
		if err == nil {
			t.Error("Build() expected error for unregistered kind, got nil")
		}
		if !errors.Is(err, ErrConnectorUnavailable) {
			t.Errorf("Build() error = %v, want to wrap %v", err, ErrConnectorUnavailable)
		}
	})

	t.Run("invalid settings returns validation error", func(t *testing.T) {
		s := &ConnectorSettings{
			Kind:     ProviderGitHub,
			ClientID: "", // missing for OAuth provider
		}
		_, err := r.Build(s)
		if err == nil {
			t.Error("Build() expected error for invalid settings, got nil")
		}
	})

	t.Run("bitbucket DC (PAT) builds without OAuth fields", func(t *testing.T) {
		r2 := NewConnectorRegistry()
		r2.Register(ProviderBitbucketDC, func(s *ConnectorSettings) (Connector, error) {
			return &mockConnector{kind: s.Kind}, nil
		})
		s := &ConnectorSettings{
			Kind:            ProviderBitbucketDC,
			InstanceBaseURL: "https://bitbucket.corp.example.com",
		}
		c, err := r2.Build(s)
		if err != nil {
			t.Fatalf("Build() PAT provider error: %v", err)
		}
		if c.Platform() != ProviderBitbucketDC {
			t.Errorf("Platform() = %q, want %q", c.Platform(), ProviderBitbucketDC)
		}
	})
}

func TestConnectorRegistryRegisterOverwritesSameKind(t *testing.T) {
	r := NewConnectorRegistry()

	callCount := 0
	r.Register(ProviderGitHub, func(_ *ConnectorSettings) (Connector, error) {
		callCount++
		return &mockConnector{}, nil
	})
	r.Register(ProviderGitHub, func(_ *ConnectorSettings) (Connector, error) {
		callCount += 100
		return &mockConnector{}, nil
	})

	r.Build(&ConnectorSettings{
		Kind:         ProviderGitHub,
		ClientID:     "id",
		ClientSecret: "s",
		CallbackURL:  "https://x.com",
	})
	if callCount != 100 {
		t.Errorf("expected second builder to be used (callCount=100), got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// Global RegisterConnector / BuildConnector wrappers
// ---------------------------------------------------------------------------

func TestRegisterConnector_GlobalWrapper(t *testing.T) {
	// Register a builder in the global registry using a valid provider kind.
	// We use ProviderGitHub since it is always valid (passes Validate()).
	called := false
	RegisterConnector(ProviderGitHub, func(s *ConnectorSettings) (Connector, error) {
		called = true
		return &mockConnector{kind: s.Kind}, nil
	})

	if !GlobalRegistry.HasKind(ProviderGitHub) {
		t.Error("GlobalRegistry.HasKind(ProviderGitHub) = false after RegisterConnector")
	}

	settings := &ConnectorSettings{
		Kind:         ProviderGitHub,
		ClientID:     "id",
		ClientSecret: "secret",
		CallbackURL:  "https://example.com/callback",
	}
	c, err := BuildConnector(settings)
	if err != nil {
		t.Fatalf("BuildConnector() error: %v", err)
	}
	if c == nil {
		t.Fatal("BuildConnector() returned nil")
	}
	if !called {
		t.Error("builder was not called")
	}
}

func TestBuildConnector_InvalidSettings(t *testing.T) {
	// Settings with empty ClientID fail Validate() → ErrClientIDRequired
	settings := &ConnectorSettings{
		Kind:     ProviderGitHub,
		ClientID: "", // missing
	}
	_, err := BuildConnector(settings)
	if err == nil {
		t.Error("BuildConnector() = nil error, want error for invalid settings")
	}
}
