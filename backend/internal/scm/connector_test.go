package scm

import (
	"testing"
)

// ---------------------------------------------------------------------------
// DefaultPagination
// ---------------------------------------------------------------------------

func TestDefaultPagination(t *testing.T) {
	p := DefaultPagination()
	if p.PageNum != 1 {
		t.Errorf("DefaultPagination().PageNum = %d, want 1", p.PageNum)
	}
	if p.PageSize != 30 {
		t.Errorf("DefaultPagination().PageSize = %d, want 30", p.PageSize)
	}
}

// ---------------------------------------------------------------------------
// ConnectorSettings.Validate
// ---------------------------------------------------------------------------

func TestConnectorSettingsValidate(t *testing.T) {
	validOAuth := ConnectorSettings{
		Kind:         ProviderGitHub,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		CallbackURL:  "https://example.com/callback",
	}

	t.Run("valid github (OAuth) settings", func(t *testing.T) {
		s := validOAuth
		if err := s.Validate(); err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("valid azure devops settings", func(t *testing.T) {
		s := ConnectorSettings{
			Kind:         ProviderAzureDevOps,
			ClientID:     "id",
			ClientSecret: "secret",
			CallbackURL:  "https://example.com/callback",
			TenantID:     "tenant-123",
		}
		if err := s.Validate(); err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("bitbucket DC (PAT-based) does not require OAuth fields", func(t *testing.T) {
		s := ConnectorSettings{
			Kind:            ProviderBitbucketDC,
			InstanceBaseURL: "https://bitbucket.example.com",
			// No ClientID, ClientSecret, or CallbackURL needed
		}
		if err := s.Validate(); err != nil {
			t.Errorf("Validate() unexpected error for PAT provider: %v", err)
		}
	})

	t.Run("invalid kind", func(t *testing.T) {
		s := ConnectorSettings{Kind: "notareal", ClientID: "id", ClientSecret: "sec", CallbackURL: "https://x.com"}
		if err := s.Validate(); err != ErrUnknownProviderKind {
			t.Errorf("Validate() error = %v, want %v", err, ErrUnknownProviderKind)
		}
	})

	t.Run("missing client_id for OAuth provider", func(t *testing.T) {
		s := validOAuth
		s.ClientID = ""
		if err := s.Validate(); err != ErrClientIDRequired {
			t.Errorf("Validate() error = %v, want %v", err, ErrClientIDRequired)
		}
	})

	t.Run("missing client_secret for OAuth provider", func(t *testing.T) {
		s := validOAuth
		s.ClientSecret = ""
		if err := s.Validate(); err != ErrClientSecretRequired {
			t.Errorf("Validate() error = %v, want %v", err, ErrClientSecretRequired)
		}
	})

	t.Run("missing callback_url for OAuth provider", func(t *testing.T) {
		s := validOAuth
		s.CallbackURL = ""
		if err := s.Validate(); err != ErrCallbackURLRequired {
			t.Errorf("Validate() error = %v, want %v", err, ErrCallbackURLRequired)
		}
	})

	t.Run("empty kind is invalid", func(t *testing.T) {
		s := ConnectorSettings{Kind: "", ClientID: "id", ClientSecret: "sec", CallbackURL: "https://x.com"}
		if err := s.Validate(); err != ErrUnknownProviderKind {
			t.Errorf("Validate() error = %v, want %v", err, ErrUnknownProviderKind)
		}
	})
}
