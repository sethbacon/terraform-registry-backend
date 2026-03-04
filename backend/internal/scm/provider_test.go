package scm

import (
	"testing"
)

// ---------------------------------------------------------------------------
// DefaultListOptions
// ---------------------------------------------------------------------------

func TestDefaultListOptions(t *testing.T) {
	opts := DefaultListOptions()
	if opts == nil {
		t.Fatal("DefaultListOptions() returned nil")
	}
	if opts.Page != 1 {
		t.Errorf("DefaultListOptions().Page = %d, want 1", opts.Page)
	}
	if opts.PerPage != 30 {
		t.Errorf("DefaultListOptions().PerPage = %d, want 30", opts.PerPage)
	}
}

// ---------------------------------------------------------------------------
// ProviderConfig.Validate
// ---------------------------------------------------------------------------

func TestProviderConfigValidate(t *testing.T) {
	validCfg := ProviderConfig{
		Type:         ProviderGitHub,
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		RedirectURL:  "https://example.com/callback",
	}

	t.Run("valid config passes", func(t *testing.T) {
		cfg := validCfg
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("all provider types accepted", func(t *testing.T) {
		for _, pt := range []ProviderType{ProviderGitHub, ProviderAzureDevOps, ProviderGitLab, ProviderBitbucketDC} {
			cfg := validCfg
			cfg.Type = pt
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() for provider %q unexpected error: %v", pt, err)
			}
		}
	})

	t.Run("invalid provider type", func(t *testing.T) {
		cfg := validCfg
		cfg.Type = "svn"
		if err := cfg.Validate(); err != ErrInvalidProviderType {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidProviderType)
		}
	})

	t.Run("empty provider type", func(t *testing.T) {
		cfg := validCfg
		cfg.Type = ""
		if err := cfg.Validate(); err != ErrInvalidProviderType {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidProviderType)
		}
	})

	t.Run("missing client_id", func(t *testing.T) {
		cfg := validCfg
		cfg.ClientID = ""
		if err := cfg.Validate(); err != ErrMissingClientID {
			t.Errorf("Validate() error = %v, want %v", err, ErrMissingClientID)
		}
	})

	t.Run("missing client_secret", func(t *testing.T) {
		cfg := validCfg
		cfg.ClientSecret = ""
		if err := cfg.Validate(); err != ErrMissingClientSecret {
			t.Errorf("Validate() error = %v, want %v", err, ErrMissingClientSecret)
		}
	})

	t.Run("missing redirect_url", func(t *testing.T) {
		cfg := validCfg
		cfg.RedirectURL = ""
		if err := cfg.Validate(); err != ErrMissingRedirectURL {
			t.Errorf("Validate() error = %v, want %v", err, ErrMissingRedirectURL)
		}
	})

	t.Run("base_url is optional", func(t *testing.T) {
		cfg := validCfg
		cfg.BaseURL = ""
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected error when base_url is empty: %v", err)
		}
	})

	t.Run("base_url can be set without error", func(t *testing.T) {
		cfg := validCfg
		cfg.BaseURL = "https://github.example.com"
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected error with base_url set: %v", err)
		}
	})
}
