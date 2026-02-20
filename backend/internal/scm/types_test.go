package scm

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ProviderType methods
// ---------------------------------------------------------------------------

func TestProviderTypeValid(t *testing.T) {
	tests := []struct {
		pt   ProviderType
		want bool
	}{
		{ProviderGitHub, true},
		{ProviderAzureDevOps, true},
		{ProviderGitLab, true},
		{ProviderBitbucketDC, true},
		{"unknown", false},
		{"", false},
		{"GITHUB", false}, // case-sensitive
		{"Github", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.pt), func(t *testing.T) {
			if got := tt.pt.Valid(); got != tt.want {
				t.Errorf("ProviderType(%q).Valid() = %v, want %v", tt.pt, got, tt.want)
			}
		})
	}
}

func TestProviderTypeIsValid(t *testing.T) {
	// IsValid is an alias for Valid; verify it matches
	for _, pt := range []ProviderType{ProviderGitHub, ProviderAzureDevOps, ProviderGitLab, ProviderBitbucketDC, "bad"} {
		if pt.Valid() != pt.IsValid() {
			t.Errorf("ProviderType(%q): Valid()=%v != IsValid()=%v", pt, pt.Valid(), pt.IsValid())
		}
	}
}

func TestProviderTypeIsPATBased(t *testing.T) {
	tests := []struct {
		pt   ProviderType
		want bool
	}{
		{ProviderBitbucketDC, true},  // only PAT-based provider
		{ProviderGitHub, false},
		{ProviderAzureDevOps, false},
		{ProviderGitLab, false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.pt), func(t *testing.T) {
			if got := tt.pt.IsPATBased(); got != tt.want {
				t.Errorf("ProviderType(%q).IsPATBased() = %v, want %v", tt.pt, got, tt.want)
			}
		})
	}
}

func TestProviderTypeString(t *testing.T) {
	tests := []struct {
		pt   ProviderType
		want string
	}{
		{ProviderGitHub, "github"},
		{ProviderAzureDevOps, "azuredevops"},
		{ProviderGitLab, "gitlab"},
		{ProviderBitbucketDC, "bitbucket_dc"},
		{"custom", "custom"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.pt.String(); got != tt.want {
				t.Errorf("ProviderType(%q).String() = %q, want %q", tt.pt, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OAuthToken.IsExpired
// ---------------------------------------------------------------------------

func TestOAuthTokenIsExpired(t *testing.T) {
	t.Run("nil ExpiresAt is never expired", func(t *testing.T) {
		tok := &OAuthToken{ExpiresAt: nil}
		if tok.IsExpired() {
			t.Error("IsExpired() = true, want false when ExpiresAt is nil")
		}
	})

	t.Run("future ExpiresAt is not expired", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		tok := &OAuthToken{ExpiresAt: &future}
		if tok.IsExpired() {
			t.Error("IsExpired() = true, want false for future expiry")
		}
	})

	t.Run("past ExpiresAt is expired", func(t *testing.T) {
		past := time.Now().Add(-time.Second)
		tok := &OAuthToken{ExpiresAt: &past}
		if !tok.IsExpired() {
			t.Error("IsExpired() = false, want true for past expiry")
		}
	})
}

// ---------------------------------------------------------------------------
// WebhookEvent.IsTagEvent
// ---------------------------------------------------------------------------

func TestWebhookEventIsTagEvent(t *testing.T) {
	tests := []struct {
		name  string
		event WebhookEvent
		want  bool
	}{
		{
			name:  "type=tag",
			event: WebhookEvent{Type: WebhookEventTag},
			want:  true,
		},
		{
			name:  "type=push with TagName set",
			event: WebhookEvent{Type: WebhookEventPush, TagName: "v1.0.0"},
			want:  true,
		},
		{
			name:  "type=push without TagName",
			event: WebhookEvent{Type: WebhookEventPush, TagName: ""},
			want:  false,
		},
		{
			name:  "type=ping",
			event: WebhookEvent{Type: WebhookEventPing},
			want:  false,
		},
		{
			name:  "type=unknown",
			event: WebhookEvent{Type: WebhookEventUnknown},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.IsTagEvent(); got != tt.want {
				t.Errorf("IsTagEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Constants / Kind aliases are consistent with ProviderType values
// ---------------------------------------------------------------------------

func TestKindAliasesMatchProviderTypes(t *testing.T) {
	if KindGitHub != ProviderGitHub {
		t.Errorf("KindGitHub != ProviderGitHub")
	}
	if KindAzureDevOps != ProviderAzureDevOps {
		t.Errorf("KindAzureDevOps != ProviderAzureDevOps")
	}
	if KindGitLab != ProviderGitLab {
		t.Errorf("KindGitLab != ProviderGitLab")
	}
	if KindBitbucketDC != ProviderBitbucketDC {
		t.Errorf("KindBitbucketDC != ProviderBitbucketDC")
	}
}
