package cve

import (
	"testing"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

func strPtr(s string) *string { return &s }

func TestProviderGoModule(t *testing.T) {
	tests := []struct {
		name string
		c    repositories.ProviderCandidate
		want string
	}{
		{
			name: "no source falls back to canonical github path",
			c:    repositories.ProviderCandidate{Namespace: "hashicorp", ProviderType: "aws"},
			want: "github.com/hashicorp/terraform-provider-aws",
		},
		{
			name: "empty source falls back to canonical",
			c:    repositories.ProviderCandidate{Namespace: "hashicorp", ProviderType: "aws", Source: strPtr("")},
			want: "github.com/hashicorp/terraform-provider-aws",
		},
		{
			name: "https github source",
			c:    repositories.ProviderCandidate{Namespace: "x", ProviderType: "y", Source: strPtr("https://github.com/foo/terraform-provider-bar")},
			want: "github.com/foo/terraform-provider-bar",
		},
		{
			name: "http github source with .git suffix",
			c:    repositories.ProviderCandidate{Namespace: "x", ProviderType: "y", Source: strPtr("http://github.com/foo/terraform-provider-bar.git")},
			want: "github.com/foo/terraform-provider-bar",
		},
		{
			name: "non-github source falls back to canonical",
			c:    repositories.ProviderCandidate{Namespace: "x", ProviderType: "y", Source: strPtr("https://gitlab.com/foo/bar")},
			want: "github.com/x/terraform-provider-y",
		},
		{
			name: "github source with extra path segments uses three-segment join",
			c:    repositories.ProviderCandidate{Namespace: "x", ProviderType: "y", Source: strPtr("https://github.com/foo/bar/baz")},
			want: "github.com/foo/bar/baz",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := providerGoModule(tc.c)
			if got != tc.want {
				t.Errorf("providerGoModule() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMustParseUUID(t *testing.T) {
	t.Run("valid uuid parses", func(t *testing.T) {
		want := uuid.New()
		got := mustParseUUID(want.String())
		if got != want {
			t.Errorf("mustParseUUID(%q) = %v, want %v", want.String(), got, want)
		}
	})
	t.Run("invalid uuid returns Nil", func(t *testing.T) {
		got := mustParseUUID("not-a-uuid")
		if got != uuid.Nil {
			t.Errorf("mustParseUUID(invalid) = %v, want uuid.Nil", got)
		}
	})
	t.Run("empty string returns Nil", func(t *testing.T) {
		got := mustParseUUID("")
		if got != uuid.Nil {
			t.Errorf("mustParseUUID(\"\") = %v, want uuid.Nil", got)
		}
	})
}
