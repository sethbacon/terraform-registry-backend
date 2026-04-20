package mtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

func TestNewProvider_Disabled(t *testing.T) {
	_, err := NewProvider(config.MTLSConfig{Enabled: false})
	if err == nil {
		t.Error("expected error when disabled")
	}
}

func TestNewProvider_MissingCAFile(t *testing.T) {
	_, err := NewProvider(config.MTLSConfig{Enabled: true})
	if err == nil {
		t.Error("expected error when client_ca_file is empty")
	}
}

func TestNewProvider_Success(t *testing.T) {
	p, err := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/etc/certs/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=terraform-ci", Scopes: []string{"modules:read"}},
			{Subject: "CN=release-bot", Scopes: []string{"modules:write", "providers:write"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(p.mappings))
	}
}

func TestAuthenticate_ByCN(t *testing.T) {
	p, _ := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=terraform-ci", Scopes: []string{"modules:read", "providers:read"}},
		},
	})

	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "terraform-ci"},
	}

	subject, scopes, err := p.Authenticate(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "CN=terraform-ci" {
		t.Errorf("subject = %q, want CN=terraform-ci", subject)
	}
	if len(scopes) != 2 {
		t.Errorf("scopes = %v, want 2 scopes", scopes)
	}
}

func TestAuthenticate_CaseInsensitive(t *testing.T) {
	p, _ := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=Terraform-CI", Scopes: []string{"modules:read"}},
		},
	})

	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "terraform-ci"},
	}

	_, scopes, err := p.Authenticate(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) != 1 {
		t.Errorf("scopes = %v, want 1 scope", scopes)
	}
}

func TestAuthenticate_NoMatch(t *testing.T) {
	p, _ := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings: []config.MTLSSubjectMapping{
			{Subject: "CN=terraform-ci", Scopes: []string{"modules:read"}},
		},
	})

	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "unknown-client"},
	}

	_, _, err := p.Authenticate(cert)
	if err == nil {
		t.Error("expected error for unmatched subject")
	}
}

func TestAuthenticate_NilCert(t *testing.T) {
	p, _ := NewProvider(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/ca.crt",
		Mappings:     []config.MTLSSubjectMapping{},
	})

	_, _, err := p.Authenticate(nil)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
}

func TestNormalizeSubject(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CN=test", "cn=test"},
		{"  CN=Test  ", "cn=test"},
		{"CN=Terraform-CI,O=Acme", "cn=terraform-ci,o=acme"},
	}
	for _, tt := range tests {
		got := normalizeSubject(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSubject(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
