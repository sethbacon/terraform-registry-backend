package saml

import (
	"testing"

	"github.com/crewjam/saml"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

func TestNewProvider_MissingACSURL(t *testing.T) {
	cfg := &config.SAMLConfig{Enabled: true}
	idpCfg := &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: minimalIdPMetadata}

	_, err := NewProvider(cfg, idpCfg)
	if err == nil {
		t.Fatal("expected error for missing acs_url")
	}
}

func TestNewProvider_InvalidACSURL(t *testing.T) {
	cfg := &config.SAMLConfig{Enabled: true, ACSURL: "://bad"}
	idpCfg := &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: minimalIdPMetadata}

	_, err := NewProvider(cfg, idpCfg)
	if err == nil {
		t.Fatal("expected error for invalid acs_url")
	}
}

func TestNewProvider_NoMetadata(t *testing.T) {
	cfg := &config.SAMLConfig{Enabled: true, ACSURL: "https://example.com/saml/acs"}
	idpCfg := &config.SAMLIdPConfig{Name: "test-idp"}

	_, err := NewProvider(cfg, idpCfg)
	if err == nil {
		t.Fatal("expected error when neither metadata_url nor metadata_xml is set")
	}
}

func TestNewProvider_WithMetadataXML(t *testing.T) {
	cfg := &config.SAMLConfig{
		Enabled:  true,
		ACSURL:   "https://registry.example.com/api/v1/auth/saml/acs",
		EntityID: "https://registry.example.com",
	}
	idpCfg := &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: minimalIdPMetadata}

	p, err := NewProvider(cfg, idpCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "test-idp" {
		t.Errorf("Name() = %q, want %q", p.Name(), "test-idp")
	}
}

func TestNewProvider_EntityIDFallback(t *testing.T) {
	cfg := &config.SAMLConfig{
		Enabled: true,
		ACSURL:  "https://registry.example.com/api/v1/auth/saml/acs",
		// EntityID intentionally empty — should derive from ACSURL
	}
	idpCfg := &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: minimalIdPMetadata}

	p, err := NewProvider(cfg, idpCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	md := p.GetMetadata()
	// The entity ID should be derived by stripping /saml/acs from the ACS URL
	if md.EntityID != "https://registry.example.com/api/v1/auth" {
		t.Errorf("entity ID = %q, want derived value", md.EntityID)
	}
}

func TestGetMetadata_ReturnsValidDescriptor(t *testing.T) {
	cfg := &config.SAMLConfig{
		Enabled:  true,
		ACSURL:   "https://registry.example.com/api/v1/auth/saml/acs",
		EntityID: "https://registry.example.com",
	}
	idpCfg := &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: minimalIdPMetadata}

	p, err := NewProvider(cfg, idpCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	md := p.GetMetadata()
	if md == nil {
		t.Fatal("GetMetadata() returned nil")
	}
	if md.EntityID != "https://registry.example.com" {
		t.Errorf("EntityID = %q, want %q", md.EntityID, "https://registry.example.com")
	}
}

func TestExtractUserInfo_EmailAndName(t *testing.T) {
	assertion := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "user@example.com"},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name:         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
						FriendlyName: "email",
						Values:       []saml.AttributeValue{{Value: "jane@example.com"}},
					},
					{
						Name:         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
						FriendlyName: "displayName",
						Values:       []saml.AttributeValue{{Value: "Jane Doe"}},
					},
				},
			},
		},
	}

	info := extractUserInfo(assertion, "")
	if info.NameID != "user@example.com" {
		t.Errorf("NameID = %q, want %q", info.NameID, "user@example.com")
	}
	if info.Email != "jane@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "jane@example.com")
	}
	if info.Name != "Jane Doe" {
		t.Errorf("Name = %q, want %q", info.Name, "Jane Doe")
	}
}

func TestExtractUserInfo_GroupAttribute(t *testing.T) {
	assertion := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "user@example.com"},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name:   "memberOf",
						Values: []saml.AttributeValue{{Value: "admins"}, {Value: "developers"}},
					},
				},
			},
		},
	}

	info := extractUserInfo(assertion, "memberOf")
	if len(info.Groups) != 2 {
		t.Fatalf("Groups length = %d, want 2", len(info.Groups))
	}
	if info.Groups[0] != "admins" || info.Groups[1] != "developers" {
		t.Errorf("Groups = %v, want [admins developers]", info.Groups)
	}
}

func TestExtractUserInfo_EmailFallbackToNameID(t *testing.T) {
	assertion := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "user@example.com"},
		},
		AttributeStatements: []saml.AttributeStatement{},
	}

	info := extractUserInfo(assertion, "")
	if info.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q (should fallback to NameID)", info.Email, "user@example.com")
	}
}

func TestExtractUserInfo_NoEmailNoFallback(t *testing.T) {
	assertion := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "not-an-email"},
		},
		AttributeStatements: []saml.AttributeStatement{},
	}

	info := extractUserInfo(assertion, "")
	if info.Email != "" {
		t.Errorf("Email = %q, want empty (NameID is not an email)", info.Email)
	}
}

func TestIsEmailAttr(t *testing.T) {
	tests := []struct {
		name, friendly string
		want           bool
	}{
		{"urn:oid:0.9.2342.19200300.100.1.3", "", true},
		{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "", true},
		{"email", "", true},
		{"mail", "", true},
		{"", "email", true},
		{"", "mail", true},
		{"givenName", "", false},
	}
	for _, tt := range tests {
		got := isEmailAttr(tt.name, tt.friendly)
		if got != tt.want {
			t.Errorf("isEmailAttr(%q, %q) = %v, want %v", tt.name, tt.friendly, got, tt.want)
		}
	}
}

func TestIsNameAttr(t *testing.T) {
	tests := []struct {
		name, friendly string
		want           bool
	}{
		{"urn:oid:2.16.840.1.113730.3.1.241", "", true},
		{"urn:oid:2.5.4.3", "", true},
		{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "", true},
		{"displayName", "", true},
		{"", "displayName", true},
		{"", "cn", true},
		{"email", "", false},
	}
	for _, tt := range tests {
		got := isNameAttr(tt.name, tt.friendly)
		if got != tt.want {
			t.Errorf("isNameAttr(%q, %q) = %v, want %v", tt.name, tt.friendly, got, tt.want)
		}
	}
}

func TestFetchIdPMetadata_RequiresHTTPS(t *testing.T) {
	_, err := fetchIdPMetadata("http://insecure.example.com/metadata")
	if err == nil {
		t.Fatal("expected error for non-HTTPS metadata URL")
	}
}

// minimalIdPMetadata is a valid SAML IdP metadata XML for testing.
const minimalIdPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://idp.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
