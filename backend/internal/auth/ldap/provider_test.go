package ldap

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

func TestNewProvider_MissingHost(t *testing.T) {
	cfg := &config.LDAPConfig{Enabled: true, BaseDN: "dc=example,dc=com", BindDN: "cn=admin", UserFilter: "(uid=%s)"}
	_, err := NewProvider(cfg)
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestNewProvider_MissingBaseDN(t *testing.T) {
	cfg := &config.LDAPConfig{Enabled: true, Host: "ldap.example.com", BindDN: "cn=admin", UserFilter: "(uid=%s)"}
	_, err := NewProvider(cfg)
	if err == nil {
		t.Fatal("expected error for missing base_dn")
	}
}

func TestNewProvider_MissingBindDN(t *testing.T) {
	cfg := &config.LDAPConfig{Enabled: true, Host: "ldap.example.com", BaseDN: "dc=example,dc=com", UserFilter: "(uid=%s)"}
	_, err := NewProvider(cfg)
	if err == nil {
		t.Fatal("expected error for missing bind_dn")
	}
}

func TestNewProvider_MissingUserFilter(t *testing.T) {
	cfg := &config.LDAPConfig{Enabled: true, Host: "ldap.example.com", BaseDN: "dc=example,dc=com", BindDN: "cn=admin"}
	_, err := NewProvider(cfg)
	if err == nil {
		t.Fatal("expected error for missing user_filter")
	}
}

func TestNewProvider_DefaultPorts(t *testing.T) {
	tests := []struct {
		name     string
		useTLS   bool
		wantPort int
	}{
		{"plain LDAP defaults to 389", false, 389},
		{"LDAPS defaults to 636", true, 636},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.LDAPConfig{
				Enabled:    true,
				Host:       "ldap.example.com",
				BaseDN:     "dc=example,dc=com",
				BindDN:     "cn=admin,dc=example,dc=com",
				UserFilter: "(uid=%s)",
				UseTLS:     tt.useTLS,
			}
			p, err := NewProvider(cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.cfg.Port != tt.wantPort {
				t.Errorf("port = %d, want %d", p.cfg.Port, tt.wantPort)
			}
		})
	}
}

func TestNewProvider_DefaultAttributes(t *testing.T) {
	cfg := &config.LDAPConfig{
		Enabled:    true,
		Host:       "ldap.example.com",
		BaseDN:     "dc=example,dc=com",
		BindDN:     "cn=admin,dc=example,dc=com",
		UserFilter: "(uid=%s)",
	}
	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.cfg.UserAttrEmail != "mail" {
		t.Errorf("UserAttrEmail = %q, want %q", p.cfg.UserAttrEmail, "mail")
	}
	if p.cfg.UserAttrName != "displayName" {
		t.Errorf("UserAttrName = %q, want %q", p.cfg.UserAttrName, "displayName")
	}
	if p.cfg.GroupMemberAttr != "member" {
		t.Errorf("GroupMemberAttr = %q, want %q", p.cfg.GroupMemberAttr, "member")
	}
}

func TestNewProvider_CustomPort(t *testing.T) {
	cfg := &config.LDAPConfig{
		Enabled:    true,
		Host:       "ldap.example.com",
		Port:       3389,
		BaseDN:     "dc=example,dc=com",
		BindDN:     "cn=admin,dc=example,dc=com",
		UserFilter: "(uid=%s)",
	}
	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.cfg.Port != 3389 {
		t.Errorf("port = %d, want 3389", p.cfg.Port)
	}
}

func TestMatchGroupMappings_Exact(t *testing.T) {
	groups := []string{
		"cn=admins,ou=groups,dc=example,dc=com",
		"cn=developers,ou=groups,dc=example,dc=com",
	}
	mappings := []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "default", Role: "admin"},
		{GroupDN: "cn=readonly,ou=groups,dc=example,dc=com", Organization: "default", Role: "viewer"},
	}

	matched := MatchGroupMappings(groups, mappings)
	if len(matched) != 1 {
		t.Fatalf("matched %d, want 1", len(matched))
	}
	if matched[0].Role != "admin" {
		t.Errorf("matched role = %q, want %q", matched[0].Role, "admin")
	}
}

func TestMatchGroupMappings_CaseInsensitive(t *testing.T) {
	groups := []string{"CN=Admins,OU=Groups,DC=Example,DC=Com"}
	mappings := []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "default", Role: "admin"},
	}

	matched := MatchGroupMappings(groups, mappings)
	if len(matched) != 1 {
		t.Fatalf("matched %d, want 1", len(matched))
	}
}

func TestMatchGroupMappings_NoMatch(t *testing.T) {
	groups := []string{"cn=users,ou=groups,dc=example,dc=com"}
	mappings := []config.LDAPGroupMapping{
		{GroupDN: "cn=admins,ou=groups,dc=example,dc=com", Organization: "default", Role: "admin"},
	}

	matched := MatchGroupMappings(groups, mappings)
	if len(matched) != 0 {
		t.Fatalf("matched %d, want 0", len(matched))
	}
}

func TestClose(t *testing.T) {
	cfg := &config.LDAPConfig{
		Enabled:    true,
		Host:       "ldap.example.com",
		BaseDN:     "dc=example,dc=com",
		BindDN:     "cn=admin,dc=example,dc=com",
		UserFilter: "(uid=%s)",
	}
	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}
