// Package ldap implements LDAP / Active Directory authentication for the registry.
// It supports simple bind authentication with StartTLS/LDAPS, user search, and
// group membership lookup for role mapping.
package ldap

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Provider manages LDAP connections and authentication operations.
type Provider struct {
	cfg *config.LDAPConfig
}

// UserInfo holds the attributes extracted from LDAP for an authenticated user.
type UserInfo struct {
	DN     string
	Email  string
	Name   string
	Groups []string
}

// NewProvider creates a new LDAP provider. It validates the configuration but
// does not open connections until Authenticate is called.
func NewProvider(cfg *config.LDAPConfig) (*Provider, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("ldap: host is required")
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("ldap: base_dn is required")
	}
	if cfg.BindDN == "" {
		return nil, fmt.Errorf("ldap: bind_dn is required for search-bind authentication")
	}
	if cfg.UserFilter == "" {
		return nil, fmt.Errorf("ldap: user_filter is required")
	}

	port := cfg.Port
	if port == 0 {
		if cfg.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}

	cfgCopy := *cfg
	cfgCopy.Port = port

	// Set sensible defaults for optional attribute names
	if cfgCopy.UserAttrEmail == "" {
		cfgCopy.UserAttrEmail = "mail"
	}
	if cfgCopy.UserAttrName == "" {
		cfgCopy.UserAttrName = "displayName"
	}
	if cfgCopy.GroupMemberAttr == "" {
		cfgCopy.GroupMemberAttr = "member"
	}

	return &Provider{
		cfg: &cfgCopy,
	}, nil
}

// Authenticate performs a search-bind authentication:
//  1. Binds with the service account (BindDN/BindPassword)
//  2. Searches for the user by UserFilter
//  3. Binds as the found user DN with the provided password
//  4. If successful, looks up group memberships
//
// Returns the user's info on success, or an error on failure.
func (p *Provider) Authenticate(username, password string) (*UserInfo, error) {
	conn, err := p.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap: failed to connect: %w", err)
	}
	defer conn.Close()

	// Step 1: Bind with service account
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: service account bind failed: %w", err)
	}

	// Step 2: Search for user
	userDN, email, name, err := p.searchUser(conn, username)
	if err != nil {
		return nil, err
	}

	// Step 3: Bind as the user to verify password
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("ldap: authentication failed for user %q", username)
	}

	// Step 4: Re-bind as service account and look up groups
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: re-bind as service account failed: %w", err)
	}

	groups, err := p.lookupGroups(conn, userDN)
	if err != nil {
		slog.Warn("ldap: group lookup failed, continuing without groups", "user", username, "error", err)
		groups = nil
	}

	return &UserInfo{
		DN:     userDN,
		Email:  email,
		Name:   name,
		Groups: groups,
	}, nil
}

// dial creates a new LDAP connection with the configured TLS settings.
func (p *Provider) dial() (*goldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", p.cfg.Host, p.cfg.Port)

	tlsConfig := &tls.Config{
		ServerName:         p.cfg.Host,
		InsecureSkipVerify: p.cfg.InsecureSkipVerify, // #nosec G402 -- admin-configurable for dev environments
	}

	if p.cfg.UseTLS {
		// LDAPS: TLS from the start
		conn, err := goldap.DialURL(fmt.Sprintf("ldaps://%s", addr), goldap.DialWithTLSConfig(tlsConfig))
		if err != nil {
			return nil, fmt.Errorf("ldaps dial failed: %w", err)
		}
		return conn, nil
	}

	// Plain LDAP (optionally upgrading to StartTLS)
	conn, err := goldap.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}

	if p.cfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close() // #nosec G104 -- best-effort close on error path
			return nil, fmt.Errorf("StartTLS failed: %w", err)
		}
	}

	return conn, nil
}

// searchUser finds a user by the configured UserFilter. The filter should
// contain %s which will be replaced with the escaped username.
func (p *Provider) searchUser(conn *goldap.Conn, username string) (dn, email, name string, err error) {
	// Escape the username to prevent LDAP injection
	escapedUsername := goldap.EscapeFilter(username)
	filter := fmt.Sprintf(p.cfg.UserFilter, escapedUsername)

	searchReq := goldap.NewSearchRequest(
		p.cfg.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		1,  // size limit: we only need one result
		10, // time limit (seconds)
		false,
		filter,
		[]string{"dn", p.cfg.UserAttrEmail, p.cfg.UserAttrName},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return "", "", "", fmt.Errorf("ldap: user search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", "", "", fmt.Errorf("ldap: user %q not found", username)
	}
	if len(result.Entries) > 1 {
		return "", "", "", fmt.Errorf("ldap: multiple entries found for user %q", username)
	}

	entry := result.Entries[0]
	return entry.DN,
		entry.GetAttributeValue(p.cfg.UserAttrEmail),
		entry.GetAttributeValue(p.cfg.UserAttrName),
		nil
}

// lookupGroups finds groups the user is a member of.
func (p *Provider) lookupGroups(conn *goldap.Conn, userDN string) ([]string, error) {
	baseDN := p.cfg.GroupBaseDN
	if baseDN == "" {
		baseDN = p.cfg.BaseDN
	}

	filter := p.cfg.GroupFilter
	if filter == "" {
		// Default: search for groups where the member attribute contains the user DN
		filter = fmt.Sprintf("(%s=%s)", p.cfg.GroupMemberAttr, goldap.EscapeFilter(userDN))
	} else {
		filter = fmt.Sprintf(filter, goldap.EscapeFilter(userDN))
	}

	searchReq := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,  // no size limit
		10, // time limit
		false,
		filter,
		[]string{"dn", "cn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap: group search failed: %w", err)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		// Use the DN as the group identifier (matches GroupMapping.GroupDN)
		groups = append(groups, entry.DN)
	}

	return groups, nil
}

// Close is a no-op for now; reserved for future connection pool shutdown.
func (p *Provider) Close() error {
	return nil
}

// MatchGroupMappings matches the user's LDAP group DNs against the configured
// group mappings and returns the matching organization/role pairs.
func MatchGroupMappings(groups []string, mappings []config.LDAPGroupMapping) []config.LDAPGroupMapping {
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		// Normalize: case-insensitive DN comparison
		groupSet[strings.ToLower(g)] = struct{}{}
	}

	var matched []config.LDAPGroupMapping
	for _, m := range mappings {
		if _, ok := groupSet[strings.ToLower(m.GroupDN)]; ok {
			matched = append(matched, m)
		}
	}
	return matched
}
