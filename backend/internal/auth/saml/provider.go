// Package saml implements SAML 2.0 Service Provider authentication for the registry.
// It supports SP-initiated and IdP-initiated SSO flows, with configurable
// group-attribute-to-role mapping that mirrors the OIDC group mapping model.
package saml

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// Provider wraps a crewjam/saml ServiceProvider and exposes methods needed
// by the auth handlers. One Provider instance is created per configured IdP.
type Provider struct {
	sp                saml.ServiceProvider
	name              string
	allowIDPInitiated bool
}

// UserInfo holds the attributes extracted from a SAML assertion.
type UserInfo struct {
	NameID string
	Email  string
	Name   string
	Groups []string
}

// AssertionMeta carries replay-relevant metadata extracted from a validated
// assertion. It is used by the ACS handler to deduplicate assertion IDs when
// IdP-initiated SSO is enabled (there is no InResponseTo binding in that flow).
type AssertionMeta struct {
	// ID is the SAML assertion ID (unique per issued assertion).
	ID string
	// NotOnOrAfter is the end of the assertion validity window; a replay-cache
	// entry need only be retained until this time.
	NotOnOrAfter time.Time
}

// NewProvider creates a SAML Service Provider for the given IdP configuration
// with the strict egress policy (no allow-list). It loads the SP
// certificate/key pair for signing and fetches IdP metadata.
func NewProvider(cfg *config.SAMLConfig, idpCfg *config.SAMLIdPConfig) (*Provider, error) {
	return NewProviderWithGuard(cfg, idpCfg, nil)
}

// NewProviderWithGuard is NewProvider with an egress guard widening the SSRF
// deny-list (nil = strict), for deployments whose SAML IdP metadata_url points
// at an internal IdP.
func NewProviderWithGuard(cfg *config.SAMLConfig, idpCfg *config.SAMLIdPConfig, egress *httpsafe.Guard) (*Provider, error) {
	if cfg.ACSURL == "" {
		return nil, fmt.Errorf("saml: acs_url is required")
	}

	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: invalid acs_url: %w", err)
	}

	entityID := cfg.EntityID
	if entityID == "" {
		entityID = strings.TrimSuffix(cfg.ACSURL, "/saml/acs")
	}

	sp := saml.ServiceProvider{
		EntityID:          entityID,
		AcsURL:            *acsURL,
		AllowIDPInitiated: cfg.AllowIDPInitiated,
	}

	// Load SP signing cert/key if provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		keyPair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("saml: failed to load SP cert/key: %w", err)
		}
		sp.Key = keyPair.PrivateKey.(*rsa.PrivateKey)
		sp.Certificate = keyPair.Leaf
		if sp.Certificate == nil {
			// tls.LoadX509KeyPair doesn't always populate Leaf; parse manually.
			cert, err := x509.ParseCertificate(keyPair.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("saml: failed to parse SP certificate: %w", err)
			}
			sp.Certificate = cert
		}
	}

	// Fetch or parse IdP metadata
	idpMetadata, err := resolveIdPMetadata(idpCfg, egress)
	if err != nil {
		return nil, fmt.Errorf("saml: IdP %q: %w", idpCfg.Name, err)
	}
	sp.IDPMetadata = idpMetadata

	return &Provider{
		sp:                sp,
		name:              idpCfg.Name,
		allowIDPInitiated: cfg.AllowIDPInitiated,
	}, nil
}

// Name returns the display name of the IdP this provider is configured for.
func (p *Provider) Name() string {
	return p.name
}

// AllowIDPInitiated reports whether unsolicited IdP-initiated SSO responses are
// accepted for this IdP. When false, only solicited SP-initiated responses
// bound to a server-issued AuthnRequest ID (InResponseTo) are accepted.
func (p *Provider) AllowIDPInitiated() bool {
	return p.allowIDPInitiated
}

// GetMetadata returns the SP metadata XML for publishing to IdPs.
func (p *Provider) GetMetadata() *saml.EntityDescriptor {
	return p.sp.Metadata()
}

// MakeAuthenticationRequest creates a SAML AuthnRequest URL for SP-initiated login.
// It returns the redirect URL and the generated AuthnRequest ID. The caller must
// persist the request ID (keyed to the RelayState/state token) and supply it as
// a possible request ID at the ACS so the assertion's InResponseTo is enforced.
func (p *Provider) MakeAuthenticationRequest(relayState string) (*url.URL, string, error) {
	authReq, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return nil, "", fmt.Errorf("saml: failed to create AuthnRequest: %w", err)
	}

	redirectURL, err := authReq.Redirect(relayState, &p.sp)
	if err != nil {
		return nil, "", fmt.Errorf("saml: failed to build redirect URL: %w", err)
	}

	return redirectURL, authReq.ID, nil
}

// ValidateResponse is the sole SAML response-parsing entry point (issue #559
// removed a second, dead ParseResponse(samlResponse, groupAttr string) method
// that called p.sp.ParseResponse(nil, []string{}) with a hardcoded-empty
// possibleRequestIDs, silently skipping InResponseTo/replay binding; it had
// no production or test caller). It validates a SAML response from an HTTP
// request and returns user info plus replay-relevant assertion metadata.
// possibleRequestIDs must contain the AuthnRequest ID issued for this login
// (SP-initiated); when the provider does not allow IdP-initiated SSO, an
// empty list rejects the response.
func (p *Provider) ValidateResponse(r *http.Request, possibleRequestIDs []string, groupAttr string) (*UserInfo, *AssertionMeta, error) {
	assertion, err := p.sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("saml: failed to validate response: %w", err)
	}

	meta := &AssertionMeta{ID: assertion.ID}
	if assertion.Conditions != nil {
		meta.NotOnOrAfter = assertion.Conditions.NotOnOrAfter
	}

	return extractUserInfo(assertion, groupAttr), meta, nil
}

// extractUserInfo pulls user attributes from a validated SAML assertion.
func extractUserInfo(assertion *saml.Assertion, groupAttr string) *UserInfo {
	info := &UserInfo{}

	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		info.NameID = assertion.Subject.NameID.Value
	}

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			values := attrValues(attr)
			switch {
			case isEmailAttr(attr.Name, attr.FriendlyName):
				if len(values) > 0 {
					info.Email = values[0]
				}
			case isNameAttr(attr.Name, attr.FriendlyName):
				if len(values) > 0 {
					info.Name = values[0]
				}
			case groupAttr != "" && (attr.Name == groupAttr || attr.FriendlyName == groupAttr):
				info.Groups = values
			}
		}
	}

	// Fall back to NameID as email if no explicit email attribute
	if info.Email == "" && strings.Contains(info.NameID, "@") {
		info.Email = info.NameID
	}

	return info
}

// resolveIdPMetadata fetches or parses IdP metadata from the config.
func resolveIdPMetadata(idpCfg *config.SAMLIdPConfig, egress *httpsafe.Guard) (*saml.EntityDescriptor, error) {
	if idpCfg.MetadataXML != "" {
		metadata := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(idpCfg.MetadataXML), metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata XML: %w", err)
		}
		return metadata, nil
	}

	if idpCfg.MetadataURL != "" {
		return fetchIdPMetadata(idpCfg.MetadataURL, egress)
	}

	return nil, fmt.Errorf("either metadata_url or metadata_xml must be provided")
}

// fetchIdPMetadata retrieves and parses IdP metadata from a URL. The fetch is
// routed through the SSRF-safe egress client (internal/httpsafe): scheme is
// restricted to HTTPS, and (unless the host is allow-listed) the resolved IP
// is checked against the private/metadata deny-list before dialing, with
// redirects re-validated per hop.
func fetchIdPMetadata(metadataURL string, egress *httpsafe.Guard) (*saml.EntityDescriptor, error) {
	parsedURL, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("metadata URL must use HTTPS: %s", metadataURL)
	}

	client := httpsafe.NewClient(30*time.Second, egress)
	resp, err := client.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata from %s: %w", metadataURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata URL returned status %d", resp.StatusCode)
	}

	// Limit read to 1MB to prevent resource exhaustion
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata response: %w", err)
	}

	metadata, err := samlsp.ParseMetadata(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata: %w", err)
	}

	slog.Info("fetched SAML IdP metadata", "url", metadataURL, "entity_id", metadata.EntityID)
	return metadata, nil
}

// isEmailAttr returns true for common SAML email attribute names/OIDs.
func isEmailAttr(name, friendlyName string) bool {
	switch {
	case friendlyName == "email" || friendlyName == "mail":
		return true
	case name == "urn:oid:0.9.2342.19200300.100.1.3": // mail
		return true
	case name == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
		return true
	case strings.EqualFold(name, "email") || strings.EqualFold(name, "mail"):
		return true
	}
	return false
}

// isNameAttr returns true for common SAML display name attribute names/OIDs.
func isNameAttr(name, friendlyName string) bool {
	switch {
	case friendlyName == "displayName" || friendlyName == "cn":
		return true
	case name == "urn:oid:2.16.840.1.113730.3.1.241": // displayName
		return true
	case name == "urn:oid:2.5.4.3": // cn
		return true
	case name == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
		return true
	case strings.EqualFold(name, "displayName") || strings.EqualFold(name, "cn"):
		return true
	}
	return false
}

// attrValues extracts string values from a SAML attribute.
func attrValues(attr saml.Attribute) []string {
	vals := make([]string, 0, len(attr.Values))
	for _, v := range attr.Values {
		if v.Value != "" {
			vals = append(vals, v.Value)
		}
	}
	return vals
}
