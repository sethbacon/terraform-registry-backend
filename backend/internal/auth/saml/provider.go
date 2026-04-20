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
)

// Provider wraps a crewjam/saml ServiceProvider and exposes methods needed
// by the auth handlers. One Provider instance is created per configured IdP.
type Provider struct {
	sp   saml.ServiceProvider
	name string
}

// UserInfo holds the attributes extracted from a SAML assertion.
type UserInfo struct {
	NameID string
	Email  string
	Name   string
	Groups []string
}

// NewProvider creates a SAML Service Provider for the given IdP configuration.
// It loads the SP certificate/key pair for signing and fetches IdP metadata.
func NewProvider(cfg *config.SAMLConfig, idpCfg *config.SAMLIdPConfig) (*Provider, error) {
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
		AllowIDPInitiated: true,
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
	idpMetadata, err := resolveIdPMetadata(idpCfg)
	if err != nil {
		return nil, fmt.Errorf("saml: IdP %q: %w", idpCfg.Name, err)
	}
	sp.IDPMetadata = idpMetadata

	return &Provider{
		sp:   sp,
		name: idpCfg.Name,
	}, nil
}

// Name returns the display name of the IdP this provider is configured for.
func (p *Provider) Name() string {
	return p.name
}

// GetMetadata returns the SP metadata XML for publishing to IdPs.
func (p *Provider) GetMetadata() *saml.EntityDescriptor {
	return p.sp.Metadata()
}

// MakeAuthenticationRequest creates a SAML AuthnRequest URL for SP-initiated login.
func (p *Provider) MakeAuthenticationRequest(relayState string) (*url.URL, error) {
	authReq, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return nil, fmt.Errorf("saml: failed to create AuthnRequest: %w", err)
	}

	redirectURL, err := authReq.Redirect(relayState, &p.sp)
	if err != nil {
		return nil, fmt.Errorf("saml: failed to build redirect URL: %w", err)
	}

	return redirectURL, nil
}

// ParseResponse validates a SAML Response (from the ACS POST) and extracts user info.
func (p *Provider) ParseResponse(samlResponse string, groupAttr string) (*UserInfo, error) {
	assertion, err := p.sp.ParseResponse(nil, []string{})
	// The crewjam/saml library expects the response in an http.Request.
	// We use samlsp.ParseResponse which is more convenient.
	// Let's use the lower-level approach with a synthetic request.
	_ = assertion
	_ = err

	// Use the direct assertion parsing approach
	assertionInfo, err := p.parseAssertionFromResponse(samlResponse)
	if err != nil {
		return nil, err
	}

	return assertionInfo, nil
}

// ValidateResponse validates a SAML response from an HTTP request and returns user info.
func (p *Provider) ValidateResponse(r *http.Request, possibleRequestIDs []string, groupAttr string) (*UserInfo, error) {
	assertion, err := p.sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, fmt.Errorf("saml: failed to validate response: %w", err)
	}

	return extractUserInfo(assertion, groupAttr), nil
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

// parseAssertionFromResponse is a helper that processes a base64-encoded SAMLResponse.
func (p *Provider) parseAssertionFromResponse(samlResponse string) (*UserInfo, error) {
	// Build a synthetic POST request for crewjam/saml's ParseResponse
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	body := strings.NewReader(form.Encode())

	req, err := http.NewRequest(http.MethodPost, p.sp.AcsURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("saml: failed to build synthetic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	assertion, err := p.sp.ParseResponse(req, []string{})
	if err != nil {
		return nil, fmt.Errorf("saml: failed to validate SAML response: %w", err)
	}

	return extractUserInfo(assertion, ""), nil
}

// resolveIdPMetadata fetches or parses IdP metadata from the config.
func resolveIdPMetadata(idpCfg *config.SAMLIdPConfig) (*saml.EntityDescriptor, error) {
	if idpCfg.MetadataXML != "" {
		metadata := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(idpCfg.MetadataXML), metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata XML: %w", err)
		}
		return metadata, nil
	}

	if idpCfg.MetadataURL != "" {
		return fetchIdPMetadata(idpCfg.MetadataURL)
	}

	return nil, fmt.Errorf("either metadata_url or metadata_xml must be provided")
}

// fetchIdPMetadata retrieves and parses IdP metadata from a URL.
func fetchIdPMetadata(metadataURL string) (*saml.EntityDescriptor, error) {
	parsedURL, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("metadata URL must use HTTPS: %s", metadataURL)
	}

	client := &http.Client{Timeout: 30 * time.Second}
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
