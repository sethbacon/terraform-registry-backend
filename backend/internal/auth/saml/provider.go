// Package saml implements SAML 2.0 Service Provider authentication for the registry.
// It supports SP-initiated and IdP-initiated SSO flows, with configurable
// group-attribute-to-role mapping that mirrors the OIDC group mapping model.
package saml

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

// IDPEntityID returns the entity ID of the IdP this provider is configured for.
//
// Used to resolve WHICH configured IdP an unsolicited (IdP-initiated) response
// came from, by matching the response's Issuer. Before this, the ACS handler
// picked an arbitrary provider out of a Go map when no RelayState resolved one
// (issue #747).
func (p *Provider) IDPEntityID() string {
	if p.sp.IDPMetadata == nil {
		return ""
	}
	return p.sp.IDPMetadata.EntityID
}

// IssuerFromResponse extracts the Issuer entity ID from a SAML response WITHOUT
// validating it.
//
// This is deliberately untrusted input: it is used only to SELECT which
// configured provider should then validate the response, and selecting the
// wrong one can only cause validation to fail. It never grants anything on its
// own -- the chosen provider still verifies the signature against its own
// configured certificate.
//
// The request's parsed form is cached by net/http, so calling this before
// ValidateResponse does not consume the body.
//
// # Why this tokenises instead of calling xml.Unmarshal
//
// The first version used xml.Unmarshal into a one-field struct, and gosec's
// G709 taint analysis flagged it (HIGH) as deserialisation of untrusted data.
// That is not the Java-style gadget-chain risk -- encoding/xml resolves no
// external entities and does no type-directed dispatch -- but it IS a real
// denial of service: xml.Unmarshal recurses over element depth, so a deeply
// nested document ("<a><a><a>...") reaches this from an UNAUTHENTICATED POST to
// the ACS endpoint and can exhaust the goroutine stack. A stack overflow is not
// recoverable; it takes the process down.
//
// Tokenising is iterative, so depth costs nothing on the Go stack, and it lets
// the depth and token count be bounded explicitly. Only the Response-level
// Issuer is read -- the child of the root element -- which is the one that
// identifies the sender; the Assertion carries its own, and the provider's real
// validation re-checks that.
func IssuerFromResponse(r *http.Request) (string, error) {
	raw := r.FormValue("SAMLResponse")
	if raw == "" {
		return "", fmt.Errorf("saml: no SAMLResponse in request")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("saml: SAMLResponse is not valid base64: %w", err)
	}
	if len(decoded) > maxSAMLResponseBytes {
		return "", fmt.Errorf("saml: SAMLResponse exceeds %d bytes", maxSAMLResponseBytes)
	}

	// #nosec G709 -- see the doc comment: this decodes untrusted input BY DESIGN.
	// encoding/xml resolves no external entities and does no type-directed
	// dispatch, so CWE-502's gadget-chain risk does not apply; G709 flags any XML
	// decoding of tainted input, so no parsing strategy clears it. The residual
	// risk is resource exhaustion, which is bounded above and below: 1 MiB of
	// input, maxSAMLDepth, maxSAMLTokens, maxIssuerBytes, and tokenising rather
	// than recursive unmarshalling. The extracted value selects a provider and
	// grants nothing on its own.
	dec := xml.NewDecoder(bytes.NewReader(decoded))
	var depth, tokens int
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("saml: could not parse SAMLResponse: %w", err)
		}
		tokens++
		if tokens > maxSAMLTokens {
			return "", fmt.Errorf("saml: SAMLResponse has more than %d tokens", maxSAMLTokens)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > maxSAMLDepth {
				return "", fmt.Errorf("saml: SAMLResponse nests deeper than %d elements", maxSAMLDepth)
			}
			// Depth 2 is a child of the root <Response>: the sender's Issuer.
			// The Assertion's Issuer sits deeper and is not what selects the
			// provider.
			if depth == 2 && t.Name.Local == "Issuer" {
				issuer, err := readCharData(dec, &tokens)
				if err != nil {
					return "", err
				}
				if issuer = strings.TrimSpace(issuer); issuer != "" {
					return issuer, nil
				}
				return "", fmt.Errorf("saml: SAMLResponse has an empty Issuer")
			}
		case xml.EndElement:
			depth--
		}
	}
	return "", fmt.Errorf("saml: SAMLResponse has no Issuer")
}

// readCharData accumulates the character data of the element the decoder has
// just entered, stopping at its closing tag.
//
// Character data only: a nested element inside <Issuer> is not part of the
// entity ID, and treating it as such would let a crafted response smuggle a
// different value past the comparison.
func readCharData(dec *xml.Decoder, tokens *int) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("saml: could not read Issuer: %w", err)
		}
		*tokens++
		if *tokens > maxSAMLTokens {
			return "", fmt.Errorf("saml: SAMLResponse has more than %d tokens", maxSAMLTokens)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if sb.Len()+len(t) > maxIssuerBytes {
				return "", fmt.Errorf("saml: Issuer exceeds %d bytes", maxIssuerBytes)
			}
			sb.Write(t)
		case xml.StartElement:
			// An entity ID is text. A nested element inside <Issuer> is
			// malformed, and accepting it is worse than pedantry: the first
			// version of this function skipped the start tag, appended the
			// nested element's character data, and then returned at the
			// nested CLOSING tag -- so
			//   <Issuer>https://idp.example.com<evil>https://attacker...</evil></Issuer>
			// yielded the two concatenated. Its own test caught that.
			return "", fmt.Errorf("saml: Issuer contains a nested %q element", t.Name.Local)
		case xml.EndElement:
			return sb.String(), nil
		}
	}
}

// maxSAMLResponseBytes bounds the decoded response parsed by IssuerFromResponse.
// Real assertions are a few KB; this is generous while still refusing to hand an
// unbounded attacker-controlled document to the XML decoder.
const (
	maxSAMLResponseBytes = 1 << 20 // 1 MiB
	// maxSAMLDepth and maxSAMLTokens bound the tokenising scan. A real
	// assertion nests around a dozen elements deep; these are far above that
	// and exist only to stop a pathological document.
	maxSAMLDepth  = 100
	maxSAMLTokens = 100_000
	// maxIssuerBytes bounds the entity ID being accumulated.
	maxIssuerBytes = 4096
)

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
