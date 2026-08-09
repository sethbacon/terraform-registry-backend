package saml

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
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
	_, err := fetchIdPMetadata("http://insecure.example.com/metadata", nil)
	if err == nil {
		t.Fatal("expected error for non-HTTPS metadata URL")
	}
}

// fetchIdPMetadata routes the fetch through httpsafe.NewClient (dial-time
// resolve-and-pin), not an upfront ValidateURL call, so the SSRF guard here
// is only exercised by actually attempting the request. A nil egress guard
// is the strict default policy (no allow-list entries), so a loopback
// target must be rejected before any TCP connection is attempted -- nothing
// needs to be listening on the target port for this to fail closed.
func TestFetchIdPMetadata_RejectsLoopbackTarget(t *testing.T) {
	_, err := fetchIdPMetadata("https://127.0.0.1:1/metadata", nil)
	if err == nil {
		t.Fatal("expected error for loopback metadata URL target")
	}
	// Assert on the SSRF guard's own wording, not just "any error": port 1
	// is closed, so a connection-refused error would also satisfy a bare
	// err != nil check without proving the egress guard is what blocked
	// this -- if the guard ever regressed, "connection refused" would
	// silently keep this test green.
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to mention the egress guard blocking the target (not e.g. a bare connection error)", err.Error())
	}
}

func TestMakeAuthenticationRequest_ReturnsRequestID(t *testing.T) {
	cfg := &config.SAMLConfig{
		Enabled:  true,
		ACSURL:   "https://registry.example.com/api/v1/auth/saml/acs",
		EntityID: "https://registry.example.com",
	}
	idpCfg := &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: minimalIdPMetadata}

	p, err := NewProvider(cfg, idpCfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	u, reqID, err := p.MakeAuthenticationRequest("state-token")
	if err != nil {
		t.Fatalf("MakeAuthenticationRequest: %v", err)
	}
	if u == nil {
		t.Fatal("expected a non-nil redirect URL")
	}
	if reqID == "" {
		t.Error("expected a non-empty AuthnRequest ID for InResponseTo binding")
	}
}

func TestAllowIDPInitiated_ReflectsConfig(t *testing.T) {
	build := func(allow bool) *Provider {
		t.Helper()
		cfg := &config.SAMLConfig{
			Enabled:           true,
			ACSURL:            "https://registry.example.com/api/v1/auth/saml/acs",
			EntityID:          "https://registry.example.com",
			AllowIDPInitiated: allow,
		}
		idpCfg := &config.SAMLIdPConfig{Name: "test-idp", MetadataXML: minimalIdPMetadata}
		p, err := NewProvider(cfg, idpCfg)
		if err != nil {
			t.Fatalf("NewProvider: %v", err)
		}
		return p
	}

	if build(false).AllowIDPInitiated() {
		t.Error("AllowIDPInitiated() = true, want false (secure default)")
	}
	if !build(true).AllowIDPInitiated() {
		t.Error("AllowIDPInitiated() = false, want true when enabled in config")
	}
}

// TestProvider_NoUnboundParseResponsePath guards against reintroducing the
// dead ParseResponse(samlResponse, groupAttr string) method removed by issue
// #559: it called p.sp.ParseResponse(nil, []string{}) with a hardcoded-empty
// possibleRequestIDs, silently skipping the InResponseTo/replay binding that
// ValidateResponse (the sole real entry point, invoked from the ACS handler)
// enforces. Checked by reflection on the method name rather than by calling
// it directly, since a direct call would simply fail to compile once the
// method is gone -- silently deleting this regression test's value along
// with it instead of failing loudly if the method is ever reintroduced.
func TestProvider_NoUnboundParseResponsePath(t *testing.T) {
	typ := reflect.TypeOf(&Provider{})
	for i := 0; i < typ.NumMethod(); i++ {
		if typ.Method(i).Name == "ParseResponse" {
			t.Fatal("Provider must not expose its own ParseResponse method (issue #559): " +
				"it bypassed InResponseTo/replay binding by calling the underlying SP's " +
				"ParseResponse with a hardcoded-empty possibleRequestIDs; callers must go " +
				"through ValidateResponse, which requires possibleRequestIDs")
		}
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

// Issue #747 follow-up — IssuerFromResponse parses UNAUTHENTICATED input.
//
// The first version used xml.Unmarshal into a one-field struct. gosec's G709
// flagged it, and while the Java-style gadget-chain risk does not apply to
// encoding/xml, the finding pointed at something real: xml.Unmarshal RECURSES
// over element depth, so a deeply nested document reaching the ACS endpoint
// from an anonymous POST could exhaust the goroutine stack — which panics
// unrecoverably and takes the process down.
//
// The tokenising implementation is iterative and bounded. These tests pin the
// bounds; without them a "fix" that only silenced the scanner would pass.

func samlResponseForm(body string) *http.Request {
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	r := httptest.NewRequest(http.MethodPost, "/acs",
		strings.NewReader("SAMLResponse="+url.QueryEscape(encoded)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestIssuerFromResponse_ReadsTheResponseLevelIssuer(t *testing.T) {
	// The nested Issuer deliberately comes FIRST in document order. In a normal
	// response the Response-level Issuer precedes the Assertion, so "first
	// Issuer anywhere" and "Issuer at depth 2" agree and the test cannot tell
	// them apart — the first version of this test was exactly that, and passed
	// with the depth check deleted.
	//
	// Ordered this way, taking any-depth returns the attacker's value and
	// taking depth 2 returns the sender's. Which provider validates the
	// response depends on this.
	body := `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Assertion><saml:Issuer>https://attacker.example.com</saml:Issuer></saml:Assertion>` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`</samlp:Response>`

	got, err := IssuerFromResponse(samlResponseForm(body))
	if err != nil {
		t.Fatalf("IssuerFromResponse: %v", err)
	}
	if got != "https://idp.example.com" {
		t.Errorf("issuer = %q, want the Response-level issuer — the Assertion's own "+
			"Issuer must not select the validating provider", got)
	}
}

func TestIssuerFromResponse_RejectsDeepNestingWithoutExhaustingTheStack(t *testing.T) {
	// Deep enough to exceed maxSAMLDepth, SHALLOW enough not to trip
	// maxSAMLTokens — otherwise this test passes with the depth bound removed
	// and is really testing the token bound. It did exactly that at first:
	// 50,000 nested elements is 100,000 tokens, so the token limit fired and
	// deleting the depth check changed nothing.
	depth := maxSAMLDepth + 50
	if 2*depth >= maxSAMLTokens {
		t.Fatalf("test depth %d would trip maxSAMLTokens (%d) first", depth, maxSAMLTokens)
	}

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?>`)
	for i := 0; i < depth; i++ {
		sb.WriteString("<a>")
	}
	for i := 0; i < depth; i++ {
		sb.WriteString("</a>")
	}

	_, err := IssuerFromResponse(samlResponseForm(sb.String()))
	if err == nil {
		t.Fatal("a document deeper than maxSAMLDepth was accepted")
	}
	// The specific bound, not merely "an error": "no Issuer" is also an error
	// and would pass a laxer assertion with the guard removed.
	if !strings.Contains(err.Error(), "nests deeper") {
		t.Errorf("error = %q, want the depth bound to be what rejected it", err)
	}
}

func TestIssuerFromResponse_RejectsTokenFlood(t *testing.T) {
	// Shallow but enormous element count, with the flood BEFORE a perfectly
	// good Response-level Issuer. Without the token bound this document parses
	// fine and returns that issuer, so the test can only pass because the bound
	// fired — the first version put the issuer nowhere and asserted merely
	// "an error", which "no Issuer" satisfied with the guard removed.
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><Response>`)
	for i := 0; i < maxSAMLTokens; i++ {
		sb.WriteString("<a/>")
	}
	sb.WriteString(`<Issuer>https://idp.example.com</Issuer></Response>`)

	got, err := IssuerFromResponse(samlResponseForm(sb.String()))
	if err == nil {
		t.Fatalf("a document over maxSAMLTokens was accepted, returning %q", got)
	}
	if !strings.Contains(err.Error(), "tokens") {
		t.Errorf("error = %q, want the token bound to be what rejected it", err)
	}
}

func TestIssuerFromResponse_RejectsOversizedInput(t *testing.T) {
	// VALID XML with a good Issuer, padded past the cap. The first version used
	// a megabyte of "a", which is not XML at all — so it failed to parse with
	// or without the cap, and deleting the cap did not change the result.
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><Response><Issuer>https://idp.example.com</Issuer><pad>`)
	sb.WriteString(strings.Repeat("A", maxSAMLResponseBytes))
	sb.WriteString(`</pad></Response>`)
	if sb.Len() <= maxSAMLResponseBytes {
		t.Fatalf("test payload is %d bytes, not over the %d cap", sb.Len(), maxSAMLResponseBytes)
	}

	got, err := IssuerFromResponse(samlResponseForm(sb.String()))
	if err == nil {
		t.Fatalf("an over-cap response was accepted, returning %q", got)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %q, want the size cap to be what rejected it", err)
	}
}

func TestIssuerFromResponse_RejectsMalformedInput(t *testing.T) {
	for name, req := range map[string]*http.Request{
		"not base64": httptest.NewRequest(http.MethodPost, "/acs",
			strings.NewReader("SAMLResponse=!!!not-base64!!!")),
		"not xml":       samlResponseForm("hello"),
		"no issuer":     samlResponseForm(`<Response><Other>x</Other></Response>`),
		"empty issuer":  samlResponseForm(`<Response><Issuer>   </Issuer></Response>`),
		"no form field": httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader("")),
	} {
		t.Run(name, func(t *testing.T) {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if _, err := IssuerFromResponse(req); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// TestIssuerFromResponse_RejectsNestedElementsInsideIssuer — an entity ID is
// text, so a nested element is malformed and refused.
//
// This is not pedantry. The first implementation skipped the nested start tag,
// appended the nested element's character data, and returned at the NESTED
// closing tag, so
//
//	<Issuer>https://idp.example.com<evil>https://attacker.example.com</evil></Issuer>
//
// produced "https://idp.example.comhttps://attacker.example.com" — the two
// concatenated. That is a value smuggled into the comparison that selects which
// IdP validates the response. This test caught it.
func TestIssuerFromResponse_RejectsNestedElementsInsideIssuer(t *testing.T) {
	body := `<Response><Issuer>https://idp.example.com<evil>https://attacker.example.com</evil></Issuer></Response>`

	got, err := IssuerFromResponse(samlResponseForm(body))
	if err == nil {
		t.Fatalf("a nested element inside <Issuer> was accepted, yielding %q", got)
	}
	if !strings.Contains(err.Error(), "nested") {
		t.Errorf("error = %q, want it to name the nested element", err)
	}
}
