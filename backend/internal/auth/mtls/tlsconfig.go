// tlsconfig.go builds the crypto/tls.Config additions needed to actually
// enable mTLS client-certificate verification on the HTTP server. Before this,
// the mtls Provider/AuthMiddleware existed but nothing ever requested or
// verified a client certificate — the TLS server had no ClientCAs and
// ClientAuth defaulted to tls.NoClientCert, so c.Request.TLS.PeerCertificates
// (and VerifiedChains) were always empty and this package's mapping logic
// could never fire (issue #559 finding [3]).
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// BuildServerTLSConfig returns the ClientCAs/ClientAuth settings the HTTP
// server's tls.Config needs to enable mTLS, loaded from cfg.ClientCAFile.
// Returns (nil, nil) when cfg.Enabled is false so callers can skip mutating
// their base tls.Config entirely.
//
// ClientAuth is always tls.VerifyClientCertIfGiven, not
// tls.RequireAndVerifyClientCert: this server also serves browser sessions
// (JWT/OIDC/SAML/LDAP) and plain API-key callers over the same listener, none
// of whom present a client certificate. VerifyClientCertIfGiven verifies a
// certificate against ClientCAs whenever the client presents one, but does not
// require every connection to present one — callers that don't present a cert
// simply fall through to the existing bearer-token auth paths.
//
// IMPORTANT — mTLS cannot work behind a TLS-terminating ingress/load balancer.
// Client certificates are part of the TLS handshake itself; once TLS is
// terminated upstream (a reverse proxy, an ALB/NLB in TLS-termination mode,
// etc.), this process never sees the raw handshake and c.Request.TLS is nil.
// Enabling security.mtls in that topology is a silent no-op — the ingress
// would need to perform its own client-cert verification and forward the
// verified identity via a trusted header, which this package does not
// implement. mTLS only works when this server terminates TLS itself
// (security.tls.enabled=true).
func BuildServerTLSConfig(cfg config.MTLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.ClientCAFile == "" {
		return nil, fmt.Errorf("mtls.client_ca_file is required when mtls.enabled is true")
	}

	caPEM, err := os.ReadFile(cfg.ClientCAFile) // #nosec G304 -- operator-supplied config path, not user input
	if err != nil {
		return nil, fmt.Errorf("failed to read mtls.client_ca_file %q: %w", cfg.ClientCAFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid PEM certificates found in mtls.client_ca_file %q", cfg.ClientCAFile)
	}

	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}, nil
}
