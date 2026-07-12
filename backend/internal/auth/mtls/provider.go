// Package mtls provides mutual TLS client certificate authentication.
// When enabled, clients presenting a valid certificate signed by the configured
// CA are authenticated and assigned scopes based on subject-to-scope mappings.
//
// Three pieces wire together to make this work end to end (issue #559 finding
// [3] — previously only the second and third existed, so the package was dead
// code because nothing ever populated verified client certs on the request):
//
//  1. BuildServerTLSConfig (tlsconfig.go) — loads ClientCAFile into the HTTP
//     server's tls.Config and sets ClientAuth=VerifyClientCertIfGiven, so Go's
//     TLS stack actually requests and verifies a client certificate during the
//     handshake. Wired in cmd/server/main.go.
//  2. Provider (this file) — maps a verified certificate's subject to scopes.
//  3. AuthMiddleware (middleware.go) — reads the leaf certificate from
//     c.Request.TLS.VerifiedChains and sets it in the Gin context for the RBAC
//     layer. Registered globally in router.go.
//
// mTLS only works when this server terminates TLS itself
// (security.tls.enabled=true). It cannot work behind a TLS-terminating
// ingress/load balancer — see BuildServerTLSConfig's doc comment.
package mtls

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Provider verifies client certificates and maps subjects to scopes.
type Provider struct {
	mappings map[string][]string // subject → scopes
}

// NewProvider creates an mTLS provider from configuration.
// The ClientCAFile is loaded by BuildServerTLSConfig for the TLS server
// configuration, not here; this provider only handles subject → scope mapping.
func NewProvider(cfg config.MTLSConfig) (*Provider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("mTLS is not enabled")
	}
	if cfg.ClientCAFile == "" {
		return nil, fmt.Errorf("mtls.client_ca_file is required")
	}
	if len(cfg.Mappings) == 0 {
		slog.Warn("mTLS enabled but no subject mappings configured")
	}

	m := make(map[string][]string, len(cfg.Mappings))
	for _, mapping := range cfg.Mappings {
		subject := normalizeSubject(mapping.Subject)
		m[subject] = mapping.Scopes
		slog.Info("mTLS subject mapping registered", "subject", subject, "scopes", mapping.Scopes)
	}

	return &Provider{mappings: m}, nil
}

// Authenticate extracts the subject from a verified client certificate and
// returns the mapped scopes. Returns an error if no mapping matches.
func (p *Provider) Authenticate(cert *x509.Certificate) (subject string, scopes []string, err error) {
	if cert == nil {
		return "", nil, fmt.Errorf("no client certificate provided")
	}

	// Try matching by CN first
	cnSubject := "CN=" + cert.Subject.CommonName
	if scopes, ok := p.mappings[normalizeSubject(cnSubject)]; ok {
		return cnSubject, scopes, nil
	}

	// Try matching by full DN
	fullDN := cert.Subject.String()
	if scopes, ok := p.mappings[normalizeSubject(fullDN)]; ok {
		return fullDN, scopes, nil
	}

	return "", nil, fmt.Errorf("no mTLS mapping for subject CN=%s (DN=%s)", cert.Subject.CommonName, fullDN)
}

// normalizeSubject lower-cases and trims whitespace from a subject string
// to allow case-insensitive matching.
func normalizeSubject(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}
