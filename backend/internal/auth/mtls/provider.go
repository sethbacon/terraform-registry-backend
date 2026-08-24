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

	"github.com/google/uuid"
	"github.com/sethbacon/terraform-suite-identity/identity/auth"
)

// Provider verifies client certificates and maps subjects to scopes.
type Provider struct {
	mappings map[string]subjectMapping // normalized subject → mapping
}

// subjectMapping is one configured certificate subject: the scopes it presents
// and, when it carries `admin`, the user whose carrier row decides whether that
// `admin` means anything on this request (issue #876).
type subjectMapping struct {
	scopes []string
	userID string
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

	m := make(map[string]subjectMapping, len(cfg.Mappings))
	for _, mapping := range cfg.Mappings {
		subject := normalizeSubject(mapping.Subject)

		// A repeated subject used to overwrite silently. That was untidy when a
		// mapping was only a scope list; now that one can name the user a
		// certificate acts as, a silent overwrite would bind a certificate to a
		// DIFFERENT PRINCIPAL than the line the operator is reading. Refuse.
		if _, dup := m[subject]; dup {
			return nil, fmt.Errorf("mtls.mappings: subject %q is configured more than once; "+
				"remove the duplicate — a repeated subject would silently take the last "+
				"scopes and user_id in the file", mapping.Subject)
		}

		// REFUSE `admin` WITHOUT A USER (issue #876).
		//
		// Platform-admin authority lives in the platform_admins carrier and the
		// carrier is keyed on user_id, so an `admin` mapping with no user names
		// no grant that can be audited, and none that revoking a carrier row
		// can take away. Refusing at construction makes that unrepresentable
		// rather than merely discouraged: router.go turns this error into a
		// log.Fatalf, so a deployment configured this way does not start.
		//
		// This is the mTLS analogue of the write-time refusals #874 put on role
		// templates and memberships. Those answer a request 400/403 because
		// they intercept a write; a mapping is configuration, so the only
		// moment there is to refuse is boot.
		if err := auth.ValidateProvisionableScopes(mapping.Scopes); err != nil && mapping.UserID == "" {
			return nil, fmt.Errorf("mtls.mappings: subject %q carries the `admin` scope with no user_id. "+
				"Platform administration is held in the platform_admins carrier, which is keyed on a "+
				"user; set user_id to the UUID of the user this certificate acts as (and grant them "+
				"platform administration through POST /api/v1/admin/platform-admins), or remove `admin` "+
				"from the mapping", mapping.Subject)
		}

		if mapping.UserID != "" {
			if _, err := uuid.Parse(mapping.UserID); err != nil {
				return nil, fmt.Errorf("mtls.mappings: subject %q has user_id %q, which is not a UUID: %w",
					mapping.Subject, mapping.UserID, err)
			}
		}

		m[subject] = subjectMapping{scopes: mapping.Scopes, userID: mapping.UserID}
		slog.Info("mTLS subject mapping registered",
			"subject", subject, "scopes", mapping.Scopes, "user_id", mapping.UserID)
	}

	return &Provider{mappings: m}, nil
}

// Authenticate extracts the subject from a verified client certificate and
// returns the mapped scopes together with the user the mapping names, if any.
// Returns an error if no mapping matches.
//
// The returned scopes are the CONFIGURED ones, not the effective ones. Anything
// reaching for `admin` here is reading a claim from a config file; the carrier
// decides whether it holds. AuthMiddleware performs that resolution — this
// method deliberately does not, so there is one place where an mTLS request's
// authority is settled rather than two.
func (p *Provider) Authenticate(cert *x509.Certificate) (subject string, scopes []string, userID string, err error) {
	if cert == nil {
		return "", nil, "", fmt.Errorf("no client certificate provided")
	}

	// Try matching by CN first
	cnSubject := "CN=" + cert.Subject.CommonName
	if mapping, ok := p.mappings[normalizeSubject(cnSubject)]; ok {
		return cnSubject, mapping.scopes, mapping.userID, nil
	}

	// Try matching by full DN
	fullDN := cert.Subject.String()
	if mapping, ok := p.mappings[normalizeSubject(fullDN)]; ok {
		return fullDN, mapping.scopes, mapping.userID, nil
	}

	return "", nil, "", fmt.Errorf("no mTLS mapping for subject CN=%s (DN=%s)", cert.Subject.CommonName, fullDN)
}

// normalizeSubject lower-cases and trims whitespace from a subject string
// to allow case-insensitive matching.
func normalizeSubject(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}
