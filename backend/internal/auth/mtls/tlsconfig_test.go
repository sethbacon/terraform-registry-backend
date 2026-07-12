package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// writeTestCA generates a minimal self-signed CA certificate, PEM-encodes it
// to a temp file, and returns the file path. Used to exercise
// BuildServerTLSConfig's file-loading path without depending on a real CA.
func writeTestCA(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-client-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "client-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestBuildServerTLSConfig_Disabled(t *testing.T) {
	tlsCfg, err := BuildServerTLSConfig(config.MTLSConfig{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg != nil {
		t.Errorf("expected nil tls.Config when mTLS is disabled, got %+v", tlsCfg)
	}
}

func TestBuildServerTLSConfig_MissingCAFile(t *testing.T) {
	_, err := BuildServerTLSConfig(config.MTLSConfig{Enabled: true})
	if err == nil {
		t.Error("expected error when client_ca_file is empty")
	}
}

func TestBuildServerTLSConfig_CAFileNotFound(t *testing.T) {
	_, err := BuildServerTLSConfig(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Error("expected error when client_ca_file does not exist")
	}
}

func TestBuildServerTLSConfig_InvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := BuildServerTLSConfig(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: path,
	})
	if err == nil {
		t.Error("expected error for a client_ca_file with no valid PEM certificates")
	}
}

// TestBuildServerTLSConfig_Success is the core assertion for issue #559
// finding [3]: enabling mTLS must produce a tls.Config with ClientCAs
// populated from the configured file and ClientAuth set to
// VerifyClientCertIfGiven (verify a presented cert, but don't require one —
// this listener also serves non-mTLS callers).
func TestBuildServerTLSConfig_Success(t *testing.T) {
	caPath := writeTestCA(t)

	tlsCfg, err := BuildServerTLSConfig(config.MTLSConfig{
		Enabled:      true,
		ClientCAFile: caPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Fatal("expected ClientCAs to be populated")
	}
	if len(tlsCfg.ClientCAs.Subjects()) != 1 { //nolint:staticcheck // Subjects() deprecated but adequate for a single-CA test assertion
		t.Errorf("expected exactly 1 CA subject in the pool, got %d", len(tlsCfg.ClientCAs.Subjects())) //nolint:staticcheck
	}
}
