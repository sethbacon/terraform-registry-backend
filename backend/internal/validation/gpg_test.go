package validation

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// armoredPublicKey returns an ASCII-armored RSA public key generated on the fly.
// The matching entity (with private key) is also returned for signature tests.
func generateTestGPGEntity(t *testing.T) (armoredPubKey string, entity *openpgp.Entity) {
	t.Helper()
	entity, err := openpgp.NewEntity("Test User", "test", "test@example.com", nil)
	if err != nil {
		t.Fatalf("openpgp.NewEntity() error: %v", err)
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode() error: %v", err)
	}
	if err := entity.Serialize(w); err != nil {
		t.Fatalf("entity.Serialize() error: %v", err)
	}
	w.Close()

	return buf.String(), entity
}

// armoredDetachSign creates an ASCII-armored detached signature of data using entity.
func armoredDetachSign(t *testing.T, data []byte, entity *openpgp.Entity) string {
	t.Helper()
	var sigBuf bytes.Buffer
	w, err := armor.Encode(&sigBuf, openpgp.SignatureType, nil)
	if err != nil {
		t.Fatalf("armor.Encode() for signature error: %v", err)
	}
	if err := openpgp.DetachSign(w, entity, bytes.NewReader(data), nil); err != nil {
		t.Fatalf("openpgp.DetachSign() error: %v", err)
	}
	w.Close()
	return sigBuf.String()
}

// ---------------------------------------------------------------------------
// ParseGPGPublicKey
// ---------------------------------------------------------------------------

func TestParseGPGPublicKey(t *testing.T) {
	t.Run("valid generated key", func(t *testing.T) {
		armoredKey, _ := generateTestGPGEntity(t)
		if err := ParseGPGPublicKey(armoredKey); err != nil {
			t.Errorf("ParseGPGPublicKey() unexpected error: %v", err)
		}
	})

	t.Run("empty key returns error", func(t *testing.T) {
		if err := ParseGPGPublicKey(""); err == nil {
			t.Error("ParseGPGPublicKey(\"\") expected error, got nil")
		}
	})

	t.Run("missing BEGIN marker", func(t *testing.T) {
		if err := ParseGPGPublicKey("-----END PGP PUBLIC KEY BLOCK-----\n"); err == nil {
			t.Error("ParseGPGPublicKey() expected error for missing BEGIN marker, got nil")
		}
	})

	t.Run("missing END marker", func(t *testing.T) {
		if err := ParseGPGPublicKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"); err == nil {
			t.Error("ParseGPGPublicKey() expected error for missing END marker, got nil")
		}
	})

	t.Run("markers present but corrupted body", func(t *testing.T) {
		corrupted := "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnotvalidbase64!!!\n-----END PGP PUBLIC KEY BLOCK-----\n"
		if err := ParseGPGPublicKey(corrupted); err == nil {
			t.Error("ParseGPGPublicKey() expected error for corrupted body, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// IsValidGPGKeyFormat
// ---------------------------------------------------------------------------

func TestIsValidGPGKeyFormat(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"empty string", "", false},
		{"missing both markers", "just some text", false},
		{"missing END marker", "-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata\n", false},
		{"missing BEGIN marker", "data\n-----END PGP PUBLIC KEY BLOCK-----\n", false},
		{
			"both markers present",
			"-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata\n-----END PGP PUBLIC KEY BLOCK-----\n",
			true,
		},
		{
			"END before BEGIN (reversed)",
			"-----END PGP PUBLIC KEY BLOCK-----\ndata\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidGPGKeyFormat(tt.key)
			if got != tt.want {
				t.Errorf("IsValidGPGKeyFormat() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("generated key is valid format", func(t *testing.T) {
		armoredKey, _ := generateTestGPGEntity(t)
		if !IsValidGPGKeyFormat(armoredKey) {
			t.Error("IsValidGPGKeyFormat() = false for a real generated key")
		}
	})
}

// ---------------------------------------------------------------------------
// NormalizeGPGKey
// ---------------------------------------------------------------------------

func TestNormalizeGPGKey(t *testing.T) {
	t.Run("windows line endings converted to unix", func(t *testing.T) {
		input := "line1\r\nline2\r\nline3"
		got := NormalizeGPGKey(input)
		if bytes.Contains([]byte(got), []byte("\r\n")) {
			t.Errorf("NormalizeGPGKey() still contains CRLF: %q", got)
		}
	})

	t.Run("leading/trailing whitespace trimmed", func(t *testing.T) {
		input := "  \n  key content  \n  "
		got := NormalizeGPGKey(input)
		// After trim and adding newline, should not start with whitespace
		if len(got) > 0 && got[0] == ' ' {
			t.Errorf("NormalizeGPGKey() result starts with whitespace: %q", got)
		}
	})

	t.Run("result always ends with newline", func(t *testing.T) {
		got := NormalizeGPGKey("some key data")
		if got[len(got)-1] != '\n' {
			t.Errorf("NormalizeGPGKey() result does not end with newline: %q", got)
		}
	})

	t.Run("already-normalized key unchanged except newline", func(t *testing.T) {
		input := "clean key"
		got := NormalizeGPGKey(input)
		if got != "clean key\n" {
			t.Errorf("NormalizeGPGKey(%q) = %q, want %q", input, got, "clean key\n")
		}
	})
}

// ---------------------------------------------------------------------------
// ExtractChecksumFromShasums
// ---------------------------------------------------------------------------

func TestExtractChecksumFromShasums(t *testing.T) {
	// SHA256SUMS format: "<checksum>  <filename>" or "<checksum>  *<filename>"
	// The asterisk is a BSD checksum binary-mode indicator on the FILENAME, not the checksum.
	const shasums = `
abc123def456abc123def456abc123def456abc123def456abc123def456abc1  terraform-provider-foo_1.0.0_linux_amd64.zip
bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb2  terraform-provider-foo_1.0.0_darwin_amd64.zip
ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc3  *terraform-provider-foo_1.0.0_windows_amd64.zip
`

	tests := []struct {
		name     string
		filename string
		want     string
		wantErr  bool
	}{
		{"exact match linux", "terraform-provider-foo_1.0.0_linux_amd64.zip", "abc123def456abc123def456abc123def456abc123def456abc123def456abc1", false},
		{"exact match darwin", "terraform-provider-foo_1.0.0_darwin_amd64.zip", "bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb2", false},
		{"asterisk prefix stripped from filename", "terraform-provider-foo_1.0.0_windows_amd64.zip", "ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc3", false},
		{"file not found", "nonexistent.zip", "", true},
		{"empty filename", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractChecksumFromShasums(shasums, tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractChecksumFromShasums() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ExtractChecksumFromShasums() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateChecksumMatch
// ---------------------------------------------------------------------------

func TestValidateChecksumMatch(t *testing.T) {
	tests := []struct {
		name       string
		calculated string
		expected   string
		wantErr    bool
	}{
		{"identical lowercase", "abcdef123456", "abcdef123456", false},
		{"case insensitive match uppercase calculated", "ABCDEF123456", "abcdef123456", false},
		{"case insensitive match uppercase expected", "abcdef123456", "ABCDEF123456", false},
		{"both uppercase", "ABCDEF123456", "ABCDEF123456", false},
		{"mismatch", "aaaaaaaaaaaa", "bbbbbbbbbbbb", true},
		{"empty both", "", "", false},
		{"empty calculated", "", "abc", true},
		{"empty expected", "abc", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChecksumMatch(tt.calculated, tt.expected)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateChecksumMatch(%q, %q) error = %v, wantErr %v",
					tt.calculated, tt.expected, err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateProviderBinary
// ---------------------------------------------------------------------------

func TestValidateProviderBinary(t *testing.T) {
	// PK\x03\x04 is the ZIP local file header magic
	validZIP := append([]byte{0x50, 0x4B, 0x03, 0x04}, make([]byte, 100)...)
	// PK\x05\x06 is the empty-archive ZIP magic
	emptyZIP := append([]byte{0x50, 0x4B, 0x05, 0x06}, make([]byte, 10)...)

	tests := []struct {
		name    string
		data    []byte
		maxSize int64
		wantErr bool
	}{
		{"valid ZIP local header", validZIP, int64(len(validZIP) + 1), false},
		{"valid empty-archive ZIP", emptyZIP, int64(len(emptyZIP) + 1), false},
		{"empty data", []byte{}, 1024, true},
		{"too small (3 bytes)", []byte{0x50, 0x4B, 0x03}, 1024, true},
		{"not a ZIP (gzip magic)", []byte{0x1F, 0x8B, 0x08, 0x00, 0x00}, 1024, true},
		{"not a ZIP (elf binary)", []byte{0x7F, 0x45, 0x4C, 0x46, 0x00}, 1024, true},
		{"exceeds max size", validZIP, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProviderBinary(tt.data, tt.maxSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProviderBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// VerifyProviderSignature (error paths + valid path)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// VerifyArmoredSignature
// ---------------------------------------------------------------------------

func TestVerifyArmoredSignature_ValidSignature(t *testing.T) {
	pubKey, entity := generateTestGPGEntity(t)
	data := []byte("hello world")
	sig := armoredDetachSign(t, data, entity)

	if err := VerifyArmoredSignature(pubKey, data, sig); err != nil {
		t.Errorf("VerifyArmoredSignature() error = %v, want nil", err)
	}
}

func TestVerifyArmoredSignature_WrongData(t *testing.T) {
	pubKey, entity := generateTestGPGEntity(t)
	sig := armoredDetachSign(t, []byte("original data"), entity)

	if err := VerifyArmoredSignature(pubKey, []byte("tampered data"), sig); err == nil {
		t.Error("VerifyArmoredSignature() = nil, want error for wrong data")
	}
}

func TestVerifyArmoredSignature_InvalidSignature(t *testing.T) {
	pubKey, _ := generateTestGPGEntity(t)
	if err := VerifyArmoredSignature(pubKey, []byte("data"), "not-a-sig"); err == nil {
		t.Error("VerifyArmoredSignature() = nil, want error for invalid signature")
	}
}

// ---------------------------------------------------------------------------
// VerifyShasumSignature
// ---------------------------------------------------------------------------

func TestVerifyShasumSignature_EmptyShasums(t *testing.T) {
	if err := VerifyShasumSignature("", "sig", "key"); err == nil {
		t.Error("VerifyShasumSignature() = nil, want error for empty shasums")
	}
}

func TestVerifyShasumSignature_EmptySignature(t *testing.T) {
	if err := VerifyShasumSignature("shasum content", "", "key"); err == nil {
		t.Error("VerifyShasumSignature() = nil, want error for empty signature")
	}
}

func TestVerifyShasumSignature_ValidSignature(t *testing.T) {
	pubKey, entity := generateTestGPGEntity(t)
	shasums := "abc123  terraform_1.0.0_linux_amd64.zip\n"
	sig := armoredDetachSign(t, []byte(shasums), entity)

	if err := VerifyShasumSignature(shasums, sig, pubKey); err != nil {
		t.Errorf("VerifyShasumSignature() error = %v, want nil", err)
	}
}

func TestVerifyShasumSignature_InvalidKey(t *testing.T) {
	_, entity := generateTestGPGEntity(t)
	shasums := "abc123  terraform_1.0.0_linux_amd64.zip\n"
	sig := armoredDetachSign(t, []byte(shasums), entity)

	// Use wrong/empty public key
	if err := VerifyShasumSignature(shasums, sig, "not-a-key"); err == nil {
		t.Error("VerifyShasumSignature() = nil, want error for invalid public key")
	}
}

// ---------------------------------------------------------------------------

func TestVerifyProviderSignature(t *testing.T) {
	t.Run("empty shasum content", func(t *testing.T) {
		result := VerifyProviderSignature(nil, []byte("sig"), []string{"key"})
		if result.Verified {
			t.Error("VerifyProviderSignature() Verified = true, want false for empty content")
		}
		if result.Error == nil {
			t.Error("VerifyProviderSignature() Error = nil, want non-nil for empty content")
		}
	})

	t.Run("empty signature content", func(t *testing.T) {
		result := VerifyProviderSignature([]byte("shasum content"), nil, []string{"key"})
		if result.Verified {
			t.Error("VerifyProviderSignature() Verified = true, want false for empty signature")
		}
		if result.Error == nil {
			t.Error("VerifyProviderSignature() Error = nil, want non-nil for empty signature")
		}
	})

	t.Run("empty public keys slice", func(t *testing.T) {
		result := VerifyProviderSignature([]byte("content"), []byte("sig"), nil)
		if result.Verified {
			t.Error("VerifyProviderSignature() Verified = true, want false for no keys")
		}
		if result.Error == nil {
			t.Error("VerifyProviderSignature() Error = nil, want non-nil for no keys")
		}
	})

	t.Run("all empty-string keys skipped", func(t *testing.T) {
		result := VerifyProviderSignature([]byte("content"), []byte("sig"), []string{"", ""})
		if result.Verified {
			t.Error("VerifyProviderSignature() Verified = true for all-empty key list")
		}
	})

	t.Run("valid signature verifies", func(t *testing.T) {
		armoredKey, entity := generateTestGPGEntity(t)
		content := []byte("abc123  terraform-provider-test_1.0.0_linux_amd64.zip\n")
		armoredSig := armoredDetachSign(t, content, entity)

		result := VerifyProviderSignature(content, []byte(armoredSig), []string{armoredKey})
		if !result.Verified {
			t.Errorf("VerifyProviderSignature() Verified = false, want true; error: %v", result.Error)
		}
		if result.Error != nil {
			t.Errorf("VerifyProviderSignature() Error = %v, want nil", result.Error)
		}
	})

	t.Run("wrong key does not verify", func(t *testing.T) {
		_, entity1 := generateTestGPGEntity(t)
		armoredKey2, _ := generateTestGPGEntity(t) // different key
		content := []byte("some content\n")
		armoredSig := armoredDetachSign(t, content, entity1)

		result := VerifyProviderSignature(content, []byte(armoredSig), []string{armoredKey2})
		if result.Verified {
			t.Error("VerifyProviderSignature() Verified = true for wrong key")
		}
	})
}
