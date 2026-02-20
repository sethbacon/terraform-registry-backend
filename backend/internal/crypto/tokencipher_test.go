package crypto

import (
	"bytes"
	"testing"
)

// testKey returns a valid 32-byte key for use in tests.
func testKey() []byte {
	return bytes.Repeat([]byte("k"), 32)
}

func TestNewTokenCipher(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		tc, err := NewTokenCipher(testKey())
		if err != nil {
			t.Fatalf("NewTokenCipher() unexpected error: %v", err)
		}
		if tc == nil {
			t.Fatal("NewTokenCipher() returned nil cipher")
		}
	})

	tests := []struct {
		name    string
		keyLen  int
		wantErr error
	}{
		{"too short (16 bytes)", 16, ErrKeyLengthInvalid},
		{"too long (64 bytes)", 64, ErrKeyLengthInvalid},
		{"empty key", 0, ErrKeyLengthInvalid},
		{"31 bytes", 31, ErrKeyLengthInvalid},
		{"33 bytes", 33, ErrKeyLengthInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTokenCipher(make([]byte, tt.keyLen))
			if err != tt.wantErr {
				t.Errorf("NewTokenCipher(len=%d) error = %v, want %v", tt.keyLen, err, tt.wantErr)
			}
		})
	}
}

func TestNewTokenCipherIsolatesKey(t *testing.T) {
	// Modifying the original key slice must not affect the cipher.
	key := testKey()
	tc, err := NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher() error: %v", err)
	}
	plaintext := "sensitive-data"
	sealed, _ := tc.Seal(plaintext)

	// Corrupt the original key
	for i := range key {
		key[i] = 0
	}

	// The cipher should still work with its own copy
	got, err := tc.Open(sealed)
	if err != nil {
		t.Errorf("Open() after key corruption error: %v", err)
	}
	if got != plaintext {
		t.Errorf("Open() = %q, want %q", got, plaintext)
	}
}

func TestDeriveTokenCipher(t *testing.T) {
	t.Run("valid passphrase and salt", func(t *testing.T) {
		salt := bytes.Repeat([]byte("s"), 16)
		tc, err := DeriveTokenCipher("my-secret-passphrase", salt, 100000)
		if err != nil {
			t.Fatalf("DeriveTokenCipher() unexpected error: %v", err)
		}
		if tc == nil {
			t.Fatal("DeriveTokenCipher() returned nil")
		}
	})

	t.Run("salt too short", func(t *testing.T) {
		_, err := DeriveTokenCipher("passphrase", make([]byte, 8), 100000)
		if err != ErrSaltTooShort {
			t.Errorf("DeriveTokenCipher() error = %v, want %v", err, ErrSaltTooShort)
		}
	})

	t.Run("low iteration count uses secure default", func(t *testing.T) {
		salt := bytes.Repeat([]byte("s"), 16)
		// Should not error; low count is silently bumped to 100000
		tc, err := DeriveTokenCipher("pass", salt, 1)
		if err != nil {
			t.Fatalf("DeriveTokenCipher() error: %v", err)
		}
		if tc == nil {
			t.Fatal("DeriveTokenCipher() returned nil")
		}
	})

	t.Run("different passphrases produce different ciphers", func(t *testing.T) {
		salt := bytes.Repeat([]byte("s"), 16)
		tc1, _ := DeriveTokenCipher("passphrase-one", salt, 100000)
		tc2, _ := DeriveTokenCipher("passphrase-two", salt, 100000)

		sealed, _ := tc1.Seal("secret")
		// tc2 should NOT be able to decrypt what tc1 sealed
		_, err := tc2.Open(sealed)
		if err == nil {
			t.Error("different-key cipher decrypted ciphertext; expected failure")
		}
	})
}

func TestSealAndOpen(t *testing.T) {
	tc, err := NewTokenCipher(testKey())
	if err != nil {
		t.Fatalf("NewTokenCipher() error: %v", err)
	}

	plaintexts := []string{
		"hello",
		"a-very-long-token-string-that-exceeds-normal-length-for-oauth-access-tokens-eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0",
		"unicode: 日本語テスト",
		"special chars: !@#$%^&*()",
		"newline\nand\ttabs",
	}

	for _, pt := range plaintexts {
		t.Run("roundtrip/"+pt[:min(len(pt), 20)], func(t *testing.T) {
			sealed, err := tc.Seal(pt)
			if err != nil {
				t.Fatalf("Seal() error: %v", err)
			}
			if sealed == "" {
				t.Fatal("Seal() returned empty string for non-empty plaintext")
			}
			if sealed == pt {
				t.Error("Seal() returned plaintext unchanged")
			}

			opened, err := tc.Open(sealed)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			if opened != pt {
				t.Errorf("Open() = %q, want %q", opened, pt)
			}
		})
	}
}

func TestSealEmptyString(t *testing.T) {
	tc, _ := NewTokenCipher(testKey())

	sealed, err := tc.Seal("")
	if err != nil {
		t.Fatalf("Seal(\"\") error: %v", err)
	}
	if sealed != "" {
		t.Errorf("Seal(\"\") = %q, want empty string", sealed)
	}

	opened, err := tc.Open("")
	if err != nil {
		t.Fatalf("Open(\"\") error: %v", err)
	}
	if opened != "" {
		t.Errorf("Open(\"\") = %q, want empty string", opened)
	}
}

func TestSealNonDeterministic(t *testing.T) {
	// Each call to Seal should produce a different ciphertext (random nonce).
	tc, _ := NewTokenCipher(testKey())
	pt := "same-plaintext"

	s1, _ := tc.Seal(pt)
	s2, _ := tc.Seal(pt)
	if s1 == s2 {
		t.Error("Seal() produced identical ciphertexts; nonce is not random")
	}
}

func TestOpenErrors(t *testing.T) {
	tc, _ := NewTokenCipher(testKey())

	tests := []struct {
		name       string
		ciphertext string
		wantErr    error
	}{
		{"not base64", "!!!not-base64!!!", ErrCiphertextCorrupted},
		{"too short after decode", "YQ==", ErrCiphertextCorrupted}, // decodes to 1 byte, shorter than nonce
		{"random base64 garbage", "dGhpcyBpcyBub3QgYSB2YWxpZCBjaXBoZXJ0ZXh0", ErrDecryptionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tc.Open(tt.ciphertext)
			if err != tt.wantErr {
				t.Errorf("Open(%q) error = %v, want %v", tt.ciphertext, err, tt.wantErr)
			}
		})
	}
}

func TestOpenWrongKey(t *testing.T) {
	key1 := bytes.Repeat([]byte("a"), 32)
	key2 := bytes.Repeat([]byte("b"), 32)

	tc1, _ := NewTokenCipher(key1)
	tc2, _ := NewTokenCipher(key2)

	sealed, err := tc1.Seal("secret-data")
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	_, err = tc2.Open(sealed)
	if err != ErrDecryptionFailed {
		t.Errorf("Open() with wrong key error = %v, want %v", err, ErrDecryptionFailed)
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("GenerateKey() len = %d, want 32", len(key))
	}

	// Two calls should produce different keys
	key2, _ := GenerateKey()
	if bytes.Equal(key, key2) {
		t.Error("GenerateKey() produced identical keys on consecutive calls")
	}

	// Generated key must be usable with NewTokenCipher
	if _, err := NewTokenCipher(key); err != nil {
		t.Errorf("NewTokenCipher(GenerateKey()) error: %v", err)
	}
}

func TestGenerateSalt(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantLen int
	}{
		{"default minimum", 0, 16},
		{"below minimum", 8, 16},
		{"exact minimum", 16, 16},
		{"custom length", 32, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt, err := GenerateSalt(tt.length)
			if err != nil {
				t.Fatalf("GenerateSalt(%d) error: %v", tt.length, err)
			}
			if len(salt) != tt.wantLen {
				t.Errorf("GenerateSalt(%d) len = %d, want %d", tt.length, len(salt), tt.wantLen)
			}
		})
	}

	// Two salts must differ
	s1, _ := GenerateSalt(16)
	s2, _ := GenerateSalt(16)
	if bytes.Equal(s1, s2) {
		t.Error("GenerateSalt() produced identical salts on consecutive calls")
	}
}

