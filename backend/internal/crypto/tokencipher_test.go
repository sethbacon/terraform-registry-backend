package crypto

import (
	"bytes"
	"errors"
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
		// MinPBKDF2Iterations rather than a literal: the floor moved from 10,000
		// to 600,000 with the swap onto the shared cipher (#835), and a literal
		// here would need chasing again the next time guidance moves.
		tc, err := DeriveTokenCipher("my-secret-passphrase", salt, MinPBKDF2Iterations)
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

	// This sub-test previously asserted "low iteration count uses secure
	// default" — that a caller passing 1 was silently bumped to 100,000. That
	// was the behaviour suite-identity #153 identified as effectively inverted:
	// the value silently rewritten was the one nobody chose, while an explicit
	// 10,000 was honoured, so the weakest ACCEPTED work factor was reachable
	// only by a caller who had thought about it. The local copy kept that
	// behaviour after it was fixed upstream (#835); the assertions invert with
	// the swap onto the shared implementation.
	t.Run("an explicit iteration count below the floor is rejected", func(t *testing.T) {
		salt := bytes.Repeat([]byte("s"), 16)
		tc, err := DeriveTokenCipher("pass", salt, 1)
		if !errors.Is(err, ErrIterationsTooLow) {
			t.Fatalf("DeriveTokenCipher(..., 1) error = %v, want ErrIterationsTooLow", err)
		}
		if tc != nil {
			t.Error("a rejected derivation must not also return a usable cipher")
		}
	})

	t.Run("no preference uses the secure default", func(t *testing.T) {
		salt := bytes.Repeat([]byte("s"), 16)
		// iterations <= 0 means "no preference" and is the one case that is
		// still filled in rather than rejected — the caller expressed no belief
		// about the work factor, so there is none to leave standing.
		tc, err := DeriveTokenCipher("pass", salt, 0)
		if err != nil {
			t.Fatalf("DeriveTokenCipher(..., 0) error: %v", err)
		}
		if tc == nil {
			t.Fatal("DeriveTokenCipher() returned nil")
		}
	})

	t.Run("different passphrases produce different ciphers", func(t *testing.T) {
		salt := bytes.Repeat([]byte("s"), 16)
		// Was 100000, which is now below the floor: the derivation returned an
		// error and a nil cipher, and the ignored error meant the next line
		// dereferenced nil. Use the floor itself so the test exercises a
		// derivation that is actually allowed.
		tc1, err := DeriveTokenCipher("passphrase-one", salt, MinPBKDF2Iterations)
		if err != nil {
			t.Fatalf("DeriveTokenCipher(one): %v", err)
		}
		tc2, err := DeriveTokenCipher("passphrase-two", salt, MinPBKDF2Iterations)
		if err != nil {
			t.Fatalf("DeriveTokenCipher(two): %v", err)
		}

		sealed, err := tc1.Seal("secret")
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		// tc2 should NOT be able to decrypt what tc1 sealed
		if _, err := tc2.Open(sealed); err == nil {
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

// ---------------------------------------------------------------------------
// Dual-key (key rotation) tests
// ---------------------------------------------------------------------------

func TestNewTokenCipherWithPrevious(t *testing.T) {
	current := bytes.Repeat([]byte("c"), 32)
	previous := bytes.Repeat([]byte("p"), 32)

	t.Run("valid current and previous keys", func(t *testing.T) {
		tc, err := NewTokenCipherWithPrevious(current, previous)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tc == nil {
			t.Fatal("returned nil cipher")
		}
	})

	t.Run("valid current, no previous", func(t *testing.T) {
		tc, err := NewTokenCipherWithPrevious(current, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tc == nil {
			t.Fatal("returned nil cipher")
		}
	})

	t.Run("invalid current key", func(t *testing.T) {
		_, err := NewTokenCipherWithPrevious([]byte("short"), previous)
		if err != ErrKeyLengthInvalid {
			t.Errorf("error = %v, want %v", err, ErrKeyLengthInvalid)
		}
	})

	t.Run("invalid previous key", func(t *testing.T) {
		_, err := NewTokenCipherWithPrevious(current, []byte("short"))
		if err != ErrKeyLengthInvalid {
			t.Errorf("error = %v, want %v", err, ErrKeyLengthInvalid)
		}
	})
}

func TestDualKeyDecryption_CurrentKey(t *testing.T) {
	current := bytes.Repeat([]byte("c"), 32)
	previous := bytes.Repeat([]byte("p"), 32)

	tc, _ := NewTokenCipherWithPrevious(current, previous)

	// Encrypt with the dual-key cipher (uses current key)
	sealed, err := tc.Seal("test-secret")
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	// Decrypt should work with current key
	opened, err := tc.Open(sealed)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if opened != "test-secret" {
		t.Errorf("Open() = %q, want %q", opened, "test-secret")
	}
}

func TestDualKeyDecryption_PreviousKey(t *testing.T) {
	oldKey := bytes.Repeat([]byte("o"), 32)
	newKey := bytes.Repeat([]byte("n"), 32)

	// Encrypt with the old key (before rotation)
	oldCipher, _ := NewTokenCipher(oldKey)
	sealed, err := oldCipher.Seal("rotated-secret")
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	// Create a dual-key cipher with new=current, old=previous
	dualCipher, _ := NewTokenCipherWithPrevious(newKey, oldKey)

	// Decrypt should fall back to old key
	opened, err := dualCipher.Open(sealed)
	if err != nil {
		t.Fatalf("Open() with previous key error: %v", err)
	}
	if opened != "rotated-secret" {
		t.Errorf("Open() = %q, want %q", opened, "rotated-secret")
	}
}

func TestDualKeyDecryption_BothKeysFail(t *testing.T) {
	keyA := bytes.Repeat([]byte("a"), 32)
	keyB := bytes.Repeat([]byte("b"), 32)
	keyC := bytes.Repeat([]byte("c"), 32)

	// Encrypt with keyC (neither current nor previous)
	cipherC, _ := NewTokenCipher(keyC)
	sealed, _ := cipherC.Seal("unreachable")

	// Dual cipher with A=current, B=previous
	dual, _ := NewTokenCipherWithPrevious(keyA, keyB)

	_, err := dual.Open(sealed)
	if err != ErrDecryptionFailed {
		t.Errorf("Open() error = %v, want %v", err, ErrDecryptionFailed)
	}
}

func TestDualKeyDecryption_NoPreviousKeyFallback(t *testing.T) {
	oldKey := bytes.Repeat([]byte("o"), 32)
	newKey := bytes.Repeat([]byte("n"), 32)

	// Encrypt with old key
	oldCipher, _ := NewTokenCipher(oldKey)
	sealed, _ := oldCipher.Seal("needs-old-key")

	// Dual cipher with no previous key set
	noPrevCipher, _ := NewTokenCipherWithPrevious(newKey, nil)

	_, err := noPrevCipher.Open(sealed)
	if err != ErrDecryptionFailed {
		t.Errorf("Open() without previous key error = %v, want %v", err, ErrDecryptionFailed)
	}
}
