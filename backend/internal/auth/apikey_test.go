package auth

import (
	"strings"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	t.Run("returns three non-empty values", func(t *testing.T) {
		key, hash, prefix, err := GenerateAPIKey("tfr")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if key == "" {
			t.Error("GenerateAPIKey() returned empty key")
		}
		if hash == "" {
			t.Error("GenerateAPIKey() returned empty hash")
		}
		if prefix == "" {
			t.Error("GenerateAPIKey() returned empty displayPrefix")
		}
	})

	t.Run("key starts with prefix_", func(t *testing.T) {
		key, _, _, err := GenerateAPIKey("tfr")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if !strings.HasPrefix(key, "tfr_") {
			t.Errorf("GenerateAPIKey() key = %q, want prefix %q", key, "tfr_")
		}
	})

	t.Run("display prefix matches key start", func(t *testing.T) {
		key, _, displayPrefix, err := GenerateAPIKey("tfr")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if !strings.HasPrefix(key, displayPrefix) {
			t.Errorf("key %q does not start with displayPrefix %q", key, displayPrefix)
		}
	})

	t.Run("display prefix length is capped at DisplayPrefixLength", func(t *testing.T) {
		_, _, displayPrefix, err := GenerateAPIKey("tfr")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if len(displayPrefix) > DisplayPrefixLength {
			t.Errorf("displayPrefix len = %d, want <= %d", len(displayPrefix), DisplayPrefixLength)
		}
	})

	t.Run("two calls produce different keys", func(t *testing.T) {
		key1, _, _, _ := GenerateAPIKey("tfr")
		key2, _, _, _ := GenerateAPIKey("tfr")
		if key1 == key2 {
			t.Error("GenerateAPIKey() produced identical keys on consecutive calls")
		}
	})

	t.Run("custom prefix is preserved", func(t *testing.T) {
		key, _, _, err := GenerateAPIKey("myapp")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if !strings.HasPrefix(key, "myapp_") {
			t.Errorf("GenerateAPIKey() key = %q, want prefix %q", key, "myapp_")
		}
	})

	t.Run("empty prefix produces key starting with _", func(t *testing.T) {
		key, _, _, err := GenerateAPIKey("")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if !strings.HasPrefix(key, "_") {
			t.Errorf("GenerateAPIKey() key = %q, want prefix %q", key, "_")
		}
	})
}

func TestValidateAPIKey(t *testing.T) {
	t.Run("correct key validates", func(t *testing.T) {
		key, hash, _, err := GenerateAPIKey("tfr")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if !ValidateAPIKey(key, hash) {
			t.Error("ValidateAPIKey() returned false for correct key")
		}
	})

	t.Run("wrong key does not validate", func(t *testing.T) {
		_, hash, _, err := GenerateAPIKey("tfr")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if ValidateAPIKey("tfr_wrongkey", hash) {
			t.Error("ValidateAPIKey() returned true for wrong key")
		}
	})

	t.Run("empty provided key does not validate", func(t *testing.T) {
		_, hash, _, err := GenerateAPIKey("tfr")
		if err != nil {
			t.Fatalf("GenerateAPIKey() error: %v", err)
		}
		if ValidateAPIKey("", hash) {
			t.Error("ValidateAPIKey() returned true for empty key")
		}
	})

	t.Run("empty hash does not validate", func(t *testing.T) {
		if ValidateAPIKey("some-key", "") {
			t.Error("ValidateAPIKey() returned true for empty hash")
		}
	})

	t.Run("different key from same prefix does not validate", func(t *testing.T) {
		key1, hash1, _, _ := GenerateAPIKey("tfr")
		key2, _, _, _ := GenerateAPIKey("tfr")
		if key1 == key2 {
			t.Skip("generated identical keys, skipping")
		}
		if ValidateAPIKey(key2, hash1) {
			t.Error("ValidateAPIKey() returned true for a key from a different generation")
		}
	})
}

func TestExtractAPIKeyFromHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{"valid bearer token", "Bearer tfr_abc123xyz", "tfr_abc123xyz", false},
		{"bearer with extra spaces", "Bearer  tfr_abc123 ", "tfr_abc123", false},
		{"empty header", "", "", true},
		{"missing Bearer prefix", "tfr_abc123", "", true},
		{"Basic auth scheme", "Basic dXNlcjpwYXNz", "", true},
		{"Bearer with no key", "Bearer ", "", true},
		{"Bearer with only spaces", "Bearer    ", "", true},
		{"lowercase bearer rejected", "bearer tfr_abc123", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractAPIKeyFromHeader(tt.header)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractAPIKeyFromHeader(%q) error = %v, wantErr %v", tt.header, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ExtractAPIKeyFromHeader(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}
