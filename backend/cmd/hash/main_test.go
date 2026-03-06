package main

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestReadKey_FromFlag(t *testing.T) {
	got, err := readKey("mykey", strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "mykey" {
		t.Errorf("want 'mykey', got %q", got)
	}
}

func TestReadKey_FromStdin(t *testing.T) {
	got, err := readKey("", strings.NewReader("stdinkey\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "stdinkey" {
		t.Errorf("want 'stdinkey', got %q", got)
	}
}

func TestReadKey_FlagTakesPrecedenceOverStdin(t *testing.T) {
	got, err := readKey("flagkey", strings.NewReader("stdinkey\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "flagkey" {
		t.Errorf("want flag value 'flagkey', got %q", got)
	}
}

func TestReadKey_TrimWhitespace_Flag(t *testing.T) {
	got, err := readKey("  spaced  ", strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "spaced" {
		t.Errorf("want trimmed 'spaced', got %q", got)
	}
}

func TestReadKey_TrimWhitespace_Stdin(t *testing.T) {
	got, err := readKey("", strings.NewReader("  spaced  \n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "spaced" {
		t.Errorf("want trimmed 'spaced', got %q", got)
	}
}

func TestReadKey_EmptyBoth(t *testing.T) {
	_, err := readKey("", strings.NewReader(""))
	if err == nil {
		t.Error("want error when both flag and stdin are empty")
	}
}

func TestReadKey_WhitespaceOnlyFlag(t *testing.T) {
	_, err := readKey("   ", strings.NewReader(""))
	if err == nil {
		t.Error("want error for whitespace-only flag value")
	}
}

func TestReadKey_WhitespaceOnlyStdin(t *testing.T) {
	_, err := readKey("", strings.NewReader("   \n"))
	if err == nil {
		t.Error("want error for whitespace-only stdin")
	}
}

func TestHashRoundtrip(t *testing.T) {
	key := "tfr_testkey_abc123"
	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(key)); err != nil {
		t.Errorf("hash does not verify: %v", err)
	}
}

func TestHashRoundtrip_WrongKey(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	if err := bcrypt.CompareHashAndPassword(hash, []byte("wrong")); err == nil {
		t.Error("expected mismatch error for wrong key")
	}
}
