package crypto

import (
	"strings"
	"testing"
)

func TestEstimateShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantMin float64
		wantMax float64
	}{
		{"empty", []byte{}, 0, 0},
		{"single repeated byte", []byte(strings.Repeat("k", 32)), 0, 0},
		{"two alternating bytes", []byte(strings.Repeat("ab", 16)), 0.9, 1.1},
		{"32 random-looking hex chars", []byte("3f7a9c1e5b2d8046f1a7c3e9b5d2084f"), 3.5, 4.1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EstimateShannonEntropy(tt.data)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("EstimateShannonEntropy(%q) = %v, want in [%v, %v]", tt.data, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestIsLikelyLowEntropySecret(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"repeated char key (low entropy)", []byte(strings.Repeat("k", 32)), true},
		{"repeated word passphrase (low entropy)", []byte(strings.Repeat("password", 4)), true},
		{"random-looking hex key (high entropy)", []byte("3f7a9c1e5b2d8046f1a7c3e9b5d2084f"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLikelyLowEntropySecret(tt.data); got != tt.want {
				t.Errorf("IsLikelyLowEntropySecret(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}
