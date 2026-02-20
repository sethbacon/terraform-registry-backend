// Package main is a development utility for generating a test API key with its bcrypt hash
// and display prefix pre-computed. It prints the raw key, hash, prefix, and a ready-to-run
// SQL UPDATE statement so developers can quickly seed a usable API key in a local database
// without running the full server flow. Do not use generated keys in production — use the
// admin UI or API to create keys with proper expiry and scope settings.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Generate random bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Encode to base64
	randomPart := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Create full key
	prefix := "dev"
	fullKey := fmt.Sprintf("%s_%s", prefix, randomPart)

	// Hash with bcrypt
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(fullKey), 10)
	if err != nil {
		log.Fatal(err)
	}

	// Display prefix
	displayPrefix := fullKey[:10]

	fmt.Println("==========================================================")
	fmt.Println("API Key Generated")
	fmt.Println("==========================================================")
	fmt.Printf("\nFull Key: %s\n", fullKey)
	fmt.Printf("\nHash: %s\n", string(hashBytes))
	fmt.Printf("\nDisplay Prefix: %s\n", displayPrefix)
	fmt.Println("\n==========================================================")
	fmt.Println("SQL Update:")
	fmt.Println("==========================================================")
	fmt.Printf(`
UPDATE api_keys 
SET key_hash = '%s',
    key_prefix = '%s'
WHERE user_id = (SELECT id FROM users WHERE email = 'admin@dev.local');
`, string(hashBytes), displayPrefix)
	fmt.Println("\n==========================================================")
	fmt.Printf("Authorization Header: Bearer %s\n", fullKey)
	fmt.Println("==========================================================")
}
