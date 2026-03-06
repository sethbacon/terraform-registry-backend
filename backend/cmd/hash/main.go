// Package main is a utility for generating bcrypt hashes of API key values.
// The registry stores only bcrypt hashes of API keys — never the raw key
// values — so this tool is used when manually seeding or verifying API key
// records in the database without running the full server.
//
// Usage:
//
//	go run cmd/hash/main.go -key <api-key-value>
//	echo "mykey" | go run cmd/hash/main.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// readKey returns the non-empty, trimmed key to hash.
// flagVal is used when non-empty; otherwise the first line of r is read.
// Returns an error when both sources are blank.
func readKey(flagVal string, r io.Reader) (string, error) {
	key := strings.TrimSpace(flagVal)
	if key == "" {
		scanner := bufio.NewScanner(r)
		if scanner.Scan() {
			key = strings.TrimSpace(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("reading input: %w", err)
		}
	}
	if key == "" {
		return "", fmt.Errorf("no key provided: use -key flag or pipe via stdin")
	}
	return key, nil
}

func main() {
	keyFlag := flag.String("key", "", "API key value to hash (or omit to read from stdin)")
	flag.Parse()

	key, err := readKey(*keyFlag, os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		flag.Usage()
		os.Exit(1)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating hash: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
