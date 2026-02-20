// Package main is a utility for generating bcrypt hashes of API key values.
// The registry stores only bcrypt hashes of API keys — never the raw key
// values — so this tool is used when manually seeding or verifying API key
// records in the database without running the full server. Running it locally
// produces a hash that can be inserted directly into the api_keys table.
package main

import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
)

func main() {
    key := "dev_qHlTX4JvjK1yVUgRukLlgiwFQmFOiHdEhHYVJNfhNXc"
    hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(hash))
}