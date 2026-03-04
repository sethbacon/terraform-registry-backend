// Package main is a smoke-test utility that verifies the registry's HTTP API
// is reachable and returning valid responses. It issues a real HTTP request to
// a known module versions endpoint and prints the status code and response body,
// making it useful for quick post-deployment checks without needing external
// tooling like curl or a full integration test suite.
package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {
	resp, err := http.Get("http://localhost:8080/v1/modules/bconline/vpc/aws/versions")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading body: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response:\n%s\n", string(body))
}
