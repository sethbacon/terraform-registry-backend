package github

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// connector used for all fuzz targets in this package.
var fuzzConnector = func() *GitHubConnector {
	c, _ := NewGitHubConnector(&scm.ConnectorSettings{
		ClientID:     "fuzz-client",
		ClientSecret: "fuzz-secret",
		CallbackURL:  "http://localhost/callback",
	})
	return c
}()

// FuzzParseDelivery exercises the GitHub webhook payload parser against arbitrary
// bytes. The parser processes untrusted network input, making it a high-priority
// fuzz target. It must never panic regardless of input.
func FuzzParseDelivery(f *testing.F) {
	// Seed with a minimal push-event payload.
	f.Add(
		[]byte(`{"ref":"refs/tags/v1.0.0","repository":{"full_name":"org/repo","clone_url":"https://github.com/org/repo.git","html_url":"https://github.com/org/repo"}}`),
		"push",
		"sha256=abc123",
	)
	// Seed with a ping event.
	f.Add([]byte(`{"zen":"Keep it logically awesome","hook_id":1}`), "ping", "")
	// Seed with empty payload.
	f.Add([]byte{}, "push", "")
	// Seed with garbage.
	f.Add([]byte(`not json`), "push", "sha256=deadbeef")
	// Seed with deeply nested JSON (should not stack-overflow).
	f.Add([]byte(`{"a":{"b":{"c":{"d":{"e":{}}}}}}`), "push", "")

	f.Fuzz(func(t *testing.T, payload []byte, event string, sig string) {
		headers := map[string]string{
			"X-GitHub-Event":      event,
			"X-Hub-Signature-256": sig,
		}
		// Must not panic; errors are acceptable.
		_, _ = fuzzConnector.ParseDelivery(payload, headers)
	})
}
