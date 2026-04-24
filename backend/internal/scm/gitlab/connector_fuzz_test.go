package gitlab

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

var fuzzConnector = func() *GitLabConnector {
	c, _ := NewGitLabConnector(&scm.ConnectorSettings{
		ClientID:     "fuzz-client",
		ClientSecret: "fuzz-secret",
		CallbackURL:  "http://localhost/callback",
	})
	return c
}()

// FuzzParseDelivery exercises the GitLab webhook payload parser against arbitrary
// bytes. Must never panic.
func FuzzParseDelivery(f *testing.F) {
	f.Add(
		[]byte(`{"object_kind":"tag_push","ref":"refs/tags/v1.0.0","project":{"path_with_namespace":"org/repo","http_url":"https://gitlab.com/org/repo.git","web_url":"https://gitlab.com/org/repo"}}`),
		"Tag Push Hook",
		"fuzz-secret",
	)
	f.Add([]byte(`{"object_kind":"push"}`), "Push Hook", "")
	f.Add([]byte{}, "Push Hook", "")
	f.Add([]byte(`not json`), "Tag Push Hook", "sig")
	f.Add([]byte(`{"object_kind":null}`), "Tag Push Hook", "")

	f.Fuzz(func(t *testing.T, payload []byte, event string, token string) {
		headers := map[string]string{
			"X-Gitlab-Event": event,
			"X-Gitlab-Token": token,
		}
		_, _ = fuzzConnector.ParseDelivery(payload, headers)
	})
}
