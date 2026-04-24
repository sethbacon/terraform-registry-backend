package bitbucket

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

var fuzzConnector = func() *BitbucketDCConnector {
	c, _ := NewBitbucketDCConnector(&scm.ConnectorSettings{
		InstanceBaseURL: "https://bitbucket.example.com",
	})
	return c
}()

// FuzzParseDelivery exercises the Bitbucket Data Center webhook payload parser
// against arbitrary bytes. Must never panic.
func FuzzParseDelivery(f *testing.F) {
	f.Add(
		[]byte(`{"changes":[{"ref":{"id":"refs/tags/v1.0.0","type":"TAG"},"toHash":"abc123"}],"repository":{"slug":"repo","links":{"clone":[{"href":"https://bitbucket.example.com/scm/proj/repo.git","name":"http"}],"self":[{"href":"https://bitbucket.example.com/projects/PROJ/repos/repo/browse"}]},"project":{"key":"PROJ"}}}`),
		"repo:refs_changed",
		"",
		"sha256=abc",
	)
	f.Add([]byte(`{"changes":[]}`), "repo:refs_changed", "", "")
	f.Add([]byte{}, "repo:refs_changed", "", "")
	f.Add([]byte(`not json`), "repo:refs_changed", "tok", "sig")
	f.Add([]byte(`null`), "repo:refs_changed", "", "")

	f.Fuzz(func(t *testing.T, payload []byte, event string, token string, sig string) {
		headers := map[string]string{
			"X-Event-Key":       event,
			"X-Hub-Signature":   sig,
			"X-Atlassian-Token": token,
		}
		_, _ = fuzzConnector.ParseDelivery(payload, headers)
	})
}
