package azuredevops

import (
	"testing"
)

var fuzzConnector = &AzureDevOpsConnector{
	clientID:     "fuzz-client",
	clientSecret: "fuzz-secret",
	callbackURL:  "http://localhost/callback",
	baseURL:      "https://dev.azure.com",
	tenantID:     "fuzz-tenant",
	organization: "fuzzorg",
}

// FuzzParseDelivery exercises the Azure DevOps webhook payload parser against
// arbitrary bytes. Must never panic.
func FuzzParseDelivery(f *testing.F) {
	f.Add(
		[]byte(`{"eventType":"git.push","resource":{"refUpdates":[{"name":"refs/tags/v1.0.0","newObjectId":"abc123","oldObjectId":"0000000000000000000000000000000000000000"}],"repository":{"remoteUrl":"https://dev.azure.com/fuzzorg/proj/_git/repo","webUrl":"https://dev.azure.com/fuzzorg/proj/_git/repo"}}}`),
		"",
		"",
	)
	f.Add([]byte(`{"eventType":"git.push","resource":{}}`), "", "")
	f.Add([]byte{}, "", "")
	f.Add([]byte(`not json`), "tok", "sig")
	f.Add([]byte(`{"eventType":null}`), "", "")

	f.Fuzz(func(t *testing.T, payload []byte, token string, sig string) {
		headers := map[string]string{
			"Authorization":       token,
			"X-Hub-Signature-256": sig,
		}
		_, _ = fuzzConnector.ParseDelivery(payload, headers)
	})
}
