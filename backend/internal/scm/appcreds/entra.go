// entra.go mints Azure DevOps access tokens from a Microsoft Entra app
// registration via the OAuth 2.0 client-credentials grant. This is the headless,
// app-owned alternative to per-user OAuth: no user, no refresh token (the grant
// simply re-mints), and the token is cached until shortly before expiry.
package appcreds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// azureDevOpsResourceID is the fixed Microsoft Entra resource (application) id
// for Azure DevOps. Requesting "<id>/.default" yields a token carrying whatever
// ADO permissions the app registration has been granted.
const azureDevOpsResourceID = "499b84ac-1321-427f-aa17-267ca6975798"

// EntraCreds is a Microsoft Entra app registration used to mint Azure DevOps
// access tokens via client-credentials.
type EntraCreds struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// mintEntraToken performs the client-credentials POST against the tenant's v2.0
// token endpoint and returns the access token and its absolute expiry.
func (m *Minter) mintEntraToken(ctx context.Context, creds EntraCreds) (string, time.Time, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", creds.ClientID)
	form.Set("client_secret", creds.ClientSecret)
	form.Set("scope", azureDevOpsResourceID+"/.default")

	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token",
		strings.TrimRight(m.entraLoginBaseURL, "/"), url.PathEscape(creds.TenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("entra token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusOK {
		// Entra returns AADSTS error codes in the body; surface a trimmed form.
		return "", time.Time{}, fmt.Errorf("entra token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("entra token response not JSON: %w", err)
	}
	if out.AccessToken == "" {
		return "", time.Time{}, errors.New("entra token response had no access_token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour // Entra default; defensive when expires_in is absent
	}
	return out.AccessToken, m.now().Add(ttl), nil
}
