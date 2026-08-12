// remotebody_test.go pins where an upstream SCM response body is allowed to travel.
//
// APIError.Error() is what handlers reach for when they format a connector failure into a
// JSON response — several do it with fmt.Sprintf("...: %v", err), and the OAuth callback that
// used to do it is reachable unauthenticated. So the provider's raw token-endpoint body must
// not be inside Error(). It still has to reach the operator, or a misconfigured app
// registration becomes undiagnosable, which is what RemoteBody and LogValue are for.
package scm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAPIError_ErrorTextExcludesRemoteBody(t *testing.T) {
	const secretish = "upstream-internal-diagnostic"

	apiErr := &APIError{
		StatusCode: http.StatusBadRequest,
		Message:    "oauth code exchange failed",
		Err:        errors.New("wrapped cause"),
		RemoteBody: secretish,
	}

	if strings.Contains(apiErr.Error(), secretish) {
		t.Errorf("Error() = %q, must not embed the upstream response body", apiErr.Error())
	}
	// Handlers format errors with %v as often as with .Error(); both go through Error().
	if got := fmt.Sprintf("%v", error(apiErr)); strings.Contains(got, secretish) {
		t.Errorf("%%v formatting = %q, must not embed the upstream response body", got)
	}
	if !strings.Contains(apiErr.Error(), "oauth code exchange failed") {
		t.Errorf("Error() = %q, want it to keep the operator-facing message", apiErr.Error())
	}
}

// TestAPIError_LogValueCarriesRemoteBody is the other half of the contract: the body has to
// stay diagnosable server-side. slog resolves LogValue when the error is logged as an attr,
// so `slog.Error("...", "error", err)` still records the provider's failure reason.
func TestAPIError_LogValueCarriesRemoteBody(t *testing.T) {
	apiErr := &APIError{
		StatusCode: http.StatusBadRequest,
		Message:    "oauth code exchange failed",
		RemoteBody: `{"error":"invalid_client"}`,
	}

	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Error("oauth failed", "error", apiErr)

	logged := buf.String()
	for _, want := range []string{"invalid_client", "oauth code exchange failed", "400"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output %q does not contain %q — the upstream failure reason must stay "+
				"diagnosable server-side", logged, want)
		}
	}
}

// TestExchangeOAuthForm_UpstreamBodyIsNotInTheErrorText drives the one helper that reads an
// upstream error body, end to end over a real response.
func TestExchangeOAuthForm_UpstreamBodyIsNotInTheErrorText(t *testing.T) {
	const body = `{"error":"invalid_client","error_description":"internal-app-registration-detail"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	var result struct{}
	err := ExchangeOAuthForm(context.Background(), srv.URL, url.Values{}, "", &result)
	if err == nil {
		t.Fatal("ExchangeOAuthForm error = nil, want an error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want an *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusBadRequest)
	}
	if strings.Contains(err.Error(), "internal-app-registration-detail") {
		t.Errorf("error text %q leaks the provider's token-endpoint response body", err.Error())
	}
	if !strings.Contains(apiErr.RemoteBody, "invalid_client") {
		t.Errorf("RemoteBody = %q, want the provider's failure reason kept for server-side logging",
			apiErr.RemoteBody)
	}
	if len(apiErr.RemoteBody) > MaxErrorBodyBytes {
		t.Errorf("RemoteBody is %d bytes, want it capped at %d", len(apiErr.RemoteBody), MaxErrorBodyBytes)
	}
}

// TestExchangeOAuthForm_RemoteBodyIsSizeCapped keeps the memory bound on the one field that
// now retains upstream bytes.
func TestExchangeOAuthForm_RemoteBodyIsSizeCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("A", MaxErrorBodyBytes*4)))
	}))
	defer srv.Close()

	var result struct{}
	err := ExchangeOAuthForm(context.Background(), srv.URL, url.Values{}, "", &result)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want an *APIError", err, err)
	}
	if len(apiErr.RemoteBody) != MaxErrorBodyBytes {
		t.Errorf("RemoteBody is %d bytes, want it truncated to %d", len(apiErr.RemoteBody), MaxErrorBodyBytes)
	}
}
