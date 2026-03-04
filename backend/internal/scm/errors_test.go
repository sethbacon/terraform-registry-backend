package scm

import (
	"errors"
	"fmt"
	"testing"
)

func TestNewAPIError(t *testing.T) {
	t.Run("stores all fields", func(t *testing.T) {
		wrapped := fmt.Errorf("upstream failure")
		e := NewAPIError(404, "not found", wrapped)
		if e.StatusCode != 404 {
			t.Errorf("StatusCode = %d, want 404", e.StatusCode)
		}
		if e.Message != "not found" {
			t.Errorf("Message = %q, want %q", e.Message, "not found")
		}
		if e.Err != wrapped {
			t.Errorf("Err = %v, want %v", e.Err, wrapped)
		}
	})

	t.Run("nil inner error is accepted", func(t *testing.T) {
		e := NewAPIError(500, "internal error", nil)
		if e.Err != nil {
			t.Errorf("Err = %v, want nil", e.Err)
		}
	})
}

func TestAPIErrorError(t *testing.T) {
	t.Run("with inner error includes both messages", func(t *testing.T) {
		inner := fmt.Errorf("connection refused")
		e := NewAPIError(503, "service unavailable", inner)
		msg := e.Error()
		if msg != "service unavailable: connection refused" {
			t.Errorf("Error() = %q, want %q", msg, "service unavailable: connection refused")
		}
	})

	t.Run("without inner error returns message only", func(t *testing.T) {
		e := NewAPIError(400, "bad request", nil)
		if e.Error() != "bad request" {
			t.Errorf("Error() = %q, want %q", e.Error(), "bad request")
		}
	})
}

func TestAPIErrorUnwrap(t *testing.T) {
	t.Run("unwraps inner error", func(t *testing.T) {
		inner := fmt.Errorf("inner cause")
		e := NewAPIError(500, "msg", inner)
		if e.Unwrap() != inner {
			t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), inner)
		}
	})

	t.Run("nil inner error unwraps to nil", func(t *testing.T) {
		e := NewAPIError(500, "msg", nil)
		if e.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", e.Unwrap())
		}
	})

	t.Run("errors.Is works through APIError", func(t *testing.T) {
		sentinel := errors.New("sentinel")
		e := NewAPIError(403, "forbidden", sentinel)
		if !errors.Is(e, sentinel) {
			t.Error("errors.Is(apiErr, sentinel) = false, want true")
		}
	})
}

func TestWrapRemoteError(t *testing.T) {
	// WrapRemoteError must be identical to NewAPIError
	inner := fmt.Errorf("some cause")
	via := WrapRemoteError(422, "unprocessable", inner)
	direct := NewAPIError(422, "unprocessable", inner)

	if via.StatusCode != direct.StatusCode {
		t.Errorf("WrapRemoteError StatusCode = %d, want %d", via.StatusCode, direct.StatusCode)
	}
	if via.Message != direct.Message {
		t.Errorf("WrapRemoteError Message = %q, want %q", via.Message, direct.Message)
	}
	if via.Err != direct.Err {
		t.Errorf("WrapRemoteError Err = %v, want %v", via.Err, direct.Err)
	}
}

// Verify error sentinel values are distinct (no two variables point to the same error).
func TestErrorSentinelsAreDistinct(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrInvalidProviderType", ErrInvalidProviderType},
		{"ErrMissingClientID", ErrMissingClientID},
		{"ErrMissingClientSecret", ErrMissingClientSecret},
		{"ErrMissingRedirectURL", ErrMissingRedirectURL},
		{"ErrProviderNotSupported", ErrProviderNotSupported},
		{"ErrPATRequired", ErrPATRequired},
		{"ErrOAuthCodeExchange", ErrOAuthCodeExchange},
		{"ErrOAuthTokenRefresh", ErrOAuthTokenRefresh},
		{"ErrOAuthTokenExpired", ErrOAuthTokenExpired},
		{"ErrOAuthTokenInvalid", ErrOAuthTokenInvalid},
		{"ErrRepositoryNotFound", ErrRepositoryNotFound},
		{"ErrRepositoryForbidden", ErrRepositoryForbidden},
		{"ErrWebhookSignatureInvalid", ErrWebhookSignatureInvalid},
		{"ErrVersionAlreadyExists", ErrVersionAlreadyExists},
		{"ErrRateLimitExceeded", ErrRateLimitExceeded},
	}

	seen := make(map[error]string)
	for _, s := range sentinels {
		if prev, ok := seen[s.err]; ok {
			t.Errorf("duplicate sentinel: %s and %s share the same error value", s.name, prev)
		}
		seen[s.err] = s.name
	}
}

// Verify that aliased errors actually equal their originals (errors.Is).
func TestErrorAliasesMatchOriginals(t *testing.T) {
	pairs := []struct {
		alias, original error
	}{
		{ErrUnknownProviderKind, ErrInvalidProviderType},
		{ErrClientIDRequired, ErrMissingClientID},
		{ErrClientSecretRequired, ErrMissingClientSecret},
		{ErrCallbackURLRequired, ErrMissingRedirectURL},
		{ErrConnectorUnavailable, ErrProviderNotSupported},
		{ErrPATAuthNeeded, ErrPATRequired},
		{ErrAuthCodeExchangeFailed, ErrOAuthCodeExchange},
		{ErrTokenRefreshFailed, ErrOAuthTokenRefresh},
		{ErrTokenExpired, ErrOAuthTokenExpired},
		{ErrTokenInvalid, ErrOAuthTokenInvalid},
		{ErrRepoNotFound, ErrRepositoryNotFound},
		{ErrRepoAccessDenied, ErrRepositoryForbidden},
		{ErrWebhookSetupFailed, ErrWebhookCreationFailed},
		{ErrWebhookSignatureBad, ErrWebhookSignatureInvalid},
		{ErrVersionCommitConflict, ErrVersionAlreadyExists},
		{ErrTagMovedFromOriginal, ErrTagMovementDetected},
		{ErrCommitMismatch, ErrCommitSHAMismatch},
		{ErrAPIRateLimited, ErrRateLimitExceeded},
	}

	for _, p := range pairs {
		if p.alias != p.original {
			t.Errorf("alias %v != original %v", p.alias, p.original)
		}
	}
}
