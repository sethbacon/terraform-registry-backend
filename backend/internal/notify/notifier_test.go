package notify

import (
	"errors"
	"fmt"
	neturl "net/url"
	"strings"
	"testing"
)

// TestRedactURLError_StripsCapabilityURL is the regression test for the
// secret-leak finding: a webhook/Slack/Teams channel target is a
// capability-bearing URL that is encrypted at rest and never returned by the
// API. http.Client.Do returns a *url.Error whose Error() embeds the full
// request URL, so surfacing it verbatim in last_error (which the admin API
// returns) would leak the secret. redactURLError must drop the URL and keep
// only the underlying transport error.
func TestRedactURLError_StripsCapabilityURL(t *testing.T) {
	// A stand-in for a capability-bearing webhook URL. Deliberately uses a
	// non-routable example host (not a real provider pattern) so it is not
	// flagged by secret scanners — redactURLError is host-agnostic, so this
	// still exercises the redaction faithfully.
	secret := "https://hooks.example.com/services/team-id/channel-id/token-placeholder"
	inner := errors.New("dial tcp 203.0.113.5:443: connect: connection refused")
	urlErr := &neturl.Error{Op: "Post", URL: secret, Err: inner}

	// Sanity: the raw *url.Error DOES contain the secret (that's the bug).
	if !strings.Contains(urlErr.Error(), secret) {
		t.Fatalf("precondition failed: *url.Error should embed the URL, got %q", urlErr.Error())
	}

	redacted := redactURLError(urlErr)
	if strings.Contains(redacted.Error(), secret) {
		t.Errorf("redactURLError leaked the capability URL: %q", redacted.Error())
	}
	if redacted.Error() != inner.Error() {
		t.Errorf("redactURLError = %q, want underlying error %q", redacted.Error(), inner.Error())
	}

	// The wrapped "send: %w" form the caller uses must also stay clean.
	wrapped := fmt.Errorf("send: %w", redacted)
	if strings.Contains(wrapped.Error(), secret) {
		t.Errorf("wrapped send error leaked the capability URL: %q", wrapped.Error())
	}
}

// TestRedactURLError_NonURLErrorPassthrough verifies a non-*url.Error is
// returned unchanged (no information is lost for errors that never carried a URL).
func TestRedactURLError_NonURLErrorPassthrough(t *testing.T) {
	plain := errors.New("marshal payload: boom")
	if got := redactURLError(plain); got != plain {
		t.Errorf("redactURLError(non-url error) = %v, want the same error unchanged", got)
	}
}

// TestRedactURLError_NilInnerPassthrough verifies a *url.Error with no wrapped
// cause is returned unchanged rather than collapsing to nil.
func TestRedactURLError_NilInnerPassthrough(t *testing.T) {
	urlErr := &neturl.Error{Op: "Post", URL: "https://example.com/x", Err: nil}
	got := redactURLError(urlErr)
	if got != error(urlErr) {
		t.Errorf("redactURLError(url error with nil Err) = %v, want the original error", got)
	}
}
