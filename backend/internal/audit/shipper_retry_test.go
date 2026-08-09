package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// Issue #756 — the audit webhook made exactly one delivery attempt.
//
// flushBatch called sendRequest once and then ran `ws.batch = ws.batch[:0]`
// unconditionally, so a network blip, a SIEM restart or a transient 5xx
// discarded the batch with a single log line. The codebase already implements a
// full retry/backoff state machine for the conceptually similar SCM webhook
// path (internal/jobs/webhook_retry_job.go); the audit shipper — whose package
// doc says these records "may be subject to compliance retention policies
// measured in years" — had none.
//
// Impact is bounded because AuditMiddleware persists the row to the database
// alongside shipping, so this is external-SIEM visibility rather than audit
// trail loss. That bound is also why the retry is modest: a long or aggressive
// policy would trade a visibility gap for unbounded memory in the batch path.

// retryTestShipper builds a shipper pointed at srv with batching disabled, so
// Ship exercises the direct delivery path synchronously.
func retryTestShipper(t *testing.T, url string) *WebhookShipper {
	t.Helper()
	// The egress guard denies loopback by default (SSRF protection), so an
	// httptest server is unreachable without allowlisting it. Without this the
	// request never leaves and every assertion below reads "attempts = 0" —
	// which looks like a retry bug and is actually the guard doing its job.
	ws, err := NewWebhookShipperWithGuard(&WebhookConfig{
		URL:     url,
		Timeout: 2 * time.Second,
	}, httpsafe.MustGuard("127.0.0.1", "::1"))
	if err != nil {
		t.Fatalf("NewWebhookShipper: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

func TestWebhookShipper_RetriesTransientFailureAndSucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail twice with a transient status, then accept — the SIEM-restart
		// shape this retry exists for.
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := retryTestShipper(t, srv.URL)
	if err := ws.Ship(context.Background(), &LogEntry{Action: "test"}); err != nil {
		t.Fatalf("Ship: %v, want success on the third attempt", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3 — with a single attempt this entry is lost", got)
	}
}

// TestWebhookShipper_DoesNotRetryAClientError is the half that keeps the retry
// from making things worse.
//
// A 400 is the shipper's own fault — malformed payload, bad URL, rejected
// credential — and fails identically every time. Retrying only delays the batch
// and multiplies load on a SIEM that is already rejecting us.
func TestWebhookShipper_DoesNotRetryAClientError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	ws := retryTestShipper(t, srv.URL)
	if err := ws.Ship(context.Background(), &LogEntry{Action: "test"}); err == nil {
		t.Fatal("Ship succeeded against a 400")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts = %d, want 1 — a 4xx must not be retried", got)
	}
}

// TestWebhookShipper_Retries429 — the one 4xx that means "later".
func TestWebhookShipper_Retries429(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := retryTestShipper(t, srv.URL)
	if err := ws.Ship(context.Background(), &LogEntry{Action: "test"}); err != nil {
		t.Fatalf("Ship: %v, want a retry after 429", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestWebhookShipper_GivesUpAfterMaxAttempts(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ws := retryTestShipper(t, srv.URL)
	err := ws.Ship(context.Background(), &LogEntry{Action: "test"})
	if err == nil {
		t.Fatal("Ship succeeded against a server that always fails")
	}
	if got := atomic.LoadInt32(&attempts); got != auditWebhookMaxAttempts {
		t.Errorf("attempts = %d, want %d — the retry must be bounded, not indefinite",
			got, auditWebhookMaxAttempts)
	}
}

// TestWebhookShipper_StopsRetryingOnContextCancellation — shutdown must not
// wait out the backoff.
func TestWebhookShipper_StopsRetryingOnContextCancellation(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ws := retryTestShipper(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = ws.Ship(ctx, &LogEntry{Action: "test"})
		close(done)
	}()

	// Cancel while it is backing off between attempts, and measure how long it
	// takes to notice.
	//
	// Counting server-side attempts CANNOT detect this: once the parent context
	// is cancelled, every derived per-attempt context is already dead, so no
	// further request reaches the server whether the backoff selects on ctx or
	// just sleeps. The observable difference is time — a sleeping backoff burns
	// the remaining ~700ms of its schedule before returning. Verified: the
	// attempt-count assertion passed with the select replaced by time.Sleep.
	time.Sleep(50 * time.Millisecond)
	cancel()
	cancelledAt := time.Now()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Ship kept retrying after its context was cancelled")
	}

	if elapsed := time.Since(cancelledAt); elapsed > 150*time.Millisecond {
		t.Errorf("Ship took %v to return after cancellation; the backoff must abort on "+
			"ctx.Done() rather than sleep through it (shutdown waits on this)", elapsed)
	}
}

// TestWebhookRetryPolicy_IsBounded pins the constants. A retry budget large
// enough to hold a batch indefinitely is the failure this replaces.
func TestWebhookRetryPolicy_IsBounded(t *testing.T) {
	if auditWebhookMaxAttempts < 2 {
		t.Errorf("auditWebhookMaxAttempts = %d, which is not a retry", auditWebhookMaxAttempts)
	}
	if auditWebhookMaxAttempts > 5 {
		t.Errorf("auditWebhookMaxAttempts = %d; the database row is the durable record, "+
			"so this should not hold a batch in memory for long", auditWebhookMaxAttempts)
	}
	if auditWebhookBaseBackoff <= 0 || auditWebhookBaseBackoff > time.Second {
		t.Errorf("auditWebhookBaseBackoff = %v, want a short positive delay", auditWebhookBaseBackoff)
	}
}
