package webhooks

import (
	"bytes"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Issue #744 — the unauthenticated webhook body was read unbounded.
//
// The read happens BEFORE the URL secret and before the HMAC signature are
// checked. It has to: the signature is computed over the body. So the only
// precondition for reaching it was a syntactically valid UUID in the path, and
// that UUID did not need to name a real link — a non-existent one still reached
// the read before the 404.
//
// These tests deliberately use a NON-EXISTENT link id and set up no database
// expectations. If the cap ever moves to after the lookup, the test fails on an
// unmet sqlmock expectation rather than passing quietly — the ordering is the
// property under test, not just the limit.

func TestWebhook_OversizedBodyRejectedBeforeAnyLookup(t *testing.T) {
	_, r := newWebhookRouter(t)

	// One byte over the cap.
	body := bytes.Repeat([]byte("a"), maxWebhookPayloadBytes+1)
	req := httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 for an oversized body; body: %s", w.Code, w.Body.String())
	}
	// The caller has not proved it knows the secret, so it must not learn the
	// limit or anything about the link from this response.
	for _, leak := range []string{"5242880", "5 MiB", "maxWebhookPayloadBytes", "not found"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("413 body disclosed %q: %s", leak, w.Body.String())
		}
	}
}

func TestWebhook_BodyAtTheCapIsNotRejectedForSize(t *testing.T) {
	mock, r := newWebhookRouter(t)
	// Exactly at the cap must be allowed through the read. It then fails later
	// for an unrelated reason (no such link), which is the point: the size check
	// is not what stops it.
	mock.ExpectQuery("SELECT.*FROM module_scm_repos WHERE id").
		WillReturnRows(sqlmock.NewRows(moduleSourceRepoCols))

	body := bytes.Repeat([]byte("a"), maxWebhookPayloadBytes)
	req := httptest.NewRequest("POST", "/webhooks/scm/"+webhookTestUUID+"/secret123", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusRequestEntityTooLarge {
		t.Errorf("a body exactly at the cap was rejected as too large; the boundary is off by one")
	}
}
