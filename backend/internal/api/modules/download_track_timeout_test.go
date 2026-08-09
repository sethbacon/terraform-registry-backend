package modules

import (
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Issue #758 — the fire-and-forget download-count goroutines had no deadline.
//
// trackProviderDownload runs after the response is served and makes FOUR
// sequential queries on a bare context.Background(). Against a wedged database
// every one of these goroutines stayed resident for the life of the process,
// one per download — the failure mode that turns a slow database into an
// out-of-memory kill.
//
// Postgres statement_timeout does not cover it: it bounds a running query, not
// the wait for a free pooled connection or a blackholed server, which is
// exactly when these accumulate.
//
// A grep-style test would be INERT here. serve.go already contained
// "context.WithTimeout" before this fix — for the audit goroutine 30 lines
// above — so asserting the string appears in the file passes on unfixed code.
// This drives the function against a stalled driver and measures that it
// actually returns.

func TestTrackProviderDownload_ReturnsWhenTheDatabaseStalls(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// The first query the function makes stalls far longer than the deadline.
	// WillDelayFor honours the context, so a bounded context aborts the wait and
	// an unbounded one blocks for the full delay.
	mock.ExpectQuery("(?s)SELECT.*organizations").
		WillDelayFor(60 * time.Second).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("org-1"))

	providerRepo := repositories.NewProviderRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		trackProviderDownload(providerRepo, orgRepo, "hashicorp", "aws", "5.31.0", "linux", "amd64")
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		// It must give up near the deadline, not immediately: returning in ~0s
		// would mean the query never ran and the test proves nothing about the
		// timeout.
		if elapsed < downloadTrackTimeout {
			t.Fatalf("returned after %v, before the %v deadline — the stalled query was "+
				"not actually exercised, so this test would pass without the fix",
				elapsed, downloadTrackTimeout)
		}
		if elapsed > downloadTrackTimeout+10*time.Second {
			t.Errorf("returned after %v, far past the %v deadline", elapsed, downloadTrackTimeout)
		}
	case <-time.After(downloadTrackTimeout + 15*time.Second):
		t.Fatal("trackProviderDownload never returned against a stalled database — the " +
			"goroutine is unbounded and accumulates one per download")
	}
}

// TestDownloadTrackTimeout_IsBounded pins the constant itself. A deadline long
// enough to be indistinguishable from none is not a deadline.
func TestDownloadTrackTimeout_IsBounded(t *testing.T) {
	if downloadTrackTimeout <= 0 {
		t.Fatalf("downloadTrackTimeout = %v, must be positive", downloadTrackTimeout)
	}
	if downloadTrackTimeout > 30*time.Second {
		t.Errorf("downloadTrackTimeout = %v; the response is already sent, so this should "+
			"shed the counter quickly rather than hold a goroutine", downloadTrackTimeout)
	}
}
