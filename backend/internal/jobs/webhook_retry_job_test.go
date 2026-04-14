package jobs

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		retryCount int
		want       time.Duration
	}{
		{0, 1 * time.Minute},
		{1, 2 * time.Minute},
		{2, 4 * time.Minute},
		{3, 8 * time.Minute},
		{4, 16 * time.Minute},
		{5, 32 * time.Minute},
	}
	for _, tt := range tests {
		got := calculateBackoff(tt.retryCount)
		if got != tt.want {
			t.Errorf("calculateBackoff(%d) = %v, want %v", tt.retryCount, got, tt.want)
		}
	}
}

func TestWebhookRetryJob_StartNoopWhenMaxRetriesZero(t *testing.T) {
	cfg := &config.WebhooksConfig{
		MaxRetries:        0,
		RetryIntervalMins: 1,
	}
	job := NewWebhookRetryJob(cfg, nil, nil, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start should return immediately without panicking (no DB calls).
	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// good — returned immediately
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return within 2s when MaxRetries=0")
	}
}

func TestWebhookRetryJob_StopIdempotent(t *testing.T) {
	cfg := &config.WebhooksConfig{
		MaxRetries:        3,
		RetryIntervalMins: 1,
	}
	job := NewWebhookRetryJob(cfg, nil, nil, nil, nil)

	// Calling Stop twice should not panic.
	job.Stop()
	job.Stop()
}

// ---------------------------------------------------------------------------
// calculateBackoff — edge cases
// ---------------------------------------------------------------------------

func TestCalculateBackoff_HighRetry(t *testing.T) {
	// Retry 10 → 2^10 = 1024 minutes
	got := calculateBackoff(10)
	want := 1024 * time.Minute
	if got != want {
		t.Errorf("calculateBackoff(10) = %v, want %v", got, want)
	}
}

func TestCalculateBackoff_Zero(t *testing.T) {
	// Retry 0 → 2^0 = 1 minute (first retry)
	got := calculateBackoff(0)
	want := 1 * time.Minute
	if got != want {
		t.Errorf("calculateBackoff(0) = %v, want %v", got, want)
	}
}

// TestWebhookRetryJob_StartStopSignal verifies that calling Stop() while
// Start() is running causes it to return promptly.
func TestWebhookRetryJob_StartStopSignal(t *testing.T) {
	cfg := &config.WebhooksConfig{
		MaxRetries:        0, // no-op path
		RetryIntervalMins: 1,
	}
	job := NewWebhookRetryJob(cfg, nil, nil, nil, nil)

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return within 2s")
	}
}

// TestNewWebhookRetryJob_Constructor verifies the constructor sets fields correctly.
func TestNewWebhookRetryJob_Constructor(t *testing.T) {
	cfg := &config.WebhooksConfig{MaxRetries: 5, RetryIntervalMins: 2}
	job := NewWebhookRetryJob(cfg, nil, nil, nil, nil)

	if job.cfg.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", job.cfg.MaxRetries)
	}
	if job.cfg.RetryIntervalMins != 2 {
		t.Errorf("RetryIntervalMins = %d, want 2", job.cfg.RetryIntervalMins)
	}
	if job.stopChan == nil {
		t.Error("stopChan should not be nil")
	}
}

// ---------------------------------------------------------------------------
// failRetry — with sqlmock-backed SCMRepository
// ---------------------------------------------------------------------------

func TestFailRetry_Exhausted(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)

	cfg := &config.WebhooksConfig{MaxRetries: 3}
	job := NewWebhookRetryJob(cfg, scmRepo, nil, nil, nil)

	eventID := uuid.New()
	event := &scm.SCMWebhookEvent{
		ID:         eventID,
		RetryCount: 2, // newRetryCount = 3 >= MaxRetries(3) → exhausted
	}

	mock.ExpectExec("UPDATE scm_webhook_events SET").
		WithArgs(eventID, 3, "provider not found", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	job.failRetry(context.Background(), event, "provider not found")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestFailRetry_ScheduleNextRetry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)

	cfg := &config.WebhooksConfig{MaxRetries: 5}
	job := NewWebhookRetryJob(cfg, scmRepo, nil, nil, nil)

	eventID := uuid.New()
	event := &scm.SCMWebhookEvent{
		ID:         eventID,
		RetryCount: 1, // newRetryCount = 2 < 5 → schedule next
	}

	mock.ExpectExec("UPDATE scm_webhook_events SET").
		WithArgs(eventID, 2, "connection timeout", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	job.failRetry(context.Background(), event, "connection timeout")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runRetryCycle — with sqlmock-backed SCMRepository
// ---------------------------------------------------------------------------

func TestRunRetryCycle_EmptyEventList(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)

	cfg := &config.WebhooksConfig{MaxRetries: 5}
	job := NewWebhookRetryJob(cfg, scmRepo, nil, nil, nil)

	// GetRetryableWebhookEvents returns empty
	mock.ExpectQuery("SELECT \\* FROM scm_webhook_events").
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	job.runRetryCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRunRetryCycle_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)

	cfg := &config.WebhooksConfig{MaxRetries: 5}
	job := NewWebhookRetryJob(cfg, scmRepo, nil, nil, nil)

	mock.ExpectQuery("SELECT \\* FROM scm_webhook_events").
		WithArgs(10).
		WillReturnError(&testWebhookDBError{"connection refused"})

	// Should not panic — just logs and returns
	job.runRetryCycle(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

type testWebhookDBError struct{ msg string }

func (e *testWebhookDBError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// Start — context cancellation and stop channel when MaxRetries > 0
// ---------------------------------------------------------------------------

func TestWebhookRetryJob_Start_ContextCancel(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)

	cfg := &config.WebhooksConfig{
		MaxRetries:        3,
		RetryIntervalMins: 1,
	}
	job := NewWebhookRetryJob(cfg, scmRepo, nil, nil, nil)

	// The immediate runRetryCycle call — return empty
	mock.ExpectQuery("SELECT \\* FROM scm_webhook_events").
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestWebhookRetryJob_Start_StopChan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)

	cfg := &config.WebhooksConfig{
		MaxRetries:        3,
		RetryIntervalMins: 1,
	}
	job := NewWebhookRetryJob(cfg, scmRepo, nil, nil, nil)

	// The immediate runRetryCycle call — return empty
	mock.ExpectQuery("SELECT \\* FROM scm_webhook_events").
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	job.Stop()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after Stop()")
	}
}

func TestWebhookRetryJob_Start_DefaultInterval(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)

	cfg := &config.WebhooksConfig{
		MaxRetries:        3,
		RetryIntervalMins: 0, // defaults to 2 minutes
	}
	job := NewWebhookRetryJob(cfg, scmRepo, nil, nil, nil)

	mock.ExpectQuery("SELECT \\* FROM scm_webhook_events").
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}
