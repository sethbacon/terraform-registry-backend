package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

func newHandleSetupTokenRepo(t *testing.T) (*repositories.OIDCConfigRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func TestDevModeFromEnv(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"1":     true,
		"false": false,
		"0":     false,
		"":      false,
		"yes":   false,
	}
	for raw, want := range cases {
		if got := devModeFromEnv(raw); got != want {
			t.Errorf("devModeFromEnv(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestIsProductionLoggingLevel(t *testing.T) {
	cases := map[string]bool{
		"warn":  true,
		"error": true,
		"info":  false,
		"debug": false,
		"":      false,
	}
	for level, want := range cases {
		if got := isProductionLoggingLevel(level); got != want {
			t.Errorf("isProductionLoggingLevel(%q) = %v, want %v", level, got, want)
		}
	}
}

// TestDevModeProductionGuard_RefusesNonDebugWithoutConfirmation is the core
// assertion for issue #559 findings [5]/[11]: DEV_MODE together with any
// logging.level other than "debug" must refuse to start unless explicitly
// confirmed non-production. "info" -- this repo's own config default, and
// what its dev/test compose stacks actually run at -- is deliberately
// included: it is NOT a safe default to allow, since it is indistinguishable
// from a plausible, deliberate production choice (an earlier version of this
// guard only blocked "warn"/"error" and so let the overwhelmingly common
// misconfiguration -- DEV_MODE=true at the "info" default -- straight
// through).
func TestDevModeProductionGuard_RefusesNonDebugWithoutConfirmation(t *testing.T) {
	for _, level := range []string{"warn", "error", "info", ""} {
		if err := devModeProductionGuard(true, level, false); err == nil {
			t.Errorf("devModeProductionGuard(true, %q, false) = nil, want an error", level)
		}
	}
}

func TestDevModeProductionGuard_AllowsDebugWithoutConfirmation(t *testing.T) {
	if err := devModeProductionGuard(true, "debug", false); err != nil {
		t.Errorf("devModeProductionGuard(true, \"debug\", false) = %v, want nil", err)
	}
}

func TestDevModeProductionGuard_AllowsNonDebugWithExplicitConfirmation(t *testing.T) {
	for _, level := range []string{"warn", "error", "info", "", "debug"} {
		if err := devModeProductionGuard(true, level, true); err != nil {
			t.Errorf("devModeProductionGuard(true, %q, true) = %v, want nil", level, err)
		}
	}
}

func TestDevModeProductionGuard_AllowsProductionWithoutDevMode(t *testing.T) {
	for _, level := range []string{"warn", "error", "info", "debug"} {
		if err := devModeProductionGuard(false, level, false); err != nil {
			t.Errorf("devModeProductionGuard(false, %q, false) = %v, want nil", level, err)
		}
	}
}

// TestServe_NeverLogsGetDSN guards against reintroducing issue #651: main.go
// used to log.Printf("Full DSN (masked): %s", cfg.Database.GetDSN()) directly
// under the very next line as its properly-redacted "Database config: ..."
// log, writing the live cleartext database password to stdout on every
// startup despite the misleading "(masked)" label. serve() isn't practically
// unit-testable in isolation (it calls db.Connect immediately after loading
// config), so this checks the source itself: no log.* call in this file may
// pass *Database.GetDSN()/GetDSNWithSearchPath() as an argument, whether
// inline on the same line or via a variable assigned from such a call on an
// earlier line (e.g. `dsn := cfg.Database.GetDSN()` ... `log.Printf(..., dsn)`
// elsewhere). This would fail loudly (a static match, not a silent
// compile-time deletion) if such a call were ever reintroduced.
func TestServe_NeverLogsGetDSN(t *testing.T) {
	f, err := os.Open("main.go")
	if err != nil {
		t.Fatalf("open main.go: %v", err)
	}
	defer f.Close()

	logCall := regexp.MustCompile(`\blog\.[A-Za-z]+\(`)
	getDSNCall := regexp.MustCompile(`\.GetDSN(WithSearchPath)?\(`)
	// dsnAssign only matches a *single* variable assigned to *exactly* a
	// GetDSN()/GetDSNWithSearchPath() call (e.g. `dsn := cfg.Database.GetDSN()`),
	// not GetDSN() appearing as a nested argument of some other call (e.g.
	// `database, err := db.Connect(cfg.Database.GetDSN(), ...)`, which assigns
	// database/err, not the DSN, and is not the #651 pattern).
	dsnAssign := regexp.MustCompile(`^\s*(\w+)\s*:?=\s*[\w.]+\.GetDSN(WithSearchPath)?\([^()]*\)\s*$`)

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan main.go: %v", err)
	}

	// dsnVars tracks variable names assigned directly from a GetDSN call so a
	// later `log.*(...dsn...)` on a *different* line is also caught, not just
	// the same-line case the getDSNCall check below catches.
	dsnVars := map[string]bool{}
	for _, line := range lines {
		if m := dsnAssign.FindStringSubmatch(line); m != nil {
			dsnVars[m[1]] = true
		}
	}

	for i, line := range lines {
		lineNum := i + 1
		if logCall.MatchString(line) && getDSNCall.MatchString(line) {
			t.Errorf("main.go:%d logs a raw DSN via GetDSN()/GetDSNWithSearchPath() (issue #651 -- these interpolate the cleartext database password with zero redaction): %s", lineNum, line)
		}
		if logCall.MatchString(line) {
			for name := range dsnVars {
				if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(line) {
					t.Errorf("main.go:%d logs %q, a variable assigned from GetDSN()/GetDSNWithSearchPath() on an earlier line (issue #651): %s", lineNum, name, line)
				}
			}
		}
	}
}

func TestFeatureSetupRearmAllowed(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"1":     false, // unlike DEV_MODE, only the literal "true" opts in
		"false": false,
		"":      false,
	}
	for raw, want := range cases {
		t.Setenv("TFR_ALLOW_FEATURE_SETUP_REARM", raw)
		if got := featureSetupRearmAllowed(); got != want {
			t.Errorf("featureSetupRearmAllowed() with env=%q = %v, want %v", raw, got, want)
		}
	}
}

// TestHandleSetupToken_PendingFeature_NoRearmByDefault is the negative
// (attack-path) test for issue #649: when setup is completed and a feature is
// pending (e.g. scanning unconfigured), handleSetupToken must NOT mint and log
// a fresh setup token by default -- doing so on every restart is what let the
// entire setup surface silently re-arm.
func TestHandleSetupToken_PendingFeature_NoRearmByDefault(t *testing.T) {
	t.Setenv("TFR_ALLOW_FEATURE_SETUP_REARM", "")
	repo, mock := newHandleSetupTokenRepo(t)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(true))
	mock.ExpectQuery(`SELECT setup_completed AND \(NOT scanning_configured\) FROM system_settings`).
		WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(true))

	if err := handleSetupToken(repo); err != nil {
		t.Fatalf("handleSetupToken() unexpected error: %v", err)
	}
	// No GetSetupTokenHash/SetSetupTokenHash query should have been issued --
	// asserting this via ExpectationsWereMet confirms handleSetupToken returned
	// before reaching the token-minting path.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/extra sqlmock expectations (should not query/mint a token): %v", err)
	}
}

// TestHandleSetupToken_PendingFeature_RearmWhenExplicitlyAllowed is the
// positive (legit-path) counterpart: with the explicit operator opt-in set,
// a pending feature still mints a token as before.
func TestHandleSetupToken_PendingFeature_RearmWhenExplicitlyAllowed(t *testing.T) {
	t.Setenv("TFR_ALLOW_FEATURE_SETUP_REARM", "true")
	repo, mock := newHandleSetupTokenRepo(t)

	mock.ExpectQuery("SELECT setup_completed FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_completed"}).AddRow(true))
	mock.ExpectQuery(`SELECT setup_completed AND \(NOT scanning_configured\) FROM system_settings`).
		WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(true))
	mock.ExpectQuery("SELECT setup_token_hash FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"setup_token_hash"}).AddRow(nil))
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := handleSetupToken(repo); err != nil {
		t.Fatalf("handleSetupToken() unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (should mint a token when rearm is allowed): %v", err)
	}
}

// TestWaitForShutdownOrListenError_QuitSignal and
// TestWaitForShutdownOrListenError_ListenerError are regression tests for
// issue #686: a listener startup/accept-loop failure (bind failure, or fd
// exhaustion after the server has been running) used to call log.Fatalf
// directly inside the listener goroutine, which calls os.Exit(1) and skips
// serve()'s deferred database.Close() and bgServices.Shutdown(). The fix
// sends the error over a channel back to the main goroutine instead, so the
// normal shutdown path always runs. These tests assert the channel-selection
// logic that fix depends on: a listener error must be returned (not
// discarded, not treated the same as a clean quit signal), and a normal quit
// signal must still return nil.
func TestWaitForShutdownOrListenError_QuitSignal(t *testing.T) {
	quit := make(chan os.Signal, 1)
	listenErrCh := make(chan error, 1)

	quit <- os.Interrupt

	err := waitForShutdownOrListenError(quit, listenErrCh)
	if err != nil {
		t.Errorf("waitForShutdownOrListenError() = %v, want nil for a normal quit signal", err)
	}
}

func TestWaitForShutdownOrListenError_ListenerError(t *testing.T) {
	quit := make(chan os.Signal, 1)
	listenErrCh := make(chan error, 1)

	wantErr := errors.New("listen tcp :8080: bind: address already in use")
	listenErrCh <- wantErr

	err := waitForShutdownOrListenError(quit, listenErrCh)
	if err != wantErr {
		t.Errorf("waitForShutdownOrListenError() = %v, want %v", err, wantErr)
	}
}

func TestWaitForShutdownOrListenError_ListenerErrorWinsWhenBothReady(t *testing.T) {
	// If both channels have a pending value, either is a legal select outcome
	// in general, but this test only sends to listenErrCh so there is no
	// ambiguity — it guards against a future edit reordering the select cases
	// in a way that stops checking listenErrCh at all.
	quit := make(chan os.Signal, 1)
	listenErrCh := make(chan error, 1)

	go func() {
		time.Sleep(10 * time.Millisecond)
		listenErrCh <- errors.New("accept loop failure")
	}()

	err := waitForShutdownOrListenError(quit, listenErrCh)
	if err == nil {
		t.Error("waitForShutdownOrListenError() = nil, want the delayed listener error")
	}
}

// ---------------------------------------------------------------------------
// shutdownServices (issue #716)
// ---------------------------------------------------------------------------

// stubShutdowner records that Shutdown ran and returns a fixed error.
type stubShutdowner struct {
	err    error
	called bool
}

func (s *stubShutdowner) Shutdown(context.Context) error {
	s.called = true
	return s.err
}

// The regression case: a graceful shutdown that itself fails or times out must
// still stop background services. Before #716 the drain error returned early,
// skipping bgServices.Shutdown() — and with it the audit shipper's final flush.
func TestShutdownServices_DrainError_StillStopsBackground(t *testing.T) {
	srv := &stubShutdowner{err: errors.New("context deadline exceeded")}
	stopped := false

	err := shutdownServices(context.Background(), srv, func() { stopped = true }, nil)

	if !stopped {
		t.Error("background services were not stopped after a failed drain (issue #716)")
	}
	if err == nil {
		t.Error("expected the drain error to be returned")
	}
}

func TestShutdownServices_CleanShutdown(t *testing.T) {
	srv := &stubShutdowner{}
	stopped := false

	if err := shutdownServices(context.Background(), srv, func() { stopped = true }, nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !srv.called {
		t.Error("server drain was not attempted")
	}
	if !stopped {
		t.Error("background services were not stopped")
	}
}

// A listener startup failure must still drain and stop background services, and
// its error takes precedence over any drain error (issue #686 behaviour, kept).
func TestShutdownServices_ListenError_TakesPrecedenceAndStopsBackground(t *testing.T) {
	srv := &stubShutdowner{err: errors.New("drain failed")}
	stopped := false
	listenErr := errors.New("bind: address already in use")

	err := shutdownServices(context.Background(), srv, func() { stopped = true }, listenErr)

	if !stopped {
		t.Error("background services were not stopped on the listener-error path")
	}
	if err == nil || !errors.Is(err, listenErr) {
		t.Errorf("err = %v, want the listener error to take precedence", err)
	}
}

func TestShutdownServices_NilStopBackground_DoesNotPanic(t *testing.T) {
	srv := &stubShutdowner{}
	if err := shutdownServices(context.Background(), srv, nil, nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
