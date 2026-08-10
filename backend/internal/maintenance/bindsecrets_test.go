package maintenance

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
)

// suite-identity #153 backfill. The properties an operator relies on when
// running this against live credentials: safe to re-run, one bad row does not
// abandon the rest, and verify writes nothing but still fails while work remains.

func newCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	tc, err := crypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

type capturedArg struct{ got *string }

func (c capturedArg) Match(v driver.Value) bool {
	if s, ok := v.(string); ok {
		*c.got = s
	}
	return true
}

func channelRows(pairs ...[2]string) *sqlmock.Rows {
	r := sqlmock.NewRows([]string{"id", "encrypted_target"})
	for _, p := range pairs {
		r.AddRow(p[0], p[1])
	}
	return r
}

const chanCol = "notification_channels.encrypted_target"

func TestBindSecrets_ConvertsAnUnboundRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	legacy, err := tc.Seal("https://hooks.example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
		WillReturnRows(channelRows([2]string{"chan-1", legacy}))

	var stored string
	mock.ExpectExec("UPDATE notification_channels").
		WithArgs(sqlmock.AnyArg(), capturedArg{got: &stored}).
		WillReturnResult(sqlmock.NewResult(0, 1))

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	if got := res[chanCol]; got.Converted != 1 || got.Failed != 0 {
		t.Fatalf("result = %s; want one conversion", got)
	}

	got, err := tc.OpenWithContext(stored, identitynotify.TargetContext("chan-1"))
	if err != nil || got != "https://hooks.example.com/a" {
		t.Fatalf("converted value does not open under its row context: (%q, %v)", got, err)
	}
	if _, err := tc.Open(stored); err == nil {
		t.Error("converted value still opens WITHOUT a context; it was not bound")
	}
}

// Re-running must be a no-op, which is what makes an interrupted sweep safe to
// resume. Asserted by the absence of any UPDATE — sqlmock fails an unexpected one.
func TestBindSecrets_SkipsAnAlreadyBoundRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	bound, err := tc.SealWithContext("https://hooks.example.com/a", identitynotify.TargetContext("chan-1"))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
		WillReturnRows(channelRows([2]string{"chan-1", bound}))

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	if got := res[chanCol]; got.AlreadyBound != 1 || got.Converted != 0 {
		t.Fatalf("result = %s; want the row recognised as already bound", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an already-bound row should trigger no write: %v", err)
	}
}

func TestBindSecrets_OneUndecryptableRowDoesNotAbortTheSweep(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	good, err := tc.Seal("https://hooks.example.com/good")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
		WillReturnRows(channelRows(
			[2]string{"chan-bad", "not-a-valid-ciphertext"},
			[2]string{"chan-good", good},
		))
	mock.ExpectExec("UPDATE notification_channels").WillReturnResult(sqlmock.NewResult(0, 1))

	res, err := BindSecrets(context.Background(), db, tc, false)
	if err != nil {
		t.Fatalf("BindSecrets: %v", err)
	}
	got := res[chanCol]
	if got.Failed != 1 || got.Converted != 1 {
		t.Errorf("result = %s; want the bad row reported and the good one still converted", got)
	}
}

func TestBindSecrets_VerifyWritesNothingAndFailsWhileUnboundRemain(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	legacy, err := tc.Seal("https://hooks.example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
		WillReturnRows(channelRows([2]string{"chan-1", legacy}))

	res, err := BindSecrets(context.Background(), db, tc, true)
	if !errors.Is(err, ErrUnboundRemain) {
		t.Fatalf("verify error = %v, want ErrUnboundRemain so it can gate a runbook step", err)
	}
	if res[chanCol].Converted != 1 {
		t.Errorf("verify should report what WOULD convert; got %s", res[chanCol])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("verify must not write: %v", err)
	}
}

// The zero that says a column's reads can stop accepting the unbound form.
func TestBindSecrets_VerifySucceedsWhenAllBound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tc := newCipher(t)

	bound, err := tc.SealWithContext("https://hooks.example.com/a", identitynotify.TargetContext("chan-1"))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
		WillReturnRows(channelRows([2]string{"chan-1", bound}))

	if _, err := BindSecrets(context.Background(), db, tc, true); err != nil {
		t.Fatalf("verify with everything bound must succeed, got %v", err)
	}
}

func TestBindSecrets_RequiresACipher(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := BindSecrets(context.Background(), db, nil, false); err == nil {
		t.Fatal("a nil cipher must be refused, not treated as 'nothing to do'")
	}
}

// Every registered column must derive its context from the row id. A constant
// context would satisfy the round-trip tests above while making the binding
// vacuous for that column, and this is the cheapest place to catch it as columns
// are added.
func TestRegisteredColumns_ContextsAreRowScoped(t *testing.T) {
	for _, col := range columns {
		if string(col.context("row-a")) == string(col.context("row-b")) {
			t.Errorf("%s derives the same context for different rows; its binding is vacuous", col.name)
		}
	}
}
