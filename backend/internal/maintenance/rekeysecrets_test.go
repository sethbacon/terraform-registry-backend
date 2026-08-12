package maintenance

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/crypto"
)

// Key rotation completion (#848). bind-secrets skips a row it can already open
// under its own context, and OpenWithContext falls back to
// ENCRYPTION_KEY_PREVIOUS — so a row bound BEFORE a rotation stays sealed under
// the old key forever, and nothing says so. The rotation therefore never ends:
// the previous key can never be dropped.
//
// The properties an operator relies on here are the same ones bind-secrets has
// to have, against a harder failure mode. A mistake in a binding sweep leaves a
// readable secret; a mistake here can write a value that only the key you are
// about to delete could open.

// rotation is the state an operator is actually in mid-rotation: everything at
// rest was sealed under `previous`, the deployment now runs with `currentKey`
// and keeps `previous` as the decryption fallback.
//
// `current` is the same key as `currentKey` with NO fallback — the oracle the
// tests use to assert "this row no longer needs the previous key", which is
// exactly what RekeySecrets builds internally and what the gate means.
type rotation struct {
	previous   *crypto.TokenCipher
	dual       *crypto.TokenCipher
	current    *crypto.TokenCipher
	currentKey []byte
}

func newRotation(t *testing.T) rotation {
	t.Helper()
	previousKey, currentKey := make([]byte, 32), make([]byte, 32)
	for i := range previousKey {
		previousKey[i] = byte(i + 3)
		currentKey[i] = byte(200 - i)
	}
	previous, err := crypto.NewTokenCipher(previousKey)
	if err != nil {
		t.Fatalf("previous cipher: %v", err)
	}
	dual, err := crypto.NewTokenCipherWithPrevious(currentKey, previousKey)
	if err != nil {
		t.Fatalf("dual cipher: %v", err)
	}
	current, err := crypto.NewTokenCipher(currentKey)
	if err != nil {
		t.Fatalf("current cipher: %v", err)
	}
	return rotation{previous: previous, dual: dual, current: current, currentKey: currentKey}
}

// rekeyRowID is the row every single-row test serves. A uuid because several
// context functions are documented as taking one, even though they only
// concatenate.
const rekeyRowID = "77777777-7777-7777-7777-777777777777"

// driveColumn primes a whole registry sweep in which `col` is the only column
// holding a row, serves `sealed` for it, and returns a pointer to whatever
// ciphertext is written back.
//
// It is derived from the column itself rather than from a per-column fixture
// table, including the config-blob singletons whose listing reads a JSON
// document and whose write is a read-modify-write of it. That is deliberate:
// the tests below iterate `columns`, so a column added to the registry is
// exercised by every one of them without anyone remembering to add a fixture —
// and the requirement here is that rekeying covers EVERY registered column, not
// a representative sample of them.
func driveColumn(t *testing.T, mock sqlmock.Sqlmock, col column, sealed string, expectWrite bool) *string {
	t.Helper()
	stored := new(string)
	for _, c := range columns {
		if c.name != col.name {
			mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id", "sealed"}))
			continue
		}
		if c.singleton {
			blobColumn, path := blobNameParts(t, c.name)
			doc := blobDocument(path, sealed)
			mock.ExpectQuery("SELECT " + blobColumn).
				WillReturnRows(sqlmock.NewRows([]string{blobColumn}).AddRow(doc))
			if expectWrite {
				// The write re-reads the blob so it rewrites what is stored
				// rather than a stale copy from the listing.
				mock.ExpectQuery("SELECT " + blobColumn).
					WillReturnRows(sqlmock.NewRows([]string{blobColumn}).AddRow(doc))
				mock.ExpectExec("UPDATE system_settings SET " + blobColumn).
					WithArgs(blobFieldCapture{path: path, into: stored}).
					WillReturnResult(sqlmock.NewResult(0, 1))
			}
			continue
		}
		mock.ExpectQuery("SELECT").
			WillReturnRows(sqlmock.NewRows([]string{"id", "sealed"}).AddRow(rekeyRowID, sealed))
		if expectWrite {
			mock.ExpectExec("UPDATE").
				WithArgs(sqlmock.AnyArg(), capturedArg{got: stored}).
				WillReturnResult(sqlmock.NewResult(0, 1))
		}
	}
	return stored
}

// blobNameParts splits a singleton column's name back into the blob column and
// the field path inside it. blobField builds the name from exactly these two
// pieces, so reading them back keeps the driver honest for any blob field added
// later rather than hard-coding the two that exist today.
func blobNameParts(t *testing.T, name string) (string, []string) {
	t.Helper()
	blobColumn, dotted, ok := strings.Cut(strings.TrimPrefix(name, "system_settings."), ":")
	if !ok {
		t.Fatalf("singleton column %q does not have the system_settings.<blob>:<path> shape "+
			"the driver relies on", name)
	}
	return blobColumn, strings.Split(dotted, ".")
}

// blobDocument builds a config blob holding `sealed` at `path`.
func blobDocument(path []string, sealed string) []byte {
	doc := map[string]any{"an_unrelated_setting": true}
	cur := doc
	for _, step := range path[:len(path)-1] {
		next := map[string]any{"an_unrelated_nested_setting": 1}
		cur[step] = next
		cur = next
	}
	cur[path[len(path)-1]] = sealed
	encoded, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return encoded
}

// blobFieldCapture records the ciphertext a blob rewrite left at `path`.
type blobFieldCapture struct {
	path []string
	into *string
}

func (b blobFieldCapture) Match(v driver.Value) bool {
	var raw []byte
	switch x := v.(type) {
	case []byte:
		raw = x
	case string:
		raw = []byte(x)
	default:
		return false
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false
	}
	s, _ := blobLookup(doc, b.path)
	*b.into = s
	return true
}

// The defect, over the whole registry: a row that is already BOUND but sealed
// under the previous key must be re-encrypted onto the current one.
//
// Iterating `columns` rather than naming a column is the point — the gate this
// feeds says "the previous key can be deleted", and that claim is only as wide
// as the set of columns actually swept.
func TestRekeySecrets_ReEncryptsEveryRegisteredColumnOntoTheCurrentKey(t *testing.T) {
	for _, col := range columns {
		t.Run(col.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			r := newRotation(t)

			secret := "secret-for-" + col.name
			aad := col.context(rekeyRowID)
			boundUnderPrevious, err := r.previous.SealWithContext(secret, aad)
			if err != nil {
				t.Fatal(err)
			}

			stored := driveColumn(t, mock, col, boundUnderPrevious, true)

			res, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, false)
			if err != nil {
				t.Fatalf("RekeySecrets: %v", err)
			}
			if got := res[col.name]; got.Converted != 1 || got.Failed != 0 {
				t.Fatalf("result = %s; want the row re-encrypted", got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the re-encrypted value was not written back: %v", err)
			}

			// The whole point of the run: the stored value no longer needs the
			// previous key.
			got, err := r.current.OpenWithContext(*stored, aad)
			if err != nil || got != secret {
				t.Fatalf("re-encrypted value does not open under the CURRENT key alone: (%q, %v)", got, err)
			}
			// ...and the binding survived the re-encryption. A singleton has no
			// row axis to be moved along, so there is nothing to assert for it.
			if !col.singleton {
				if _, err := r.current.OpenWithContext(*stored, col.context("some-other-row")); err == nil {
					t.Error("re-encrypted value opens under another row's context; the binding was dropped")
				}
			}
		})
	}
}

// Re-running must write nothing. A rekey that rewrites every row on every
// invocation turns a routine verification into a full credential rewrite, and
// an interrupted run into an unbounded one.
func TestRekeySecrets_LeavesARowAlreadyOnTheCurrentKeyAlone(t *testing.T) {
	for _, col := range columns {
		t.Run(col.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			r := newRotation(t)

			aad := col.context(rekeyRowID)
			boundUnderCurrent, err := r.current.SealWithContext("already-rotated", aad)
			if err != nil {
				t.Fatal(err)
			}

			// expectWrite=false: sqlmock fails an UPDATE that was not queued.
			driveColumn(t, mock, col, boundUnderCurrent, false)

			res, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, false)
			if err != nil {
				t.Fatalf("RekeySecrets: %v", err)
			}
			if got := res[col.name]; got.AlreadyBound != 1 || got.Converted != 0 {
				t.Fatalf("result = %s; want the row recognised as already on the current key", got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a row already on the current key must not be rewritten: %v", err)
			}
		})
	}
}

// A row that is BOTH unbound and on the previous key converges in one pass, so a
// deployment that never ran bind-secrets is not left needing two commands in a
// particular order.
func TestRekeySecrets_ConvergesAnUnboundRowOnThePreviousKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := newRotation(t)

	col := registeredColumn(t, chanCol)
	aad := col.context(rekeyRowID)
	legacy, err := r.previous.Seal("https://hooks.example.com/a")
	if err != nil {
		t.Fatal(err)
	}

	stored := driveColumn(t, mock, col, legacy, true)

	res, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, false)
	if err != nil {
		t.Fatalf("RekeySecrets: %v", err)
	}
	if got := res[chanCol]; got.Converted != 1 || got.Failed != 0 {
		t.Fatalf("result = %s; want one conversion", got)
	}
	if got, err := r.current.OpenWithContext(*stored, aad); err != nil || got != "https://hooks.example.com/a" {
		t.Fatalf("value did not converge to bound-and-current in one pass: (%q, %v)", got, err)
	}
	if _, err := r.current.Open(*stored); err == nil {
		t.Error("the re-encrypted value still opens WITHOUT a context; the rekey dropped the binding")
	}
}

// The regression that names the bug. This row is exactly what bind-secrets
// declares finished — bound, and openable through the dual-key fallback — while
// still requiring the key the operator is about to delete.
//
// Asserting both commands on the SAME row is what makes it a regression test
// rather than a restatement: bind-secrets verify passing here is correct and
// must keep passing, and it is precisely why it cannot be the rotation gate.
func TestRekeyVerify_FailsOnTheRowBindVerifyCallsDone(t *testing.T) {
	r := newRotation(t)
	col := registeredColumn(t, chanCol)
	boundUnderPrevious, err := r.previous.SealWithContext("https://hooks.example.com/a", col.context(rekeyRowID))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("bind-secrets verify reports nothing to do", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		driveColumn(t, mock, col, boundUnderPrevious, false)

		if _, err := BindSecrets(context.Background(), db, r.dual, true); err != nil {
			t.Fatalf("bind verify = %v; the row IS bound, so this must stay clean", err)
		}
	})

	t.Run("rekey verify refuses", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		driveColumn(t, mock, col, boundUnderPrevious, false)

		res, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, true)
		if !errors.Is(err, ErrPreviousKeyStillRequired) {
			t.Fatalf("rekey verify = %v, want ErrPreviousKeyStillRequired so a runbook step can gate on it", err)
		}
		if res[chanCol].Converted != 1 {
			t.Errorf("verify should report what WOULD be re-encrypted; got %s", res[chanCol])
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("verify must not write: %v", err)
		}
	})
}

// The zero that permits dropping ENCRYPTION_KEY_PREVIOUS.
func TestRekeyVerify_SucceedsOnlyWhenEveryRowIsOnTheCurrentKey(t *testing.T) {
	for _, col := range columns {
		t.Run(col.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			r := newRotation(t)

			boundUnderCurrent, err := r.current.SealWithContext("rotated", col.context(rekeyRowID))
			if err != nil {
				t.Fatal(err)
			}
			driveColumn(t, mock, col, boundUnderCurrent, false)

			if _, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, true); err != nil {
				t.Fatalf("verify with everything on the current key must succeed, got %v", err)
			}
		})
	}
}

// A row nothing can decrypt is reported and stepped over, as in the binding
// sweep — but unlike there it must also HOLD THE GATE SHUT. "One row could not
// be read" is not evidence that deleting the previous key is safe.
func TestRekeySecrets_OneUndecryptableRowIsSteppedOverAndBlocksTheGate(t *testing.T) {
	r := newRotation(t)
	col := registeredColumn(t, chanCol)

	good, err := r.previous.SealWithContext("https://hooks.example.com/good", col.context("chan-good"))
	if err != nil {
		t.Fatal(err)
	}

	prime := func(mock sqlmock.Sqlmock, expectWrite bool) {
		for _, c := range columns {
			if c.name != chanCol {
				mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id", "sealed"}))
				continue
			}
			mock.ExpectQuery("SELECT id, encrypted_target FROM notification_channels").
				WillReturnRows(channelRows(
					[2]string{"chan-bad", "not-a-valid-ciphertext"},
					[2]string{"chan-good", good},
				))
			if expectWrite {
				mock.ExpectExec("UPDATE notification_channels").WillReturnResult(sqlmock.NewResult(0, 1))
			}
		}
	}

	t.Run("the good row is still re-encrypted", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		prime(mock, true)

		res, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, false)
		if err != nil {
			t.Fatalf("RekeySecrets: %v", err)
		}
		if got := res[chanCol]; got.Failed != 1 || got.Converted != 1 {
			t.Errorf("result = %s; want the bad row reported and the good one still re-encrypted", got)
		}
	})

	t.Run("verify refuses while it remains", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		prime(mock, false)

		if _, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, true); !errors.Is(err, ErrPreviousKeyStillRequired) {
			t.Fatalf("verify = %v; an unreadable row is not proof the previous key can go", err)
		}
	})
}

// A ciphertext lifted out of another row must NOT be re-sealed into the row it
// was planted in. Re-binding it here would launder the move the AAD exists to
// detect — the rekey would hand an attacker the valid binding they could not
// forge, and the audit trail would be a routine rotation.
func TestRekeySecrets_RefusesToReBindAValueMovedFromAnotherRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := newRotation(t)

	col := registeredColumn(t, chanCol)
	// Sealed for a different channel, then written into this row.
	planted, err := r.previous.SealWithContext("https://attacker.example.com/",
		col.context("00000000-0000-0000-0000-00000000dead"))
	if err != nil {
		t.Fatal(err)
	}

	driveColumn(t, mock, col, planted, false)

	res, err := RekeySecrets(context.Background(), db, r.dual, r.currentKey, false)
	if err != nil {
		t.Fatalf("RekeySecrets: %v", err)
	}
	if got := res[chanCol]; got.Failed != 1 || got.Converted != 0 {
		t.Fatalf("result = %s; a value bound to another row must be reported, never re-bound here", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("nothing should have been written for a moved value: %v", err)
	}
}

// The gate is only meaningful if the key it checks against is the key the
// service seals with. Handed the wrong ENCRYPTION_KEY, the sweep must refuse up
// front rather than report every row as needing work — or, far worse, re-seal
// the estate under a key nothing else has.
func TestRekeySecrets_RefusesAKeyTheCipherDoesNotSealWith(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := newRotation(t)

	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = byte(i + 11)
	}

	// Prime the whole sweep as a run with nothing to do. Without this the test
	// passes on the wrong evidence: sqlmock rejects the first unexpected query,
	// so ANY failure to check the key still surfaces as "an error was returned".
	// With it, a missing check produces a clean nil — which is the outcome that
	// has to fail.
	for range columns {
		mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id", "sealed"}))
	}

	_, err = RekeySecrets(context.Background(), db, r.dual, wrong, false)
	if !errors.Is(err, ErrEncryptionKeyMismatch) {
		t.Fatalf("err = %v, want ErrEncryptionKeyMismatch", err)
	}
	if mock.ExpectationsWereMet() == nil {
		t.Error("the sweep read rows before checking the key; the refusal must come first, " +
			"because the alternative is re-sealing the estate under a key nothing else has")
	}
}

func TestRekeySecrets_RequiresACipherAndAKey(t *testing.T) {
	r := newRotation(t)
	cases := []struct {
		name string
		tc   *crypto.TokenCipher
		key  []byte
	}{
		{"no cipher", nil, r.currentKey},
		{"no key", r.dual, nil},
		{"short key", r.dual, []byte("too-short")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, _, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := RekeySecrets(context.Background(), db, c.tc, c.key, false); err == nil {
				t.Fatal("must be refused, not treated as 'nothing to do'")
			}
		})
	}
}

// registeredColumn returns a column by name, failing if the registry no longer
// has it — so a rename shows up as "this test drives nothing" rather than as a
// silently vacuous pass.
func registeredColumn(t *testing.T, name string) column {
	t.Helper()
	for _, c := range columns {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("column %q is not registered; the test drives nothing", name)
	return column{}
}
