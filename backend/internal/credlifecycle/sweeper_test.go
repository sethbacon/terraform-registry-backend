package credlifecycle

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// akCols is the row shape returned by the identity store's API-key list
// queries.
var akCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at",
	"expiry_notification_sent_at", "created_at", "user_name",
}

func keyRow(id, userID, orgID string, scopes string) *sqlmock.Rows {
	return sqlmock.NewRows(akCols).AddRow(
		id, userID, orgID, "CI Key", nil, "hashedkey", "tfr_abc",
		[]byte(scopes), nil, nil, nil, time.Now(), nil)
}

// newSweeperWithMock builds a Sweeper whose two halves share one mocked
// connection. In production they are separate connections (the watermark lives
// on the registry database, api_keys on the identity database); for the
// sweeper's own logic only the statement sequence matters.
func newSweeperWithMock(t *testing.T) (*Sweeper, sqlmock.Sqlmock, *sql.DB) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := NewSweeper(
		repositories.NewUserTokenRevocationRepository(db),
		repositories.NewAPIKeyRepository(db),
	)
	if s == nil {
		t.Fatal("NewSweeper returned nil with both repositories present")
	}
	return s, mock, db
}

func expectWatermark(mock sqlmock.Sqlmock, userID string) {
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// ---------------------------------------------------------------------------
// AuthorityRetained — the predicate that separates a REDUCTION from any other
// change, and so decides whether an irreversible deletion happens at all.
// ---------------------------------------------------------------------------

func TestAuthorityRetained(t *testing.T) {
	cases := []struct {
		name     string
		have     []string
		retained []string
		want     bool
	}{
		{"identical set", []string{"modules:write"}, []string{"modules:write"}, true},
		{
			// The order-sensitivity bug: the previous gate compared slices
			// index-wise, so swapping two entries read as a scope change and
			// hard-deleted every affected member's keys.
			name:     "same set, different order",
			have:     []string{"modules:read", "providers:write"},
			retained: []string{"providers:write", "modules:read"},
			want:     true,
		},
		{
			// A WIDENING. Granting more permission must never destroy
			// credentials.
			name:     "strict superset retains",
			have:     []string{"modules:read"},
			retained: []string{"modules:read", "providers:write", "modules:write"},
			want:     true,
		},
		{
			name:     "reduction is not retained",
			have:     []string{"modules:read", "providers:write"},
			retained: []string{"modules:read"},
			want:     false,
		},
		{"admin wildcard retains everything", []string{"modules:write", "providers:write"}, []string{"admin"}, true},
		{"write implies read", []string{"modules:read"}, []string{"modules:write"}, true},
		{"read does not imply write", []string{"modules:write"}, []string{"modules:read"}, false},
		{
			// Membership removal: nothing is retained, so any credential
			// carrying a scope over-asks.
			name:     "empty retained revokes a scoped credential",
			have:     []string{"modules:read"},
			retained: nil,
			want:     false,
		},
		{
			// A credential that grants nothing cannot over-ask, so there is
			// nothing to gain by destroying it.
			name:     "scopeless credential is vacuously retained",
			have:     nil,
			retained: nil,
			want:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AuthorityRetained(tc.have, tc.retained); got != tc.want {
				t.Errorf("AuthorityRetained(%v, %v) = %v, want %v",
					tc.have, tc.retained, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Nil handling — a nil *Sweeper is a documented no-op receiver, relied on by
// every handler constructed without the revocation subsystem wired.
// ---------------------------------------------------------------------------

func TestNewSweeper_BothNil_ReturnsNil(t *testing.T) {
	if s := NewSweeper(nil, nil); s != nil {
		t.Errorf("NewSweeper(nil, nil) = %v, want nil so callers can store it directly", s)
	}
}

func TestNilSweeper_AllMethodsAreNoOps(t *testing.T) {
	var s *Sweeper
	ctx := context.Background()

	if out := s.OrgAuthorityReduced(ctx, "u", "o", nil, "r"); out != (Outcome{}) {
		t.Errorf("OrgAuthorityReduced on nil = %+v, want zero Outcome", out)
	}
	if out := s.OrgKeysOnly(ctx, "u", "o", nil, "r"); out != (Outcome{}) {
		t.Errorf("OrgKeysOnly on nil = %+v, want zero Outcome", out)
	}
	if out := s.UserDeprovisioned(ctx, "u", "r"); out != (Outcome{}) {
		t.Errorf("UserDeprovisioned on nil = %+v, want zero Outcome", out)
	}
}

func TestSweeper_KeysOnlyHalfWired_SkipsJWTFamily(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	s := NewSweeper(nil, repositories.NewAPIKeyRepository(db))
	if s == nil {
		t.Fatal("NewSweeper returned nil with one repository present")
	}
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1").
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["modules:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "test")
	if out.TokensRevoked {
		t.Error("TokensRevoked = true with no revocation repository wired")
	}
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1", out.KeysRevoked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OrgAuthorityReduced
// ---------------------------------------------------------------------------

func TestOrgAuthorityReduced_SweepsBothFamilies(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1").
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "removed from organization")
	if !out.TokensRevoked || out.KeysRevoked != 1 || out.Incomplete {
		t.Errorf("Outcome = %+v, want TokensRevoked=true KeysRevoked=1 Incomplete=false", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// The narrowing contract: a key entirely within the retained authority is
// listed and then LEFT ALONE. No DELETE is registered, so sqlmock fails the
// test if the sweep issues one.
func TestOrgAuthorityReduced_RetainsKeysWithinNewAuthority(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1").
		WillReturnRows(sqlmock.NewRows(akCols).
			AddRow("key-keep", "user-1", "org-1", "Reader Key", nil, "h", "tfr_a",
				[]byte(`["modules:read"]`), nil, nil, nil, time.Now(), nil).
			AddRow("key-drop", "user-1", "org-1", "Publisher Key", nil, "h", "tfr_b",
				[]byte(`["providers:write"]`), nil, nil, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-drop").
		WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1",
		[]string{"modules:read"}, "role template narrowed")
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1 (only the over-asking key)", out.KeysRevoked)
	}
	if out.KeysRetained != 1 {
		t.Errorf("KeysRetained = %d, want 1 (the key within the new authority)", out.KeysRetained)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// The JWT half failing must be reported, not swallowed: the caller surfaces it
// as revocation_incomplete.
func TestOrgAuthorityReduced_JWTHalfFails_ReportsIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("user-1").
		WillReturnError(errors.New("watermark write failed"))
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1").
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "test")
	if out.TokensRevoked {
		t.Error("TokensRevoked = true after the watermark write failed")
	}
	if !out.Incomplete {
		t.Error("Incomplete = false after the JWT half failed")
	}
	// The API-key half must still have run: one family failing does not
	// abandon the other.
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1 (key sweep must not be abandoned)", out.KeysRevoked)
	}
}

// The API-key half failing must be reported too. This is the direction the
// class is actually about -- the key family is the one that never expires, so
// a silent failure here leaves a permanently valid credential.
func TestOrgAuthorityReduced_APIKeyHalfFails_ReportsIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1").
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1").
		WillReturnError(errors.New("delete failed"))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "test")
	if !out.TokensRevoked {
		t.Error("TokensRevoked = false; the JWT half succeeded")
	}
	if out.KeysRevoked != 0 {
		t.Errorf("KeysRevoked = %d, want 0 (the delete failed)", out.KeysRevoked)
	}
	if !out.Incomplete {
		t.Error("Incomplete = false after the API-key half failed; the caller would report a fully closed incident")
	}
}

// A failure to even LIST the keys is equally incomplete: the sweep does not
// know what it did not revoke.
func TestOrgAuthorityReduced_APIKeyListFails_ReportsIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1").
		WillReturnError(errors.New("list failed"))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "test")
	if !out.Incomplete {
		t.Error("Incomplete = false after the key listing failed")
	}
}

// An empty organization ID cannot scope a key query; sweeping on it would
// either error or match nothing. Assert it short-circuits without issuing SQL.
func TestOrgAuthorityReduced_EmptyOrgID_SkipsKeySweep(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "", nil, "test")
	if out.KeysRevoked != 0 || out.Incomplete {
		t.Errorf("Outcome = %+v, want no key work and no incompleteness", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected SQL issued for an empty organization: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OrgKeysOnly — the IdP login path, which must NOT move the watermark.
// ---------------------------------------------------------------------------

func TestOrgKeysOnly_DoesNotTouchTheWatermark(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	// No watermark expectation is registered: moving it here would revoke the
	// session token this same request is about to mint (see the method's doc),
	// so sqlmock must see only the key statements.
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1").
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["modules:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.OrgKeysOnly(context.Background(), "user-1", "org-1", nil, "idp deprovision")
	if out.TokensRevoked {
		t.Error("TokensRevoked = true; OrgKeysOnly must leave the JWT watermark alone")
	}
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1", out.KeysRevoked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UserDeprovisioned — whole-principal offboarding, every org.
// ---------------------------------------------------------------------------

func TestUserDeprovisioned_RevokesEveryKeyEverywhere(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*WHERE ak.user_id").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(akCols).
			AddRow("key-a", "user-1", "org-1", "A", nil, "h", "tfr_a",
				[]byte(`["modules:read"]`), nil, nil, nil, time.Now(), nil).
			AddRow("key-b", "user-1", "org-2", "B", nil, "h", "tfr_b",
				[]byte(`["providers:write"]`), nil, nil, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-a").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-b").WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.UserDeprovisioned(context.Background(), "user-1", "scim: user deleted")
	if !out.TokensRevoked || out.KeysRevoked != 2 || out.Incomplete {
		t.Errorf("Outcome = %+v, want TokensRevoked=true KeysRevoked=2 Incomplete=false", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Deprovisioning retains NOTHING regardless of scopes: the principal holds no
// authority anywhere, so the retention filter must not apply here.
func TestUserDeprovisioned_IgnoresRetentionFilter(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*WHERE ak.user_id").
		WithArgs("user-1").
		WillReturnRows(keyRow("key-a", "user-1", "org-1", `["modules:read"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-a").WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.UserDeprovisioned(context.Background(), "user-1", "scim: user deleted")
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1 (a deprovisioned user retains nothing)", out.KeysRevoked)
	}
	if out.KeysRetained != 0 {
		t.Errorf("KeysRetained = %d, want 0", out.KeysRetained)
	}
}

func TestUserDeprovisioned_ListFails_ReportsIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*WHERE ak.user_id").
		WithArgs("user-1").
		WillReturnError(errors.New("list failed"))

	out := s.UserDeprovisioned(context.Background(), "user-1", "test")
	if !out.Incomplete {
		t.Error("Incomplete = false after the key listing failed")
	}
	if !out.TokensRevoked {
		t.Error("TokensRevoked = false; the JWT half succeeded before the listing failed")
	}
}

func TestUserDeprovisioned_OneDeleteFails_ContinuesAndReportsIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery("(?s)FROM api_keys ak.*WHERE ak.user_id").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(akCols).
			AddRow("key-a", "user-1", "org-1", "A", nil, "h", "tfr_a",
				[]byte(`["modules:read"]`), nil, nil, nil, time.Now(), nil).
			AddRow("key-b", "user-1", "org-2", "B", nil, "h", "tfr_b",
				[]byte(`["modules:read"]`), nil, nil, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-a").WillReturnError(errors.New("delete failed"))
	// The second key must still be attempted: one failure must not abandon the
	// rest of the sweep.
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-b").WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.UserDeprovisioned(context.Background(), "user-1", "test")
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1", out.KeysRevoked)
	}
	if !out.Incomplete {
		t.Error("Incomplete = false despite a failed key deletion")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the sweep abandoned the remaining keys after one failure: %v", err)
	}
}

func TestUserDeprovisioned_NoKeyRepository_StillMovesWatermark(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	s := NewSweeper(repositories.NewUserTokenRevocationRepository(db), nil)
	expectWatermark(mock, "user-1")

	out := s.UserDeprovisioned(context.Background(), "user-1", "test")
	if !out.TokensRevoked || out.Incomplete {
		t.Errorf("Outcome = %+v, want TokensRevoked=true Incomplete=false", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
