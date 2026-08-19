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
	db, mock, err := newSQLMock()
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
	if out := s.UserDeprovisioned(ctx, "u", repositories.OrgScopeAllOrganizations(), "r"); out != (Outcome{}) {
		t.Errorf("UserDeprovisioned on nil = %+v, want zero Outcome", out)
	}
}

func TestSweeper_KeysOnlyHalfWired_SkipsJWTFamily(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	s := NewSweeper(nil, repositories.NewAPIKeyRepository(db))
	if s == nil {
		t.Fatal("NewSweeper returned nil with one repository present")
	}
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["modules:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1", sqlmock.AnyArg()).
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
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1", sqlmock.AnyArg()).
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
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(akCols).
			AddRow("key-keep", "user-1", "org-1", "Reader Key", nil, "h", "tfr_a",
				[]byte(`["modules:read"]`), nil, nil, nil, time.Now(), nil).
			AddRow("key-drop", "user-1", "org-1", "Publisher Key", nil, "h", "tfr_b",
				[]byte(`["providers:write"]`), nil, nil, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-drop", sqlmock.AnyArg()).
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
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1", sqlmock.AnyArg()).
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
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1", sqlmock.AnyArg()).
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
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["modules:write"]`))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs("key-1", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	out := s.OrgKeysOnly(context.Background(), "user-1", "org-1", nil, "idp deprovision")

	// Incomplete is the assertion that makes this guard work, and its absence
	// made the guard INERT: flipping OrgKeysOnly to OrgAuthorityReduced -- the
	// exact change that permanently locks users out -- used to PASS.
	//
	// Why the obvious assertions do not catch it. sqlmock has no watermark
	// expectation registered, so a watermark write is REJECTED at the driver
	// rather than executed. The sweeper records that failure and carries on, so
	// TokensRevoked stays false (the write did not succeed) and
	// ExpectationsWereMet stays happy (it reports UNMET expectations, not
	// unexpected calls). The only trace left is Incomplete.
	//
	// Verified by mutation: with this check present, OrgKeysOnly ->
	// OrgAuthorityReduced fails; without it, it passes.
	if out.Incomplete {
		t.Error("Incomplete = true: OrgKeysOnly issued SQL this test did not expect. " +
			"The likely cause is a watermark write — moving the watermark here revokes " +
			"the session token this same request is about to mint, and the user can " +
			"never log in.")
	}
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

// GUARD credlifecycle-org-sweep-tenant-scope (identity #138). The org-scoped
// sweep names ONE organization, so both of its statements carry that
// organization as a tenant predicate — not just as the orgID filter they always
// had. A mutant that passes OrgScopeAllOrganizations() here renders the
// predicate as the literal TRUE and fails both expectations below.
func TestOrgAuthorityReduced_StatementsCarryTenantPredicate(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectQuery(`ak.organization_id = \$2 AND ak.organization_id = ANY\(\$3\)`).
		WithArgs("user-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(keyRow("key-1", "user-1", "org-1", `["providers:write"]`))
	mock.ExpectExec(`DELETE FROM api_keys WHERE id = \$1 AND organization_id = ANY\(\$2\)`).
		WithArgs("key-1", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	out := s.OrgAuthorityReduced(context.Background(), "user-1", "org-1", nil, "membership removed")
	if out.KeysRevoked != 1 || out.Incomplete {
		t.Errorf("Outcome = %+v, want KeysRevoked=1 Incomplete=false", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UserDeprovisioned — whole-principal offboarding, scoped to the organizations
// whose authority was actually withdrawn.
//
// Since identity v0.25.0 this is ONE scoped DELETE rather than a list followed
// by a revoke per key. The tests that pinned the loop's per-key behaviour (a
// raced key must not raise Incomplete; one failed delete must not abandon the
// rest) are re-pointed onto the set-based statement, where the same guarantees
// are properties of the single Exec: zero rows affected is an ordinary outcome,
// and there is no "rest" to abandon.
// ---------------------------------------------------------------------------

func TestUserDeprovisioned_PlatformWideScopeRevokesEverywhere(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	// Platform-wide renders as the literal TRUE, binding no organization
	// argument — the shape that must NEVER appear on a request-scoped path.
	mock.ExpectExec(`DELETE FROM api_keys WHERE user_id = \$1 AND TRUE`).
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 2))

	out := s.UserDeprovisioned(context.Background(), "user-1",
		repositories.OrgScopeAllOrganizations(), "user deleted by administrator")
	if !out.TokensRevoked || out.KeysRevoked != 2 || out.Incomplete {
		t.Errorf("Outcome = %+v, want TokensRevoked=true KeysRevoked=2 Incomplete=false", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// GUARD credlifecycle-sweep-tenant-scope (identity #160/#162). The organizations
// the caller's strip actually removed are carried into the DELETE as a
// predicate, so a sweep can never reach a tenant whose authority was untouched.
// Reverting the scope argument to OrgScopeAllOrganizations() drops the ANY(...)
// clause and fails this test.
func TestUserDeprovisioned_ScopedSweepCarriesTenantPredicate(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectExec(`DELETE FROM api_keys WHERE user_id = \$1 AND organization_id = ANY\(\$2\)`).
		WithArgs("user-1", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	out := s.UserDeprovisioned(context.Background(), "user-1",
		repositories.OrgScopeOrganizations("org-1"), "scim: user deleted")
	if out.KeysRevoked != 1 || out.Incomplete {
		t.Errorf("Outcome = %+v, want KeysRevoked=1 Incomplete=false", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// The fail-closed zero value sweeps nothing AND issues no statement: a caller
// that has not decided whose tenancy this is destroys no credentials.
func TestUserDeprovisioned_ZeroScopeRevokesNothing(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	// No ExpectExec for api_keys: any DELETE at all fails ExpectationsWereMet
	// via sqlmock's ordered, exhaustive matching.

	out := s.UserDeprovisioned(context.Background(), "user-1", repositories.OrgScope{}, "undecided")
	if out.KeysRevoked != 0 {
		t.Errorf("KeysRevoked = %d, want 0 for the fail-closed zero scope", out.KeysRevoked)
	}
	if out.Incomplete {
		t.Error("Incomplete = true; sweeping nothing under an empty scope is a decision, not a failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Deprovisioning retains NOTHING regardless of scopes: the principal holds no
// authority in the swept organizations, so the AuthorityRetained filter that
// governs the org-scoped sweep must not apply here.
func TestUserDeprovisioned_IgnoresRetentionFilter(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectExec("DELETE FROM api_keys WHERE user_id").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	out := s.UserDeprovisioned(context.Background(), "user-1",
		repositories.OrgScopeAllOrganizations(), "scim: user deleted")
	if out.KeysRevoked != 1 {
		t.Errorf("KeysRevoked = %d, want 1 (a deprovisioned user retains nothing)", out.KeysRevoked)
	}
	if out.KeysRetained != 0 {
		t.Errorf("KeysRetained = %d, want 0", out.KeysRetained)
	}
}

// A genuine database failure must still raise Incomplete: DeleteUserHandler
// refuses to delete the user on it, precisely because a surviving key would
// outlive its principal.
func TestUserDeprovisioned_DeleteFails_ReportsIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectExec("DELETE FROM api_keys WHERE user_id").
		WithArgs("user-1").
		WillReturnError(errors.New("delete failed"))

	out := s.UserDeprovisioned(context.Background(), "user-1",
		repositories.OrgScopeAllOrganizations(), "test")
	if !out.Incomplete {
		t.Error("Incomplete = false after the key sweep failed")
	}
	if !out.TokensRevoked {
		t.Error("TokensRevoked = false; the JWT half succeeded before the sweep failed")
	}
}

// Zero rows affected is the ordinary answer for a user who held no keys in the
// swept organizations — or whose keys a concurrent sweep already removed. It is
// the state the sweep exists to produce, so it must NOT raise Incomplete: doing
// so would block deprovisioning on the one condition proving there is nothing
// left to revoke.
func TestUserDeprovisioned_ZeroRowsIsNotIncomplete(t *testing.T) {
	s, mock, _ := newSweeperWithMock(t)

	expectWatermark(mock, "user-1")
	mock.ExpectExec("DELETE FROM api_keys WHERE user_id").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))

	out := s.UserDeprovisioned(context.Background(), "user-1",
		repositories.OrgScopeAllOrganizations(), "raced")
	if out.Incomplete {
		t.Error("Incomplete = true for a sweep that matched no rows; an already-absent key is the desired end state")
	}
	if out.KeysRevoked != 0 {
		t.Errorf("KeysRevoked = %d, want 0", out.KeysRevoked)
	}
}

func TestUserDeprovisioned_NoKeyRepository_StillMovesWatermark(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	s := NewSweeper(repositories.NewUserTokenRevocationRepository(db), nil)
	expectWatermark(mock, "user-1")

	out := s.UserDeprovisioned(context.Background(), "user-1",
		repositories.OrgScopeAllOrganizations(), "test")
	if !out.TokensRevoked || out.Incomplete {
		t.Errorf("Outcome = %+v, want TokensRevoked=true Incomplete=false", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
