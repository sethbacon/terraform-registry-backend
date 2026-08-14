package admin

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Issue #766, PR 2 — the management surface for the platform-admin carrier.
//
// Three properties are load-bearing here and each is asserted on an EXACT
// status and an EXACT payload, never on "not 200":
//
//  1. the last remaining platform administrator cannot be revoked, and an
//     ORPHANED grant does not count as one that remains;
//  2. grant and revoke write an audit entry naming the actor, the target and
//     the time — that entry IS the gap this design exists to close;
//  3. a grant whose user no longer resolves is listed and labelled, not hidden.

const (
	paCaller = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	paTarget = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	paThird  = "cccccccc-cccc-cccc-cccc-cccccccccccc"
)

var paGrantCols = []string{"user_id", "granted_by", "granted_at", "note"}

// carrierOver and outboxOver construct the two mechanisms these handlers run
// on, against the same mocked connection, with the same table names
// internal/api/router.go uses.
func carrierOver(t *testing.T, db *sql.DB) *platformadmin.Carrier {
	t.Helper()
	carrier, err := platformadmin.New(db, "platform_admins")
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	return carrier
}

func outboxOver(t *testing.T, db *sql.DB) *auditoutbox.Outbox {
	t.Helper()
	outbox, err := auditoutbox.New(db, "audit_outbox")
	if err != nil {
		t.Fatalf("auditoutbox.New: %v", err)
	}
	return outbox
}

// capturedJSONArg matches any bound argument and keeps it, so a test can assert on
// a value (the audit metadata JSON) that is built inside the handler.
type capturedJSONArg struct{ value driver.Value }

func (c *capturedJSONArg) Match(v driver.Value) bool {
	c.value = v
	return true
}

func (c *capturedJSONArg) metadata(t *testing.T) map[string]interface{} {
	t.Helper()
	raw, ok := c.value.([]byte)
	if !ok {
		t.Fatalf("audit metadata argument was %T (%v), want JSON bytes", c.value, c.value)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("audit metadata is not JSON: %v (%s)", err, raw)
	}
	return out
}

// newPlatformAdminRouter mounts the three routes with callerID as the acting
// principal. All three repositories share one mocked connection, which is also
// what makes sqlmock's ORDERED matching meaningful across them: the carrier
// read, the identity resolution and the audit write have to happen in the order
// the handler claims they do.
func newPlatformAdminRouter(t *testing.T, callerID string) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewPlatformAdminHandlers(
		carrierOver(t, db),
		repositories.NewUserRepository(db),
		outboxOver(t, db),
	)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", callerID)
		// The route gate is middleware.RequireScope(ScopeAdmin) in
		// router_routes.go; these tests exercise the handlers behind it, and
		// internal/api/platform_admin_routes_test.go owns the gate itself.
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Next()
	})
	r.GET("/platform-admins", h.ListPlatformAdmins)
	r.POST("/platform-admins", h.GrantPlatformAdmin)
	r.DELETE("/platform-admins/:user_id", h.RevokePlatformAdmin)
	return mock, r
}

// expectUserLookup primes one GetUserByID. found=false returns no rows, which
// is how a grant whose user was deleted resolves.
func expectUserLookup(mock sqlmock.Sqlmock, userID, email string, found bool) {
	q := mock.ExpectQuery("(?s)FROM users WHERE id").WithArgs(userID)
	if !found {
		q.WillReturnRows(sqlmock.NewRows(authUserCols))
		return
	}
	q.WillReturnRows(sqlmock.NewRows(authUserCols).
		AddRow(userID, email, "Name "+email, nil, time.Now(), time.Now()))
}

// expectAuditWrite primes the audit intent write and returns the metadata
// capture.
//
// The intent goes to `audit_outbox` on the carrier's OWN connection, inside the
// mutation's transaction (issue #766, migration 000052) — it is no longer a
// second write to audit_logs on the identity connection after the fact. Where
// it sits in the ordered expectations is therefore itself an assertion: between
// the mutation and the COMMIT. The relay delivers it to audit_logs afterwards
// (identity/auditoutbox's relay, covered by its own tests).
//
// The actor, action, resource type and resource id are matched EXACTLY: an
// audit row that records the wrong target, or attributes the change to nobody,
// is the same defect as no row at all. organization_id is asserted NULL because
// platform-admin is not an organization-owned fact and the platform-wide audit
// scope is what makes NULL-owner rows readable.
func expectAuditWrite(mock sqlmock.Sqlmock, actor, action, targetID string) *capturedJSONArg {
	meta := &capturedJSONArg{}
	mock.ExpectExec(`INSERT INTO "audit_outbox"`).
		WithArgs(
			sqlmock.AnyArg(), // event_id
			sqlmock.AnyArg(), // occurred_at
			action,
			actor,            // actor_user_id
			nil,              // actor_email — resolved at delivery when absent
			nil,              // organization_id
			"platform_admin", // resource_type
			targetID,         // resource_id
			sqlmock.AnyArg(), // ip_address
			meta,             // metadata
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	return meta
}

func paDo(t *testing.T, r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func paJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, w.Body.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// List — the orphan decision
// ---------------------------------------------------------------------------

// A grant whose user no longer resolves is SHOWN and LABELLED. Dropping it
// would hide a live row from the only surface that can remove it; showing it
// unlabelled would read as a corrupt record.
func TestListPlatformAdmins_OrphanGrantIsListedAndFlagged(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	granted := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT user_id, granted_by, granted_at, note FROM "platform_admins"`).
		WillReturnRows(sqlmock.NewRows(paGrantCols).
			AddRow(paCaller, nil, granted, nil).
			AddRow(paTarget, paCaller, granted.Add(time.Hour), "on call"))
	expectUserLookup(mock, paCaller, "caller@example.com", true)
	expectUserLookup(mock, paTarget, "", false) // deleted user: the orphan
	// paTarget's grantor is paCaller, already resolved and memoised — a second
	// lookup here would be an unexpected query and fail ExpectationsWereMet.

	w := paDo(t, r, http.MethodGet, "/platform-admins", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	items, ok := paJSON(t, w)["platform_admins"].([]interface{})
	if !ok || len(items) != 2 {
		t.Fatalf("platform_admins = %v, want 2 entries — an orphan must not be dropped", paJSON(t, w)["platform_admins"])
	}

	live := items[0].(map[string]interface{})
	if live["user_id"] != paCaller {
		t.Errorf("items[0].user_id = %v, want %s", live["user_id"], paCaller)
	}
	if live["user_resolved"] != true {
		t.Errorf("items[0].user_resolved = %v, want true", live["user_resolved"])
	}
	if live["email"] != "caller@example.com" {
		t.Errorf("items[0].email = %v, want caller@example.com", live["email"])
	}

	orphan := items[1].(map[string]interface{})
	if orphan["user_id"] != paTarget {
		t.Errorf("items[1].user_id = %v, want %s", orphan["user_id"], paTarget)
	}
	if orphan["user_resolved"] != false {
		t.Errorf("items[1].user_resolved = %v, want false — an unresolvable grant must say so", orphan["user_resolved"])
	}
	if _, present := orphan["email"]; present {
		t.Errorf("items[1] carries an email (%v) for a user that does not resolve", orphan["email"])
	}
	if orphan["granted_by_email"] != "caller@example.com" {
		t.Errorf("items[1].granted_by_email = %v, want caller@example.com — the provenance survives the holder", orphan["granted_by_email"])
	}
	if orphan["note"] != "on call" {
		t.Errorf("items[1].note = %v, want \"on call\"", orphan["note"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestListPlatformAdmins_CarrierReadFails(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)
	mock.ExpectQuery(`SELECT user_id, granted_by, granted_at, note FROM "platform_admins"`).
		WillReturnError(errDB)

	w := paDo(t, r, http.MethodGet, "/platform-admins", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "Failed to list platform administrators" {
		t.Errorf("error = %v, want the carrier-read message", got)
	}
}

// An identity-store FAILURE is not "this user does not exist". Serving a
// partial list, in which the unreachable rows look like orphans, would
// misreport who holds the highest privilege in the product.
func TestListPlatformAdmins_IdentityFailureIsNotAnOrphan(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)
	mock.ExpectQuery(`SELECT user_id, granted_by, granted_at, note FROM "platform_admins"`).
		WillReturnRows(sqlmock.NewRows(paGrantCols).AddRow(paCaller, nil, time.Now(), nil))
	mock.ExpectQuery("(?s)FROM users WHERE id").WithArgs(paCaller).WillReturnError(errDB)

	w := paDo(t, r, http.MethodGet, "/platform-admins", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "Failed to resolve platform administrator identities" {
		t.Errorf("error = %v, want the identity-resolution message", got)
	}
}

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

func TestGrantPlatformAdmin_WritesGrantAndAuditEntry(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	granted := time.Date(2026, 8, 12, 13, 0, 0, 0, time.UTC)
	expectUserLookup(mock, paTarget, "target@example.com", true)
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "platform_admins"`).
		WithArgs(paTarget, paCaller, "incident 42").
		WillReturnRows(sqlmock.NewRows(paGrantCols).AddRow(paTarget, paCaller, granted, "incident 42"))
	meta := expectAuditWrite(mock, paCaller, "platform_admin.granted", paTarget)
	mock.ExpectCommit()
	expectUserLookup(mock, paCaller, "caller@example.com", true) // grantor, for the rendered row

	w := paDo(t, r, http.MethodPost, "/platform-admins",
		`{"user_id":"`+paTarget+`","note":"incident 42"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}

	item, ok := paJSON(t, w)["platform_admin"].(map[string]interface{})
	if !ok {
		t.Fatalf("response has no platform_admin object: %s", w.Body.String())
	}
	if item["user_id"] != paTarget {
		t.Errorf("user_id = %v, want %s", item["user_id"], paTarget)
	}
	if item["granted_by"] != paCaller {
		t.Errorf("granted_by = %v, want the acting principal %s", item["granted_by"], paCaller)
	}
	if item["granted_at"] != granted.Format(time.RFC3339) {
		t.Errorf("granted_at = %v, want %v", item["granted_at"], granted.Format(time.RFC3339))
	}

	md := meta.metadata(t)
	if md["target_user_id"] != paTarget {
		t.Errorf("audit metadata target_user_id = %v, want %s", md["target_user_id"], paTarget)
	}
	if md["target_user_email"] != "target@example.com" {
		t.Errorf("audit metadata target_user_email = %v, want target@example.com", md["target_user_email"])
	}
	if md["note"] != "incident 42" {
		t.Errorf("audit metadata note = %v, want \"incident 42\"", md["note"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// Granting to a UUID nobody answers to would mint an orphan on purpose. The
// mock is primed with NO carrier INSERT, so a write would be an unexpected
// query — this asserts the refusal, not just the status.
func TestGrantPlatformAdmin_UnknownUser(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)
	expectUserLookup(mock, paTarget, "", false)

	w := paDo(t, r, http.MethodPost, "/platform-admins", `{"user_id":"`+paTarget+`"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "User not found" {
		t.Errorf("error = %v, want \"User not found\"", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (was a grant written for a nonexistent user?): %v", err)
	}
}

// A re-grant leaves the original provenance alone and says so, rather than
// reporting a success that rewrote who conferred the privilege.
func TestGrantPlatformAdmin_AlreadyGranted(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)
	expectUserLookup(mock, paTarget, "target@example.com", true)
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "platform_admins"`).
		WillReturnRows(sqlmock.NewRows(paGrantCols)) // ON CONFLICT DO NOTHING
	mock.ExpectRollback()

	w := paDo(t, r, http.MethodPost, "/platform-admins", `{"user_id":"`+paTarget+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "User already holds platform-admin" {
		t.Errorf("error = %v, want the already-granted message", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (an audit entry for a grant that did not happen?): %v", err)
	}
}

func TestGrantPlatformAdmin_RejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"not a uuid", `{"user_id":"not-a-uuid"}`, "user_id must be a UUID"},
		{"missing user_id", `{"note":"x"}`, "Invalid request body"},
		{"note too long", `{"user_id":"` + paTarget + `","note":"` + string(make([]byte, 0)) + longNote() + `"}`,
			"note must be at most 500 characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, r := newPlatformAdminRouter(t, paCaller)
			w := paDo(t, r, http.MethodPost, "/platform-admins", tt.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
			}
			if got := paJSON(t, w)["error"]; got != tt.want {
				t.Errorf("error = %v, want %q", got, tt.want)
			}
			// Nothing was primed: a 400 must be decided before any query.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

func longNote() string {
	b := make([]byte, maxPlatformAdminNoteLen+1)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Revoke — the last-standing guard
// ---------------------------------------------------------------------------

// expectRevokeLock primes BEGIN + the locking read with the given carrier rows.
func expectRevokeLock(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)FROM "platform_admins".*FOR UPDATE`).WillReturnRows(rows)
}

func TestRevokePlatformAdmin_WritesAuditEntry(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	now := time.Now()
	// The target's address is resolved BEFORE the lock now, because the audit
	// intent is written inside the revoking transaction and has to be complete
	// by the time the DELETE runs.
	expectUserLookup(mock, paTarget, "target@example.com", true)
	expectRevokeLock(mock, sqlmock.NewRows(paGrantCols).
		AddRow(paCaller, nil, now, nil).
		AddRow(paTarget, paCaller, now, nil))
	expectUserLookup(mock, paCaller, "caller@example.com", true) // the remaining admin
	mock.ExpectExec(`DELETE FROM "platform_admins" WHERE user_id`).
		WithArgs(paTarget).
		WillReturnResult(sqlmock.NewResult(0, 1))
	meta := expectAuditWrite(mock, paCaller, "platform_admin.revoked", paTarget)
	mock.ExpectCommit()

	w := paDo(t, r, http.MethodDelete, "/platform-admins/"+paTarget, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["message"]; got != "Platform administrator revoked" {
		t.Errorf("message = %v, want the revoked message", got)
	}

	md := meta.metadata(t)
	if md["target_user_id"] != paTarget {
		t.Errorf("audit metadata target_user_id = %v, want %s", md["target_user_id"], paTarget)
	}
	if md["target_user_email"] != "target@example.com" {
		t.Errorf("audit metadata target_user_email = %v, want target@example.com", md["target_user_email"])
	}
	if md["self_revocation"] != false {
		t.Errorf("audit metadata self_revocation = %v, want false", md["self_revocation"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// SELF-REVOCATION IS ALLOWED while another administrator remains. The hazard
// the guard defends against is reaching ZERO administrators, which is a
// different question from who is asking.
func TestRevokePlatformAdmin_SelfRevocationAllowedWhenAnotherRemains(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	now := time.Now()
	expectUserLookup(mock, paCaller, "caller@example.com", true) // the target, for the record
	expectRevokeLock(mock, sqlmock.NewRows(paGrantCols).
		AddRow(paCaller, nil, now, nil).
		AddRow(paTarget, paCaller, now, nil))
	expectUserLookup(mock, paTarget, "target@example.com", true) // the remaining admin
	mock.ExpectExec(`DELETE FROM "platform_admins" WHERE user_id`).
		WithArgs(paCaller).
		WillReturnResult(sqlmock.NewResult(0, 1))
	meta := expectAuditWrite(mock, paCaller, "platform_admin.revoked", paCaller)
	mock.ExpectCommit()

	w := paDo(t, r, http.MethodDelete, "/platform-admins/"+paCaller, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (self-revocation is permitted): %s", w.Code, w.Body.String())
	}
	if md := meta.metadata(t); md["self_revocation"] != true {
		t.Errorf("audit metadata self_revocation = %v, want true", md["self_revocation"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// GUARD platform-admin-last-standing. No DELETE and no audit entry are primed,
// so a revocation that slipped through would be an unexpected query as well as
// a wrong status.
func TestRevokePlatformAdmin_RefusesTheLastAdministrator(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	expectUserLookup(mock, paCaller, "caller@example.com", true) // the target, for the record
	expectRevokeLock(mock, sqlmock.NewRows(paGrantCols).
		AddRow(paCaller, nil, time.Now(), nil))
	mock.ExpectRollback()

	w := paDo(t, r, http.MethodDelete, "/platform-admins/"+paCaller, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	body := paJSON(t, w)
	if body["error"] != "Cannot revoke the last platform administrator" {
		t.Errorf("error = %v, want the last-administrator refusal", body["error"])
	}
	if body["details"] == nil || body["details"] == "" {
		t.Error("the refusal carries no details saying how to proceed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (was the last administrator deleted?): %v", err)
	}
}

// An ORPHANED grant is not an administrator. Both auth middlewares load the
// user before consulting the carrier, so a deleted user's row elevates nobody
// — counting it would let the last real administrator revoke themselves
// against a count of two.
func TestRevokePlatformAdmin_OrphanGrantDoesNotCountAsTheRemainingAdmin(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	now := time.Now()
	expectUserLookup(mock, paCaller, "caller@example.com", true) // the target, for the record
	expectRevokeLock(mock, sqlmock.NewRows(paGrantCols).
		AddRow(paCaller, nil, now, nil).
		AddRow(paThird, nil, now, "grant left behind by a deleted user"))
	expectUserLookup(mock, paThird, "", false)
	mock.ExpectRollback()

	w := paDo(t, r, http.MethodDelete, "/platform-admins/"+paCaller, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 — an orphan grant is a row, not an administrator: %s",
			w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "Cannot revoke the last platform administrator" {
		t.Errorf("error = %v, want the last-administrator refusal", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// An identity store that cannot answer must not be read as "every other grant
// is an orphan". That would turn an outage into the lockout the guard exists to
// prevent, which is why the resolver keeps failure and absence apart.
func TestRevokePlatformAdmin_IdentityFailureBlocksTheRevocation(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	now := time.Now()
	// The pre-resolve of the target's address fails too. It is SWALLOWED — the
	// record simply carries no address — while the same failure inside the
	// last-standing guard aborts the revocation. The two are different
	// questions and must not collapse.
	mock.ExpectQuery("(?s)FROM users WHERE id").WithArgs(paCaller).WillReturnError(errDB)
	expectRevokeLock(mock, sqlmock.NewRows(paGrantCols).
		AddRow(paCaller, nil, now, nil).
		AddRow(paTarget, nil, now, nil))
	mock.ExpectQuery("(?s)FROM users WHERE id").WithArgs(paTarget).WillReturnError(errDB)
	mock.ExpectRollback()

	w := paDo(t, r, http.MethodDelete, "/platform-admins/"+paCaller, "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "Failed to verify remaining platform administrators" {
		t.Errorf("error = %v, want the verification-failure message (NOT the last-admin refusal, "+
			"and NOT a success)", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (was anything deleted?): %v", err)
	}
}

func TestRevokePlatformAdmin_NotAnAdministrator(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	expectUserLookup(mock, paTarget, "target@example.com", true) // the target, for the record
	expectRevokeLock(mock, sqlmock.NewRows(paGrantCols).
		AddRow(paCaller, nil, time.Now(), nil))
	mock.ExpectRollback()

	w := paDo(t, r, http.MethodDelete, "/platform-admins/"+paTarget, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "User does not hold platform-admin" {
		t.Errorf("error = %v, want the not-an-admin message", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRevokePlatformAdmin_InvalidUserID(t *testing.T) {
	mock, r := newPlatformAdminRouter(t, paCaller)

	w := paDo(t, r, http.MethodDelete, "/platform-admins/not-a-uuid", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "user_id must be a UUID" {
		t.Errorf("error = %v, want the UUID message", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// A handler constructed without a user repository cannot resolve anyone, so
// every grant would look like an orphan. It answers 500 instead — the same
// fail-closed direction as an identity outage, and the reason the nil check in
// userResolver.get is a branch rather than a comment.
func TestListPlatformAdmins_NoUserRepositoryFailsClosed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewPlatformAdminHandlers(carrierOver(t, db), nil, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", paCaller); c.Next() })
	r.GET("/platform-admins", h.ListPlatformAdmins)

	mock.ExpectQuery(`SELECT user_id, granted_by, granted_at, note FROM "platform_admins"`).
		WillReturnRows(sqlmock.NewRows(paGrantCols).AddRow(paCaller, nil, time.Now(), nil))

	w := paDo(t, r, http.MethodGet, "/platform-admins", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — an unresolvable listing must not be served as a "+
			"complete one: %s", w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != "Failed to resolve platform administrator identities" {
		t.Errorf("error = %v, want the identity-resolution message", got)
	}
}

// ---------------------------------------------------------------------------
// Issue #766 PR 3 — the mutation cannot commit unaudited
// ---------------------------------------------------------------------------

// newUnauditablePlatformAdminRouter mounts the routes with NO audit outbox, so
// every attempt to record a change fails. That is the failure injection the
// durability requirement asks for: the audit destination is unavailable, and
// the question is what happens to the mutation.
func newUnauditablePlatformAdminRouter(t *testing.T, callerID string) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewPlatformAdminHandlers(
		carrierOver(t, db),
		repositories.NewUserRepository(db),
		nil, // no outbox: nowhere to record the change
	)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", callerID)
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Next()
	})
	r.POST("/platform-admins", h.GrantPlatformAdmin)
	r.DELETE("/platform-admins/:user_id", h.RevokePlatformAdmin)
	return mock, r
}

// GUARD durable-audit-atomic (grant, through the handler). The carrier INSERT
// runs, the audit record cannot be written, and the transaction is ROLLED BACK
// — there is no committed grant to go looking for afterwards.
//
// Before this change the same situation produced a 201 and a platform
// administrator nobody could account for. The status is asserted exactly, and
// so is the message, because "500" alone would not distinguish this from the
// grant itself failing — and an operator has to know the privilege did NOT
// change hands.
func TestGrantPlatformAdmin_UnauditableGrantIsRolledBack(t *testing.T) {
	mock, r := newUnauditablePlatformAdminRouter(t, paCaller)

	expectUserLookup(mock, paTarget, "target@example.com", true)
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "platform_admins"`).
		WithArgs(paTarget, paCaller, nil).
		WillReturnRows(sqlmock.NewRows(paGrantCols).AddRow(paTarget, paCaller, time.Now(), nil))
	// No ExpectCommit. A commit is an unexpected call and fails the test, which
	// is the assertion that matters: the grant did not land.
	mock.ExpectRollback()

	w := paDo(t, r, http.MethodPost, "/platform-admins", `{"user_id":"`+paTarget+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — an unauditable grant must be refused, not reported as created: %s",
			w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != errUnauditableMutation {
		t.Errorf("error = %v, want %q", got, errUnauditableMutation)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the unaudited grant committed): %v", err)
	}
}

// GUARD durable-audit-atomic (revoke, through the handler). Same shape: the
// DELETE runs inside the transaction, the record cannot be written, nothing
// commits, and the caller is told the privilege was NOT removed.
func TestRevokePlatformAdmin_UnauditableRevocationIsRolledBack(t *testing.T) {
	mock, r := newUnauditablePlatformAdminRouter(t, paCaller)

	now := time.Now()
	expectUserLookup(mock, paTarget, "target@example.com", true)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)FROM "platform_admins".*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows(paGrantCols).
			AddRow(paCaller, nil, now, nil).
			AddRow(paTarget, paCaller, now, nil))
	expectUserLookup(mock, paCaller, "caller@example.com", true) // the remaining admin
	mock.ExpectExec(`DELETE FROM "platform_admins" WHERE user_id`).
		WithArgs(paTarget).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	w := paDo(t, r, http.MethodDelete, "/platform-admins/"+paTarget, "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — an unauditable revocation must be refused: %s",
			w.Code, w.Body.String())
	}
	if got := paJSON(t, w)["error"]; got != errUnauditableMutation {
		t.Errorf("error = %v, want %q", got, errUnauditableMutation)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the unaudited revocation committed): %v", err)
	}
}
