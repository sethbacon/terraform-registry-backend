package adminfloor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
)

// ---------------------------------------------------------------------------
// Scope decoding
// ---------------------------------------------------------------------------

// TestParseRoleScopes covers BOTH encodings role_templates.scopes has in this
// estate — jsonb in the registry's public schema, TEXT[] in the shared
// identity schema (migration 000051 documents the split and had to write its
// backfill twice because of it).
//
// The identity-schema rows are the ones that matter most: a floor that read
// only the jsonb form would decode every identity-schema template as "no
// scopes", conclude the deployment has zero administrators, and refuse every
// removal — a guard that is wrong in the safe direction is still wrong, and it
// would have been discovered by an operator, not by a test.
func TestParseRoleScopes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"jsonb admin", `["admin"]`, []string{"admin"}},
		{"jsonb multiple", `["organizations:write","users:read"]`, []string{"organizations:write", "users:read"}},
		{"jsonb empty", `[]`, nil},
		{"text array admin", `{admin}`, []string{"admin"}},
		{"text array multiple", `{organizations:write,users:read}`, []string{"organizations:write", "users:read"}},
		{"text array quoted", `{"organizations:write","admin"}`, []string{"organizations:write", "admin"}},
		{"text array empty", `{}`, nil},
		{"null column", ``, nil},
		{"unparseable", `not-a-scope-list`, nil},
		{"truncated json", `["admin"`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRoleScopes([]byte(tt.raw))
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseRoleScopes(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestIsOrganizationAdmin(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"platform wildcard", []string{"admin"}, true},
		{"org owner", []string{"organizations:write", "modules:write"}, true},
		{"user manager", []string{"users:write", "organizations:write"}, true},
		{"publisher", []string{"modules:write", "providers:write", "organizations:read"}, false},
		{"viewer", []string{"modules:read", "organizations:read"}, false},
		{"org provisioner", []string{"organizations:create", "organizations:read"}, false},
		{"no role at all", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOrganizationAdmin(tt.scopes); got != tt.want {
				t.Fatalf("isOrganizationAdmin(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// twoConnections mirrors the real topology: platform_admins and the advisory
// lock on the registry connection, the membership tables on the identity one.
// They are separate mocks so each side's expectations are ordered
// independently, exactly as the two pools behave.
func twoConnections(t *testing.T) (registry, identity sqlmock.Sqlmock, g *Guard) {
	t.Helper()
	rdb, rmock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (registry): %v", err)
	}
	t.Cleanup(func() { rdb.Close() })
	idb, imock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	t.Cleanup(func() { idb.Close() })
	carrier, err := platformadmin.New(rdb, carrierTable)
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	return rmock, imock, New(carrier, idb)
}

// carrierTable is the name this package's tests construct the carrier with —
// the same one internal/api/router.go uses.
const carrierTable = "platform_admins"

// advisoryLockKey recomputes the key platformadmin derives from the carrier's
// QUOTED table name.
//
// Recomputed rather than read from the library, deliberately: it pins WHICH key
// is taken. The fixed constant this package used to hash would serialise two
// applications sharing one database against each other's unrelated
// revocations, and a return to that shape fails here on the argument rather
// than silently in a deployment nobody has yet.
var advisoryLockKey = func() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("terraform-suite-identity/platformadmin\x00"))
	_, _ = h.Write([]byte(`"` + carrierTable + `"`))
	return int64(h.Sum64())
}()

// expectLock queues the lock transaction. It carries no writes, so it is
// always rolled back.
func expectLock(registry sqlmock.Sqlmock) {
	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WithArgs(advisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// expectOrganizationState queues one invariant-B read.
func expectOrganizationState(identity sqlmock.Sqlmock, members ...[2]string) {
	identity.ExpectQuery("WHERE om.organization_id").WillReturnRows(orgStateRows(members...))
}

func orgStateRows(rows ...[2]string) *sqlmock.Rows {
	r := sqlmock.NewRows([]string{"user_id", "scopes"})
	for _, row := range rows {
		r.AddRow(row[0], []byte(row[1]))
	}
	return r
}

const (
	adminScopes    = `["admin"]`
	ownerScopes    = `["organizations:write","modules:write"]`
	viewerScopes   = `["modules:read","organizations:read"]`
	viewerTemplate = "role-viewer"
)

// runProtect calls Protect and reports whether write ran. A guard that refuses
// but still runs the write is the failure this returns rather than infers.
func runProtect(t *testing.T, g *Guard, ch Change) (err error, wrote bool) {
	t.Helper()
	err = g.Protect(context.Background(), ch, func(context.Context) error {
		wrote = true
		return nil
	})
	return err, wrote
}

// ---------------------------------------------------------------------------
// Invariant A — the deployment
//
// THE CARRIER IS THE ONLY SOURCE IT COUNTS, from migration 000054. The auth
// middleware strips `admin` from a session whose principal has no
// platform_admins row, so an admin-bearing role template administers nothing
// and a floor that counted one would answer "an administrator remains" while
// the deployment's last real one was deleted.
//
// Two shapes follow, and both are asserted below rather than inferred:
//
//   - only a change that DESTROYS THE PRINCIPAL can break invariant A. A
//     membership removal, a re-role and an organization deletion do not touch
//     platform_admins.
//   - a principal who holds no carrier row is not a reduction either.
//
// The tests that must show a read did NOT happen inject an ERROR into it
// rather than inspecting the mock afterwards: if the floor makes the read, the
// call returns ErrIndeterminate, which is a different value from both the
// refusal and the success. "The wrong query ran" then fails on the value being
// asserted instead of on a bare err != nil.
// ---------------------------------------------------------------------------

// expectCarrier queues the one registry read invariant A makes.
func expectCarrier(registry sqlmock.Sqlmock, holders ...string) {
	registry.ExpectQuery(`FROM "platform_admins"`).WillReturnRows(carrierRows(holders...))
}

// carrierRows is the carrier's full projection, which is what the mechanism
// scans: user_id, granted_by, granted_at, note.
func carrierRows(holders ...string) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"user_id", "granted_by", "granted_at", "note"})
	for _, h := range holders {
		rows.AddRow(h, nil, time.Now(), nil)
	}
	return rows
}

func expectUserExists(identity sqlmock.Sqlmock, userID string, exists bool) {
	identity.ExpectQuery("FROM users").WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(exists))
}

// TestProtect_RefusesDestroyingTheLastCarrierAdmin is the headline case: one
// administrator, held through the carrier, and a user deletion.
func TestProtect_RefusesDestroyingTheLastCarrierAdmin(t *testing.T) {
	registry, _, g := twoConnections(t)
	expectLock(registry)
	expectCarrier(registry, "user-admin")
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal — a refusal that still writes is not a guard")
	}
}

// TestProtect_AllowsDestroyingAnAdminWhenAnotherCarrierGrantRemains is the
// positive control. A guard that refused everything would satisfy the test
// above and look correct.
func TestProtect_AllowsDestroyingAnAdminWhenAnotherCarrierGrantRemains(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	expectCarrier(registry, "user-admin", "user-other")
	expectUserExists(identity, "user-other", true)
	// Invariant B still runs on a principal destruction; this one belongs to
	// no organization.
	identity.ExpectQuery("SELECT organization_id FROM organization_members").
		WithArgs("user-admin").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !wrote {
		t.Fatal("the write did not run — the floor is refusing a change that keeps an administrator")
	}
}

// TestProtect_DoesNotCountAnOrphanCarrierGrant. A carrier row whose user no
// longer resolves elevates nobody — both auth middlewares load the user before
// consulting the carrier — so counting it would let the last real
// administrator go against a count of two.
func TestProtect_DoesNotCountAnOrphanCarrierGrant(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	expectCarrier(registry, "user-admin", "user-deleted")
	expectUserExists(identity, "user-deleted", false)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal")
	}
}

// TestProtect_DestroyingThePrincipalStopsCountingItsOwnCarrierGrant.
// platform_admins carries no foreign key to users (migration 000051), so a
// deleted administrator's grant row SURVIVES the delete while elevating
// nobody. Counting it would let the deployment's last administrator delete
// themselves against their own record — which is what the refusal in
// TestProtect_RefusesDestroyingTheLastCarrierAdmin depends on, asserted here
// against a SECOND, orphaned row so the two are not the same test twice.
func TestProtect_DestroyingThePrincipalStopsCountingItsOwnCarrierGrant(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	expectCarrier(registry, "user-admin", "user-ghost")
	expectUserExists(identity, "user-ghost", false)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		DestroysPrincipal: true,
	})
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin — the principal's own row is not "+
			"exercisable once the principal is gone", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal")
	}
}

// TestProtect_AnAdminBearingTemplateIsNotAPlatformAdministrator IS THE CHANGE
// migration 000054 makes, asserted where it would otherwise be invisible.
//
// The deployment has an admin-bearing membership in an organization this change
// does not touch. Until this release that membership WAS platform-admin
// authority, `checkPlatformFloor` found it first and returned nil, and deleting
// the only carrier administrator was permitted. It confers nothing now, so the
// deletion must be refused.
//
// The union read is queued to SUCCEED, with a surviving admin-bearing
// membership in it. That is deliberate and it is the difference between a test
// that catches this and one that does not: injecting an ERROR there would only
// catch a floor that read the union AND propagated the failure, so a version
// that swallowed the error would still count the membership and still pass.
// Returning the row makes any floor that reads it answer nil — a different
// VALUE from the refusal asserted here — however it handles errors.
func TestProtect_AnAdminBearingTemplateIsNotAPlatformAdministrator(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "scopes"}).
			AddRow("org-untouched", "user-template", []byte(adminScopes)))
	expectCarrier(registry, "user-admin")
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		DestroysPrincipal: true,
	})
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin: the floor still counts an admin-bearing role "+
			"template as a platform administrator. It confers nothing from migration 000054, so "+
			"counting it permits the last real administrator to be deleted (#766)", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal")
	}
	// The other half of the same claim: the read is not merely discounted, it
	// is never made. An unmet expectation here is the pass.
	if err := identity.ExpectationsWereMet(); err == nil {
		t.Error("invariant A read admin-bearing memberships")
	}
}

// TestProtect_AMembershipChangeCannotBreakInvariantA. A removal does not touch
// platform_admins, so there is nothing for invariant A to decide and the
// carrier is not read at all. The carrier read is queued to FAIL: reaching it
// turns this into ErrIndeterminate.
//
// This is not a micro-optimisation. Reading the carrier here and refusing on an
// empty one would block every ordinary offboarding on a deployment that is
// already missing an administrator — a refusal with no hazard behind it, which
// detection (admin_floor_violations) exists to report instead.
func TestProtect_AMembershipChangeCannotBreakInvariantA(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	// An EMPTY carrier, queued to succeed: a floor that consults it here finds
	// no administrator and refuses, which is a different VALUE from the nil
	// asserted below however it treats read errors.
	expectCarrier(registry)
	expectOrganizationState(identity,
		[2]string{"user-owner", ownerScopes},
		[2]string{"user-viewer", viewerScopes},
	)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-viewer",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil — a membership change does not reduce carrier authority", err)
	}
	if !wrote {
		t.Fatal("the write did not run")
	}
}

// TestProtect_DestroyingANonHolderIsNotAReduction. The principal being deleted
// holds no carrier row, so the administrator count cannot fall and no user
// resolution is needed. The resolution query is queued to FAIL.
func TestProtect_DestroyingANonHolderIsNotAReduction(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	expectCarrier(registry, "user-admin")
	// Unordered on the identity side so the resolution below, which must NOT be
	// consumed, does not block the read that legitimately follows it. It
	// answers "this holder does not exist": a floor that scanned the holders
	// anyway would find none exercisable and refuse, which is a different VALUE
	// from the nil asserted below.
	identity.MatchExpectationsInOrder(false)
	expectUserExists(identity, "user-admin", false)
	identity.ExpectQuery("SELECT organization_id FROM organization_members").
		WithArgs("user-viewer").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-viewer",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil — deleting a principal with no carrier grant cannot "+
			"lower the administrator count", err)
	}
	if !wrote {
		t.Fatal("the write did not run")
	}
}

// TestProtect_ACarrierGrantSurvivesAMembershipOnlyDeprovision is the reason
// DestroysPrincipal exists rather than being assumed. A SCIM deprovision strips
// memberships; the user can still authenticate, so their carrier grant is still
// exercisable and the deployment still has an administrator.
func TestProtect_ACarrierGrantSurvivesAMembershipOnlyDeprovision(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	identity.ExpectQuery("SELECT organization_id FROM organization_members").
		WithArgs("user-admin").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow("org-1"))
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows([2]string{"user-admin", ownerScopes}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		RemovesMembership: true,
		DestroysPrincipal: false,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil — a membership-only deprovision leaves the carrier exercisable", err)
	}
	if !wrote {
		t.Fatal("the write did not run")
	}
}

// ---------------------------------------------------------------------------
// Invariant B — each organization
// ---------------------------------------------------------------------------

// TestProtect_RefusesRemovingAnOrganizationsLastAdministrator: other members
// remain, so the organization would exist with people in it and nobody able to
// manage them.
func TestProtect_RefusesRemovingAnOrganizationsLastAdministrator(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	// The deployment keeps a platform administrator elsewhere, so invariant A
	// passes and invariant B is genuinely REACHED — the inert-guard trap PR
	// #860 found, where every case short-circuits before the code under test.
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-owner", ownerScopes},
			[2]string{"user-viewer", viewerScopes},
		))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-owner",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if !errors.Is(err, ErrLastOrganizationAdmin) {
		t.Fatalf("err = %v, want ErrLastOrganizationAdmin", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal")
	}
}

// TestProtect_AllowsEmptyingAnOrganizationEntirely is the empty-organization
// decision, asserted rather than assumed.
//
// Removing the LAST member takes the organization to zero members. That is not
// a stranded organization, it is the empty set, and invariant B is vacuous
// over it. Refusing here would mean the only way to offboard the final person
// from a wound-down organization is to delete the organization.
func TestProtect_AllowsEmptyingAnOrganizationEntirely(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows([2]string{"user-owner", ownerScopes}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-owner",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil — emptying an organization is legitimate", err)
	}
	if !wrote {
		t.Fatal("the write did not run")
	}
}

// TestProtect_RefusesDemotingAnOrganizationsLastAdministrator. The membership
// row survives, so the organization keeps a member and loses its last
// administrator — the case emptying it does not cover.
func TestProtect_RefusesDemotingAnOrganizationsLastAdministrator(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	keeps := viewerTemplate
	identity.ExpectQuery("SELECT scopes FROM role_templates").
		WithArgs(keeps).
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(viewerScopes)))
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows([2]string{"user-owner", ownerScopes}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:              "user-owner",
		OrganizationIDs:     []string{"org-1"},
		KeepsRoleTemplateID: &keeps,
	})
	if !errors.Is(err, ErrLastOrganizationAdmin) {
		t.Fatalf("err = %v, want ErrLastOrganizationAdmin — demoting the sole "+
			"administrator leaves a member with nobody able to manage them", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal")
	}
}

// TestProtect_ClearingTheRoleOfTheLastAdministratorIsAlsoRefused. `PUT
// {"role_template_id": null}` is a demotion with no template named, and it is
// the one an implementation keyed off "the new template's scopes" would let
// through.
func TestProtect_ClearingTheRoleOfTheLastAdministratorIsAlsoRefused(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-owner", ownerScopes},
			[2]string{"user-viewer", viewerScopes},
		))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:              "user-owner",
		OrganizationIDs:     []string{"org-1"},
		KeepsRoleTemplateID: nil,
	})
	if !errors.Is(err, ErrLastOrganizationAdmin) {
		t.Fatalf("err = %v, want ErrLastOrganizationAdmin", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal")
	}
}

// TestProtect_AllowsRemovingANonAdministrator is the broad positive control
// for invariant B: the ordinary offboarding this guard must not interfere with.
func TestProtect_AllowsRemovingANonAdministrator(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-owner", ownerScopes},
			[2]string{"user-viewer", viewerScopes},
		))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-viewer",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !wrote {
		t.Fatal("the write did not run")
	}
}

// TestProtect_ChecksEveryOrganizationOfAWholePrincipalChange. A user deletion
// names no organization; the floor has to look in all of them, and refuse if
// ANY would be stranded. The second organization is the one that fails, so a
// loop that stopped after the first would report green.
func TestProtect_ChecksEveryOrganizationOfAWholePrincipalChange(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	// The principal holds no carrier grant, so invariant A passes at once and
	// invariant B is genuinely REACHED — the inert-guard trap where every case
	// short-circuits before the code under test.
	expectCarrier(registry, "user-platform")
	identity.ExpectQuery("SELECT organization_id FROM organization_members").
		WithArgs("user-owner").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow("org-1").AddRow("org-2"))
	// org-1 is fine: another owner remains.
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-owner", ownerScopes},
			[2]string{"user-other-owner", ownerScopes},
		))
	// org-2 is not: a viewer would be left behind with no administrator.
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-owner", ownerScopes},
			[2]string{"user-viewer", viewerScopes},
		))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-owner",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if !errors.Is(err, ErrLastOrganizationAdmin) {
		t.Fatalf("err = %v, want ErrLastOrganizationAdmin from the SECOND organization", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal")
	}
}

// ---------------------------------------------------------------------------
// Organization deletion — the path with no membership statement in it
// ---------------------------------------------------------------------------

// TestProtect_OrganizationDeletionNoLongerTouchesInvariantA.
// organization_members.organization_id is ON DELETE CASCADE, so deleting an
// organization removes every membership in it with no membership statement
// anywhere on the path. That USED to be able to take the deployment's last
// platform administrator away, because the authority rode on an
// admin-bearing role template inside one of those memberships.
//
// It cannot any more (migration 000054): the authority is in platform_admins,
// which an organization deletion does not touch. Both reads invariant A used to
// make are queued to FAIL, so a floor that still made either of them returns
// ErrIndeterminate instead of the nil asserted here.
func TestProtect_OrganizationDeletionNoLongerTouchesInvariantA(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	// Both reads are queued to SUCCEED and to report NO administrator: a floor
	// that made either one would refuse, which is a different VALUE from the
	// nil asserted below, whatever it does with read errors.
	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "scopes"}))
	expectCarrier(registry)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		OrganizationIDs:      []string{"org-1"},
		DeletesOrganizations: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil — deleting an organization cannot remove a carrier grant", err)
	}
	if !wrote {
		t.Fatal("the write did not run")
	}
}

// TestProtect_OrganizationDeletionSkipsInvariantB pins the decision rather
// than leaving it to be inferred: a deleted organization cannot be stranded,
// so no per-organization read happens at all. Asserted through the mock —
// an unexpected query fails, which is what makes this structural.
func TestProtect_OrganizationDeletionSkipsInvariantB(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	registry.ExpectRollback()

	if err, _ := runProtect(t, g, Change{
		OrganizationIDs:      []string{"org-1"},
		DeletesOrganizations: true,
	}); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if err := identity.ExpectationsWereMet(); err != nil {
		t.Fatalf("organization deletion read per-organization state it does not need: %v", err)
	}
}

// TestProtect_OrganizationDeletionNamingNoOrganizationIsIndeterminate. Without
// this, a Change{DeletesOrganizations: true} with an empty list would mean
// "affects every organization", and the floor would refuse every deletion in
// the deployment for no reason.
func TestProtect_OrganizationDeletionNamingNoOrganizationIsIndeterminate(t *testing.T) {
	registry, _, g := twoConnections(t)
	expectLock(registry)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{DeletesOrganizations: true})
	if !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("err = %v, want ErrIndeterminate", err)
	}
	if wrote {
		t.Fatal("the write ran for a deletion naming no organization")
	}
}

// ---------------------------------------------------------------------------
// Unresolved answers, and the absent guard
// ---------------------------------------------------------------------------

// TestProtect_AnUnreadableCarrierIsNotPermission. An outage must not read as
// "no administrators are recorded, so deleting this one is fine" — the exact
// inversion platform_admins.go's errIdentityUnavailable exists to stop.
func TestProtect_AnUnreadableCarrierIsNotPermission(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	registry.ExpectQuery(`FROM "platform_admins"`).WillReturnError(errors.New("connection refused"))
	// Invariant B is queued to SUCCEED and to be satisfied. Without it, a
	// mutant that swallowed the read error above would fall through to B,
	// return nil, and this test would fail on the value rather than passing for
	// the wrong reason on an unqueued query.
	identity.ExpectQuery("SELECT organization_id FROM organization_members").
		WithArgs("user-admin").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("err = %v, want ErrIndeterminate", err)
	}
	if wrote {
		t.Fatal("the write ran on an unresolved floor")
	}
}

// TestProtect_AFailedCarrierResolutionIsNotPermission covers the same rule on
// the cross-connection half, which is the one that fails independently when
// identity lives in another database: the carrier lists a holder and the
// identity store cannot say whether that holder still exists.
func TestProtect_AFailedCarrierResolutionIsNotPermission(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	expectCarrier(registry, "user-admin", "user-carrier")
	identity.ExpectQuery("FROM users").
		WithArgs("user-carrier").
		WillReturnError(errors.New("identity store unreachable"))
	// Same isolation as above.
	identity.ExpectQuery("SELECT organization_id FROM organization_members").
		WithArgs("user-admin").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("err = %v, want ErrIndeterminate", err)
	}
	if wrote {
		t.Fatal("the write ran on an unresolved floor")
	}
}

// TestProtect_TakesTheLockBeforeReadingAnything. Ordered expectations on the
// registry mock make this assertion structural: the BEGIN and the
// pg_advisory_xact_lock are queued ahead of the platform_admins read, so a
// version that checked first and locked afterwards fails on the mock, not on a
// race that reproduces one run in a thousand.
func TestProtect_TakesTheLockBeforeReadingAnything(t *testing.T) {
	registry, _, g := twoConnections(t)
	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WithArgs(advisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
	registry.ExpectQuery(`FROM "platform_admins"`).
		WillReturnRows(carrierRows())
	registry.ExpectRollback()

	// DestroysPrincipal, because that is the only shape that reaches the
	// carrier read this test is ordering the lock against.
	_, _ = runProtect(t, g, Change{
		UserID:            "user-admin",
		RemovesMembership: true,
		DestroysPrincipal: true,
	})
	if err := registry.ExpectationsWereMet(); err != nil {
		t.Fatalf("the lock was not taken before the floor was read: %v", err)
	}
}

// TestProtect_FailureToTakeTheLockIsNotPermission. If the lock cannot be
// taken, the check cannot be serialized, so its answer is not trustworthy.
func TestProtect_FailureToTakeTheLockIsNotPermission(t *testing.T) {
	registry, _, g := twoConnections(t)
	registry.ExpectBegin().WillReturnError(errors.New("pool exhausted"))

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("err = %v, want ErrIndeterminate", err)
	}
	if wrote {
		t.Fatal("the write ran without the lock")
	}
}

// TestProtect_ANamelessPrincipalIsIndeterminate. A Change with no user is a
// caller bug; answering "fine, go ahead" would let a mis-wired call site write
// unprotected forever.
func TestProtect_ANamelessPrincipalIsIndeterminate(t *testing.T) {
	registry, _, g := twoConnections(t)
	expectLock(registry)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{RemovesMembership: true})
	if !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("err = %v, want ErrIndeterminate", err)
	}
	if wrote {
		t.Fatal("the write ran for a change naming no principal")
	}
}

// TestProtect_NilGuardRunsTheWrite pins the documented "wired as a unit"
// convention, so the hundreds of handler tests that construct no floor keep
// working and nobody has to guess whether nil means open or closed.
func TestProtect_NilGuardRunsTheWrite(t *testing.T) {
	var g *Guard
	wrote := false
	if err := g.Protect(context.Background(), Change{UserID: "u"}, func(context.Context) error {
		wrote = true
		return nil
	}); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !wrote {
		t.Fatal("a nil guard must run the write")
	}
}

// TestProtect_HalfWiredGuardRefuses. A Guard holding one connection cannot
// evaluate either invariant, and must say so rather than wave the change
// through.
func TestProtect_HalfWiredGuardRefuses(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	carrier, err := platformadmin.New(db, carrierTable)
	if err != nil {
		t.Fatalf("platformadmin.New: %v", err)
	}
	for _, g := range []*Guard{New(carrier, nil), New(nil, db), New(nil, nil)} {
		wrote := false
		err := g.Protect(context.Background(), Change{UserID: "u"}, func(context.Context) error {
			wrote = true
			return nil
		})
		if !errors.Is(err, ErrIndeterminate) {
			t.Fatalf("err = %v, want ErrIndeterminate", err)
		}
		if wrote {
			t.Fatal("a half-wired guard ran the write")
		}
	}
}

// TestProtect_PropagatesTheWritesOwnError so a caller can still tell a floor
// refusal apart from a failed write.
func TestProtect_PropagatesTheWritesOwnError(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-viewer", viewerScopes},
			[2]string{"user-owner", ownerScopes},
		))
	registry.ExpectRollback()

	writeErr := errors.New("insert failed")
	err := g.Protect(context.Background(), Change{
		UserID:            "user-viewer",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	}, func(context.Context) error { return writeErr })
	if !errors.Is(err, writeErr) {
		t.Fatalf("err = %v, want the write's own error", err)
	}
	if errors.Is(err, ErrLastPlatformAdmin) || errors.Is(err, ErrLastOrganizationAdmin) {
		t.Fatal("a failed write was reported as a floor refusal")
	}
}

// sanity: the sentinels are distinct values, so errors.Is cannot conflate the
// two refusals a caller maps onto different messages.
func TestSentinelsAreDistinct(t *testing.T) {
	if errors.Is(ErrLastPlatformAdmin, ErrLastOrganizationAdmin) ||
		errors.Is(ErrLastOrganizationAdmin, ErrLastPlatformAdmin) ||
		errors.Is(ErrIndeterminate, ErrLastPlatformAdmin) {
		t.Fatal("the floor's sentinels are not distinguishable")
	}
	// And the driver's own "no rows" -- which roleTemplateScopes absorbs
	// legitimately -- is not mistakable for a refusal.
	if errors.Is(fmt.Errorf("wrapped: %w", sql.ErrNoRows), ErrIndeterminate) {
		t.Fatal("sql.ErrNoRows matches a floor sentinel")
	}
}
