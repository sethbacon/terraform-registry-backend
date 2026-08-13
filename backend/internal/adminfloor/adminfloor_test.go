package adminfloor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
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
	return rmock, imock, New(rdb, idb)
}

// expectLock queues the lock transaction. It carries no writes, so it is
// always rolled back.
func expectLock(registry sqlmock.Sqlmock) {
	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WithArgs(advisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func adminBearingRows(rows ...[3]string) *sqlmock.Rows {
	r := sqlmock.NewRows([]string{"organization_id", "user_id", "scopes"})
	for _, row := range rows {
		r.AddRow(row[0], row[1], []byte(row[2]))
	}
	return r
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
// ---------------------------------------------------------------------------

// TestProtect_RefusesRemovingTheLastPlatformAdmin is the headline case: one
// administrator, held through the role-template union (the shape a deployment
// bootstrapped by the setup wizard has, because setup predates the carrier),
// an empty carrier, and a removal.
func TestProtect_RefusesRemovingTheLastPlatformAdmin(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin", err)
	}
	if wrote {
		t.Fatal("the write ran despite the refusal — a refusal that still writes is not a guard")
	}
}

// TestProtect_AllowsWhenAnotherUnionAdminRemains is the positive control. A
// guard that refused everything would satisfy the test above and look correct.
func TestProtect_AllowsWhenAnotherUnionAdminRemains(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows(
			[3]string{"org-1", "user-other", adminScopes},
			[3]string{"org-1", "user-admin", adminScopes},
		))
	// Invariant B still runs: org-1 keeps user-other, who holds `admin`.
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-other", adminScopes},
			[2]string{"user-admin", adminScopes},
		))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !wrote {
		t.Fatal("the write did not run — the floor is refusing a change that keeps an administrator")
	}
}

// TestProtect_AllowsWhenAnExercisableCarrierGrantRemains: the union side goes
// to zero but the carrier still names a live user, so effective admin
// (`carrier OR union`) is non-zero and the change is not a lockout.
func TestProtect_AllowsWhenAnExercisableCarrierGrantRemains(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-carrier"))
	identity.ExpectQuery("FROM users").
		WithArgs("user-carrier").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows(
			[2]string{"user-admin", adminScopes},
			[2]string{"user-owner", ownerScopes},
		))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !wrote {
		t.Fatal("the write did not run despite a live carrier grant remaining")
	}
}

// TestProtect_DoesNotCountAnOrphanCarrierGrant. A carrier row whose user no
// longer resolves elevates nobody — both auth middlewares load the user before
// consulting the carrier — so counting it would let the last real
// administrator go against a count of one.
func TestProtect_DoesNotCountAnOrphanCarrierGrant(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-deleted"))
	identity.ExpectQuery("FROM users").
		WithArgs("user-deleted").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
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
// themselves against their own record.
func TestProtect_DestroyingThePrincipalStopsCountingItsOwnCarrierGrant(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-admin"))
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

// TestProtect_ACarrierGrantSurvivesAMembershipOnlyDeprovision is the other
// half of the pair above, and the reason DestroysPrincipal exists rather than
// being assumed. A SCIM deprovision strips memberships; the user can still
// authenticate, so their carrier grant is still exercisable and the deployment
// still has an administrator.
func TestProtect_ACarrierGrantSurvivesAMembershipOnlyDeprovision(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-admin"))
	identity.ExpectQuery("FROM users").
		WithArgs("user-admin").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	identity.ExpectQuery("SELECT organization_id FROM organization_members").
		WithArgs("user-admin").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow("org-1"))
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows([2]string{"user-admin", adminScopes}))
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

// TestProtect_ReRoleOntoAnotherAdminTemplateIsNotAReduction. Moving the only
// administrator from one admin-bearing template to another leaves the
// deployment exactly as administered as it was.
func TestProtect_ReRoleOntoAnotherAdminTemplateIsNotAReduction(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	keeps := "role-admin-2"
	identity.ExpectQuery("SELECT scopes FROM role_templates").
		WithArgs(keeps).
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(adminScopes)))
	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows([2]string{"user-admin", adminScopes}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:              "user-admin",
		OrganizationIDs:     []string{"org-1"},
		KeepsRoleTemplateID: &keeps,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !wrote {
		t.Fatal("the write did not run")
	}
}

// TestProtect_KeepsAuthorityThroughAnUntouchedOrganization. The principal
// administers two organizations and is being removed from one; they are still
// the deployment's administrator through the other.
func TestProtect_KeepsAuthorityThroughAnUntouchedOrganization(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows(
			[3]string{"org-1", "user-admin", adminScopes},
			[3]string{"org-2", "user-admin", adminScopes},
		))
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(orgStateRows([2]string{"user-admin", adminScopes}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
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
	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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
	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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

// TestProtect_RefusesDeletingTheOrganizationHoldingTheLastAdmin.
// organization_members.organization_id is ON DELETE CASCADE, so deleting an
// organization removes every membership in it with no membership statement
// anywhere on the path — including the one that carries the deployment's only
// platform-admin role template.
func TestProtect_RefusesDeletingTheOrganizationHoldingTheLastAdmin(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		OrganizationIDs:      []string{"org-1"},
		DeletesOrganizations: true,
	})
	if !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("err = %v, want ErrLastPlatformAdmin", err)
	}
	if wrote {
		t.Fatal("the organization was deleted despite holding the last platform administrator")
	}
}

// TestProtect_AllowsDeletingAnOrganizationWhoseAdminIsAdminElsewhere is the
// positive control, and the case that separates "this organization is deleted"
// from "this principal loses authority": the same person administers another
// organization, so the deployment keeps an administrator.
func TestProtect_AllowsDeletingAnOrganizationWhoseAdminIsAdminElsewhere(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows(
			[3]string{"org-1", "user-admin", adminScopes},
			[3]string{"org-2", "user-admin", adminScopes},
		))
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		OrganizationIDs:      []string{"org-1"},
		DeletesOrganizations: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
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

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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

// TestProtect_AnUnreadableIdentityStoreIsNotPermission. An outage must not
// read as "no administrators are recorded, so removing this one is fine" — the
// exact inversion platform_admins.go's errIdentityUnavailable exists to stop.
func TestProtect_AnUnreadableIdentityStoreIsNotPermission(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	boom := errors.New("connection refused")
	identity.ExpectQuery("FROM organization_members").WillReturnError(boom)
	// Invariant B is queued to SUCCEED and to be satisfied. Without it, a
	// mutant that swallowed the read error above would fall through to an
	// unqueued query, fail there, and still return ErrIndeterminate — the test
	// would pass for the wrong reason and prove nothing about the branch it
	// names. Verified by making checkPlatformFloor return nil on error and
	// watching this fail.
	expectOrganizationState(identity,
		[2]string{"user-admin", adminScopes},
		[2]string{"user-owner", ownerScopes},
	)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
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
// identity lives in another database.
func TestProtect_AFailedCarrierResolutionIsNotPermission(t *testing.T) {
	registry, identity, g := twoConnections(t)
	expectLock(registry)

	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-carrier"))
	identity.ExpectQuery("FROM users").
		WithArgs("user-carrier").
		WillReturnError(errors.New("identity store unreachable"))
	// Same isolation as above: invariant B would pass, so only the carrier
	// resolution failure can produce the refusal.
	expectOrganizationState(identity,
		[2]string{"user-admin", adminScopes},
		[2]string{"user-owner", ownerScopes},
	)
	registry.ExpectRollback()

	err, wrote := runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
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
	registry, identity, g := twoConnections(t)
	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WithArgs(advisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-1", "user-admin", adminScopes}))
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	registry.ExpectRollback()

	_, _ = runProtect(t, g, Change{
		UserID:            "user-admin",
		OrganizationIDs:   []string{"org-1"},
		RemovesMembership: true,
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

	for _, g := range []*Guard{New(db, nil), New(nil, db), New(nil, nil)} {
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
	identity.ExpectQuery("FROM organization_members").
		WillReturnRows(adminBearingRows([3]string{"org-9", "user-platform", adminScopes}))
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
