package admin

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Issue #766 on the IdP group-mapping reconciliation — the authority reduction
// nobody requests.
//
// reconcileGroupMemberships' revoke branch fires when NO current IdP group maps
// to a managed organization, so a group deleted or renamed at the identity
// provider offboards its members on their next login. If one of them was the
// deployment's last administrator, that login was the moment the deployment
// stopped having one, and the only trace was an INFO line saying the mapping
// had been applied.
//
// THE REFUSAL HERE IS A SKIP, NOT AN ERROR, and that is deliberate: this runs
// inside the login it is about, and failing the login would lock out exactly
// the person who has to log in to fix the mapping. What these tests pin is that
// the skip is real — the membership survives — rather than a log line over a
// write that happened anyway.

// flooredAuthHandlers builds AuthHandlers with a real floor over two mocked
// connections. The identity mock is the same handle the handlers use, so the
// reconciliation's reads and the floor's reads interleave on one ordered mock,
// exactly as they do against one database.
func flooredAuthHandlers(t *testing.T, cfg *config.Config) (*AuthHandlers, sqlmock.Sqlmock, sqlmock.Sqlmock) {
	t.Helper()
	idb, identity, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	t.Cleanup(func() { idb.Close() })
	rdb, registry, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (registry): %v", err)
	}
	t.Cleanup(func() { rdb.Close() })

	h, err := NewAuthHandlers(cfg, idb, nil, nil, auth.NewMemoryStateStore(time.Hour),
		WithAdminFloor(adminfloor.New(carrierOver(t, rdb), idb)))
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}
	return h, identity, registry
}

// idpRevokeConfig maps one group to one organization, so calling
// applyGroupMappings with NO groups puts the reconciliation on its revoke
// branch for that organization.
func idpRevokeConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "editor"},
	}
	return cfg
}

// expectManagedOrgLookup queues the two reads every branch makes first: resolve
// the managed organization, then check the subject's membership in it.
func expectManagedOrgLookup(identity sqlmock.Sqlmock) {
	identity.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(authOrgCols).
			AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))
	roleID := "rt-admin"
	identity.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
		WillReturnRows(sqlmock.NewRows(authMemberCols).
			AddRow("org-1", "user-1", &roleID, time.Now()))
	// The membership FACT is still identity's; the role it holds is registry's.
	expectRegistryRoleFor(identity, registryRole{id: roleID})
}

// TestIdPReconcile_SkipsADeprovisionThatWouldStrandTheOrganization.
//
// This used to be a DEPLOYMENT-floor case: the subject held the only
// admin-bearing role template anywhere, the carrier was empty, and invariant A
// refused. Migration 000054 makes that membership confer nothing — the
// subject's platform-admin authority, if they have any, is in the carrier and
// an IdP deprovision does not touch it — so invariant A no longer applies to
// this path at all and the refusal that still matters is invariant B's: the
// organization would keep a member and lose its last administrator.
//
// No DELETE is queued. sqlmock is in its default ordered mode, so a regression
// that dropped the guard would not merely leave the membership gone — it would
// attempt an unexpected statement and fail on that too.
func TestIdPReconcile_SkipsADeprovisionThatWouldStrandTheOrganization(t *testing.T) {
	h, identity, registry := flooredAuthHandlers(t, idpRevokeConfig())

	expectManagedOrgLookup(identity)

	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	// org-1 keeps a viewer after the subject goes, and the subject is its only
	// administrator.
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "scopes"}).
			AddRow("user-1", []byte(`["organizations:write"]`)).
			AddRow("viewer-1", []byte(`["modules:read"]`)))
	registry.ExpectRollback()

	// No group maps to acme any more.
	if err := h.applyGroupMappings(context.Background(), "user-1", nil); err != nil {
		t.Fatalf("applyGroupMappings returned %v — a floor refusal must not fail the login, "+
			"or the last administrator can never log in to fix the mapping that caused it", err)
	}
	if err := identity.ExpectationsWereMet(); err != nil {
		t.Fatalf("the membership was removed despite the refusal: %v", err)
	}
}

// TestIdPReconcile_StillDeprovisionsAnOrdinaryLeaver is the positive control.
// Without it, a change that skipped every reconciliation would satisfy the test
// above and look like a fix — while quietly disabling IdP offboarding, which is
// a security regression in the other direction.
func TestIdPReconcile_StillDeprovisionsAnOrdinaryLeaver(t *testing.T) {
	h, identity, registry := flooredAuthHandlers(t, idpRevokeConfig())

	expectManagedOrgLookup(identity)

	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	// No invariant-A fixture: a membership removal cannot reduce carrier
	// authority, so the floor goes straight to invariant B.
	// org-1 keeps an owner after the subject goes.
	identity.ExpectQuery("WHERE om.organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "scopes"}).
			AddRow("user-1", []byte(`["modules:read"]`)).
			AddRow("owner-1", []byte(`["organizations:write"]`)))
	identity.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))
	registry.ExpectRollback()

	if err := h.applyGroupMappings(context.Background(), "user-1", nil); err != nil {
		t.Fatalf("applyGroupMappings: %v", err)
	}
	if err := identity.ExpectationsWereMet(); err != nil {
		t.Fatalf("the ordinary leaver was not deprovisioned: %v", err)
	}
}
