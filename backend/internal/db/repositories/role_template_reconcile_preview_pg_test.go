package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

	registryauth "github.com/terraform-registry/terraform-registry/internal/auth"
)

// Issue #282's preview primitive, wired into terraform-registry-backend,
// against real PostgreSQL and the real migrations.
//
// This is the empirical half of the caveat documented on
// admin.RBACHandlers.PreviewRoleTemplateReconciliation: the shared library
// resolves membership through identity's `organization_members`, while
// registry's OWN sweep (ListRoleTemplateMemberships) resolves it through the
// per-app mirror `organization_member_roles` (terraform-suite-identity#206
// phase 3b) -- two different tables, on the same connection here, but
// distinguishable in a topology where the identity connection differs. The
// sqlmock-based tests in internal/api/admin/rbac_test.go prove the HANDLER's
// wiring; this file proves the two real queries agree, principal for
// principal, once the mirror has been reconciled -- the steady state the
// estate is continuously CI-gated to hold (see
// member_role_equivalence_pg_test.go).
//
// CI DOES NOT RUN THIS. No workflow sets TFR_TEST_DATABASE_URL (issue #886)
// for this package's *_pg_test.go files generally, so this skips on a PR
// exactly as its neighbors do. It is evidence produced locally against
// postgres:16 and named as such in the pull request.

// seedPreviewFixture builds one template with two members: one whose key is a
// SUBSET of the narrowed scopes (must survive) and one whose key EXCEEDS them
// (must be swept), then reconciles registry's own mirror from the identity
// tables -- the same reconcile NewRouter runs at every boot.
func seedPreviewFixture(t *testing.T, db *sql.DB) (templateID, orgID, subsetUser, overUser string) {
	t.Helper()
	ctx := context.Background()

	orgID = uuid.NewString()
	mustExec(t, db, `INSERT INTO organizations (id, name, display_name) VALUES ($1,$2,$3)`,
		orgID, "preview-org-"+orgID[:8], "Preview Org")

	templateID = uuid.NewString()
	mustExec(t, db, `INSERT INTO role_templates (id, name, display_name, scopes, is_system) VALUES ($1,$2,$3,$4,false)`,
		templateID, "preview-tmpl-"+templateID[:8], "Preview Template", `["modules:read","providers:write"]`)

	subsetUser, overUser = uuid.NewString(), uuid.NewString()
	for _, u := range []string{subsetUser, overUser} {
		mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Preview User')`, u, u+"@example.test")
	}
	mustExec(t, db, `INSERT INTO organization_members (organization_id, user_id, role_template_id) VALUES ($1,$2,$3),($1,$4,$3)`,
		orgID, subsetUser, templateID, overUser)

	mustExec(t, db, `INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
	                  VALUES ($1,$2,$3,'subset key','h1','p1',$4,NOW())`,
		uuid.NewString(), subsetUser, orgID, `["modules:read"]`)
	mustExec(t, db, `INSERT INTO api_keys (id, user_id, organization_id, name, key_hash, key_prefix, scopes, created_at)
	                  VALUES ($1,$2,$3,'over key','h2','p2',$4,NOW())`,
		uuid.NewString(), overUser, orgID, `["providers:write"]`)

	report, err := ReconcileMemberRoles(ctx, db, db)
	if err != nil {
		t.Fatalf("ReconcileMemberRoles: %v", err)
	}
	if report.MembershipsWritten < 2 {
		t.Fatalf("reconcile wrote %d membership(s), want at least 2 -- the fixture and the mirror disagree about what was seeded", report.MembershipsWritten)
	}
	return templateID, orgID, subsetUser, overUser
}

// TestPreviewRoleTemplateReconciliation_AgreesWithRegistryMirror is the
// empirical proof for the caveat on PreviewRoleTemplateReconciliation: in a
// reconciled estate, the shared library's identity-table query and
// registry's own mirror-table query (ListRoleTemplateMemberships) name the
// SAME principals for the SAME template -- not by construction, by running
// both against one real database and comparing the results.
func TestPreviewRoleTemplateReconciliation_AgreesWithRegistryMirror(t *testing.T) {
	db := scratchAtHead(t)
	ctx := context.Background()

	templateID, orgID, subsetUser, overUser := seedPreviewFixture(t, db)

	// The library's query, exactly as PreviewRoleTemplateReconciliation runs
	// it -- narrowing the template to ["modules:read"].
	impact, err := identitystore.PreviewRoleTemplateReconciliation(
		ctx, db, templateID, []string{"modules:read"}, registryauth.ReadWritePairs(),
	)
	if err != nil {
		t.Fatalf("PreviewRoleTemplateReconciliation: %v", err)
	}
	if impact.Scanned != 2 {
		t.Errorf("Scanned = %d, want 2 (subsetUser, overUser)", impact.Scanned)
	}
	if impact.Principals != 1 || impact.Keys != 1 {
		t.Errorf("Principals=%d Keys=%d, want 1/1 (only overUser's key is swept)", impact.Principals, impact.Keys)
	}

	// Registry's OWN production read -- what UpdateRoleTemplate/
	// DeleteRoleTemplate actually sweep through, via the per-app mirror.
	sqlxDB := sqlx.NewDb(db, "pgx")
	rbacRepo := NewRBACRepository(sqlxDB)
	tid, err := uuid.Parse(templateID)
	if err != nil {
		t.Fatalf("uuid.Parse: %v", err)
	}
	memberships, err := rbacRepo.ListRoleTemplateMemberships(ctx, tid)
	if err != nil {
		t.Fatalf("ListRoleTemplateMemberships: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("registry's mirror named %d member(s), want 2", len(memberships))
	}
	got := map[string]string{} // userID -> orgID
	for _, m := range memberships {
		got[m.UserID] = m.OrganizationID
	}
	for _, u := range []string{subsetUser, overUser} {
		if got[u] != orgID {
			t.Errorf("registry's mirror missing/mismatched (%s, %s): got org %q", u, orgID, got[u])
		}
	}
	// THE AGREEMENT: the library's Scanned count and registry's own mirror
	// read name the same number of principals for the same template, in a
	// reconciled estate -- the promise the preview endpoint's response
	// caveat documents rather than assumes.
	if impact.Scanned != len(memberships) {
		t.Errorf("preview Scanned=%d disagrees with registry's own mirror read (%d members) -- "+
			"the preview and the real sweep are looking at different populations", impact.Scanned, len(memberships))
	}
}
