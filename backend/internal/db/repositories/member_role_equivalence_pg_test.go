package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	identityauth "github.com/sethbacon/terraform-suite-identity/identity/auth"
	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"

	registryauth "github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// THE EQUIVALENCE PROOF for the read cutover
// (sethbacon/terraform-suite-identity#206, phase 3b).
//
// Everything else in this change argues that the flip is safe. This file is the
// only thing that DEMONSTRATES it: for a representative set of principals it
// resolves effective scopes BOTH WAYS -- once with the SQL the pre-cutover code
// issued against `organization_members` joined to `role_templates`, and once
// through the accessors as they are now -- and asserts the two agree, scope for
// scope, principal by principal, organization by organization.
//
// The final test is the other half of the proof, and it is the one that makes
// the rest of the file mean anything: it corrupts ONE mirrored row and asserts
// the comparison FAILS. A test that only ever sees agreement cannot distinguish
// "the two copies agree" from "the comparison is not looking at anything", and
// this repository has shipped guards that could not tell those apart.
//
// CI DOES NOT RUN THIS. No workflow sets TFR_TEST_DATABASE_URL (issue #886), so
// everything below skips on a PR. It is evidence produced locally against
// postgres:16 and named as such in the pull request.

// principal is one (organization, user) pair and the role it should hold.
type principal struct {
	name   string
	orgID  string
	userID string
	// roleID is empty for a membership that carries no role at all.
	roleID string
	scopes []string
}

// seedEquivalenceEstate builds a deployment with the shapes that actually
// distinguish a correct cutover from a plausible one.
//
// Not one happy-path member: the cases below are the ones where "resolve the
// role from a different table" can go wrong in a way a single-member fixture
// would never show -- a user in TWO organizations with DIFFERENT roles (the
// cross-organization union is the token mint, and collapsing it is a privilege
// escalation), a membership with NO role (nil and "" are different rows, and a
// missing mirror row looks like this one if the overlay is sloppy), a role with
// an EMPTY scope list, and two members sharing one template (so a per-member
// overlay cannot accidentally pass by being per-template).
func seedEquivalenceEstate(t *testing.T, db *sql.DB) []principal {
	t.Helper()

	orgAlpha, orgBeta := uuid.NewString(), uuid.NewString()
	mustExec(t, db, `INSERT INTO organizations (id, name, display_name) VALUES ($1,'alpha','Alpha'),($2,'beta','Beta')`,
		orgAlpha, orgBeta)

	admin, publisher, viewer, empty := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	mustExec(t, db, `INSERT INTO role_templates (id, name, display_name, scopes, is_system) VALUES
		($1,'eq-admin','EQ Admin','["organizations:write","modules:write","modules:read"]'::jsonb,false),
		($2,'eq-publisher','EQ Publisher','["modules:write","modules:read","providers:read"]'::jsonb,false),
		($3,'eq-viewer','EQ Viewer','["modules:read"]'::jsonb,false),
		($4,'eq-empty','EQ Empty','[]'::jsonb,false)`,
		admin, publisher, viewer, empty)

	// dual belongs to both organizations with DIFFERENT roles. This is the one
	// that catches a resolver which unions across organizations.
	dual := uuid.NewString()
	// solo shares eq-viewer with dual's beta membership, so a template-keyed
	// overlay cannot pass by accident.
	solo := uuid.NewString()
	// roleless is a member with role_template_id NULL -- present, entitled to
	// nothing. Indistinguishable from "not mirrored" unless the overlay keeps
	// the distinction migration 000055 built into the schema.
	roleless := uuid.NewString()
	// emptyScoped holds a template that exists and confers nothing.
	emptyScoped := uuid.NewString()

	for _, id := range []string{dual, solo, roleless, emptyScoped} {
		mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Test User')`, id, id+"@example.com")
	}

	mustExec(t, db, `INSERT INTO organization_members (organization_id, user_id, role_template_id) VALUES
		($1,$2,$3), ($4,$2,$5),
		($1,$6,$7),
		($1,$8,NULL),
		($4,$9,$10)`,
		orgAlpha, dual, admin,
		orgBeta, viewer,
		solo, publisher,
		roleless,
		emptyScoped, empty)

	return []principal{
		{"dual in alpha (admin)", orgAlpha, dual, admin, []string{"organizations:write", "modules:write", "modules:read"}},
		{"dual in beta (viewer)", orgBeta, dual, viewer, []string{"modules:read"}},
		{"solo in alpha (publisher)", orgAlpha, solo, publisher, []string{"modules:write", "modules:read", "providers:read"}},
		{"roleless in alpha (no role)", orgAlpha, roleless, "", nil},
		{"emptyScoped in beta (empty template)", orgBeta, emptyScoped, empty, nil},
	}
}

// scopesTheOldWay resolves a principal's effective scopes in ONE organization
// with the query the pre-cutover code issued.
//
// It is written out here rather than called through the shared store, on
// purpose: the store is what the cutover changed the CALLERS of, so asking it
// again would be asking the new code whether it agrees with itself. This is the
// old SQL, against the old tables, and it is the independent side of the
// comparison.
func scopesTheOldWay(t *testing.T, db *sql.DB, orgID, userID string) []string {
	t.Helper()
	var raw []byte
	err := db.QueryRow(`
		SELECT COALESCE(rt.scopes, '[]'::jsonb)
		  FROM organization_members om
		  LEFT JOIN role_templates rt ON rt.id = om.role_template_id
		 WHERE om.organization_id = $1 AND om.user_id = $2`, orgID, userID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		t.Fatalf("resolve scopes the old way for (%s, %s): %v", orgID, userID, err)
	}
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		t.Fatalf("parse old-way scopes: %v", err)
	}
	return scopes
}

// roleTheOldWay reads the role template id the pre-cutover code would have
// resolved for a membership.
func roleTheOldWay(t *testing.T, db *sql.DB, orgID, userID string) string {
	t.Helper()
	var id sql.NullString
	err := db.QueryRow(
		`SELECT role_template_id FROM organization_members WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&id)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("resolve role the old way: %v", err)
	}
	if !id.Valid {
		return ""
	}
	return id.String
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := sortedCopy(a), sortedCopy(b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// equivalenceFixture builds the estate, reconciles registry's tables from it,
// and returns the repository the cutover put in front of every caller.
func equivalenceFixture(t *testing.T) (*sql.DB, *OrganizationRepository, []principal) {
	t.Helper()
	db, _ := reconcileScratchDB(t, 55)
	principals := seedEquivalenceEstate(t, db)

	report, err := ReconcileMemberRoles(context.Background(), db, db)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if report.SourceMemberships != len(principals) {
		t.Fatalf("reconcile read %d source membership(s), want %d — the fixture and the "+
			"reconcile disagree about what was seeded", report.SourceMemberships, len(principals))
	}
	return db, NewOrganizationRepository(db), principals
}

// TestEquivalence_EffectiveScopesMatchBothWays is the proof.
//
// For every principal, every accessor that answers "what may this person do
// here" is asked, and its answer is compared to what the pre-cutover SQL
// resolves from the identity tables. Not "no error": the exact scope set, the
// exact role template id.
func TestEquivalence_EffectiveScopesMatchBothWays(t *testing.T) {
	db, repo, principals := equivalenceFixture(t)
	ctx := context.Background()

	for _, p := range principals {
		t.Run(p.name, func(t *testing.T) {
			wantScopes := scopesTheOldWay(t, db, p.orgID, p.userID)
			wantRole := roleTheOldWay(t, db, p.orgID, p.userID)

			// The fixture's own expectation, checked against the old way as
			// well: if these disagree the seed is wrong and every comparison
			// below would be comparing two copies of the same mistake.
			if !sameStringSet(wantScopes, p.scopes) {
				t.Fatalf("fixture disagrees with the identity tables: seeded %v, identity resolves %v",
					sortedCopy(p.scopes), sortedCopy(wantScopes))
			}

			// 1. The per-organization authorization check -- the accessor every
			//    org-scoped route is decided by.
			got, err := repo.GetUserScopesForOrg(ctx, p.userID, p.orgID)
			if err != nil {
				t.Fatalf("GetUserScopesForOrg: %v", err)
			}
			if !sameStringSet(got, wantScopes) {
				t.Errorf("GetUserScopesForOrg = %v, identity tables resolve %v",
					sortedCopy(got), sortedCopy(wantScopes))
			}

			// 2. The membership accessor the per-resource guards are built on.
			member, err := repo.GetMemberWithRole(ctx, p.orgID, p.userID, identitystore.OrgScopeAllOrganizations())
			if err != nil {
				t.Fatalf("GetMemberWithRole: %v", err)
			}
			if !sameStringSet(member.RoleTemplateScopes, wantScopes) {
				t.Errorf("GetMemberWithRole scopes = %v, identity tables resolve %v",
					sortedCopy(member.RoleTemplateScopes), sortedCopy(wantScopes))
			}
			if gotRole := derefOrEmpty(member.RoleTemplateID); gotRole != wantRole {
				t.Errorf("GetMemberWithRole role_template_id = %q, identity tables hold %q", gotRole, wantRole)
			}

			// 3. The bare membership read.
			bare, err := repo.GetMember(ctx, p.orgID, p.userID, identitystore.OrgScopeAllOrganizations())
			if err != nil {
				t.Fatalf("GetMember: %v", err)
			}
			if gotRole := derefOrEmpty(bare.RoleTemplateID); gotRole != wantRole {
				t.Errorf("GetMember role_template_id = %q, identity tables hold %q", gotRole, wantRole)
			}

			// 4. CheckMembership's second return value, which several route
			//    guards read INSTEAD of calling GetMember.
			isMember, checkRole, err := repo.CheckMembership(ctx, p.orgID, p.userID, identitystore.OrgScopeAllOrganizations())
			if err != nil {
				t.Fatalf("CheckMembership: %v", err)
			}
			if !isMember {
				t.Errorf("CheckMembership says not a member, but the identity tables have the row")
			}
			if gotRole := derefOrEmpty(checkRole); gotRole != wantRole {
				t.Errorf("CheckMembership role_template_id = %q, identity tables hold %q", gotRole, wantRole)
			}
		})
	}
}

// TestEquivalence_CrossOrganizationUnionMatches covers the accessors keyed by
// USER rather than by membership -- the token mint and the tenant predicate.
//
// Separate from the per-membership proof because they are the ones that can be
// wrong in the direction that ESCALATES: a resolver that attached the wrong
// organization's role to a membership, or that unioned two organizations into
// one, produces a token carrying authority the principal holds nowhere.
func TestEquivalence_CrossOrganizationUnionMatches(t *testing.T) {
	db, repo, principals := equivalenceFixture(t)
	ctx := context.Background()

	// Every distinct user in the fixture.
	users := map[string]bool{}
	for _, p := range principals {
		users[p.userID] = true
	}

	for userID := range users {
		t.Run(userID[:8], func(t *testing.T) {
			// The old way: union the scopes of every membership this user has.
			want := map[string]bool{}
			perOrg := map[string][]string{}
			rows, err := db.Query(
				`SELECT organization_id FROM organization_members WHERE user_id = $1`, userID)
			if err != nil {
				t.Fatalf("list organizations: %v", err)
			}
			var orgIDs []string
			for rows.Next() {
				var orgID string
				if err := rows.Scan(&orgID); err != nil {
					t.Fatalf("scan: %v", err)
				}
				orgIDs = append(orgIDs, orgID)
			}
			_ = rows.Close()
			for _, orgID := range orgIDs {
				scopes := scopesTheOldWay(t, db, orgID, userID)
				perOrg[orgID] = scopes
				for _, s := range scopes {
					want[s] = true
				}
			}
			wantUnion := make([]string, 0, len(want))
			for s := range want {
				wantUnion = append(wantUnion, s)
			}

			got, err := repo.GetUserCombinedScopes(ctx, userID) //nolint:staticcheck // SA1019: the cross-org union is exactly what is under test here
			if err != nil {
				t.Fatalf("GetUserCombinedScopes: %v", err)
			}
			if !sameStringSet(got, wantUnion) {
				t.Errorf("GetUserCombinedScopes = %v, identity tables union to %v",
					sortedCopy(got), sortedCopy(wantUnion))
			}

			// GetUserMemberships must keep the roles attached to the RIGHT
			// organizations, which the union above cannot show.
			memberships, err := repo.GetUserMemberships(ctx, userID)
			if err != nil {
				t.Fatalf("GetUserMemberships: %v", err)
			}
			if len(memberships) != len(orgIDs) {
				t.Fatalf("GetUserMemberships returned %d membership(s), identity has %d",
					len(memberships), len(orgIDs))
			}
			for _, m := range memberships {
				if !sameStringSet(m.RoleTemplateScopes, perOrg[m.OrganizationID]) {
					t.Errorf("organization %s: scopes = %v, identity tables resolve %v",
						m.OrganizationID, sortedCopy(m.RoleTemplateScopes), sortedCopy(perOrg[m.OrganizationID]))
				}
			}

			// OrgScopeForUser is the tenant predicate. Ask it for a scope only
			// SOME of this user's organizations grant, so a resolver that
			// unioned would return an organization it must not.
			scope, err := repo.OrgScopeForUser(ctx, userID, "modules:write", registryauth.ReadWritePairs())
			if err != nil {
				t.Fatalf("OrgScopeForUser: %v", err)
			}
			var wantOrgs []string
			for orgID, scopes := range perOrg {
				if identityauth.HasScope(scopes, "modules:write", registryauth.ReadWritePairs()) {
					wantOrgs = append(wantOrgs, orgID)
				}
			}
			if !sameStringSet(scope.OrganizationIDs(), wantOrgs) {
				t.Errorf("OrgScopeForUser(modules:write) = %v, identity tables grant it in %v",
					sortedCopy(scope.OrganizationIDs()), sortedCopy(wantOrgs))
			}
		})
	}
}

// TestEquivalence_DriftCheckIsZeroOnAReconciledEstate is the gate itself, run
// against the estate the proof above uses. It must be clean, and it must say it
// compared something.
func TestEquivalence_DriftCheckIsZeroOnAReconciledEstate(t *testing.T) {
	db, _, principals := equivalenceFixture(t)

	report, err := CheckMemberRoleDrift(context.Background(), db, db)
	if err != nil {
		t.Fatalf("CheckMemberRoleDrift: %v", err)
	}
	if !report.Clean() {
		for _, row := range report.Rows {
			t.Errorf("unexpected drift: %s", row)
		}
		t.Fatal("a freshly reconciled estate must produce zero drift; the gate is unusable otherwise")
	}
	if report.SourceMemberships != len(principals) {
		t.Errorf("drift check compared %d membership(s), fixture seeded %d — a gate that "+
			"reports clean without looking at the rows is the failure it exists to prevent",
			report.SourceMemberships, len(principals))
	}
	if report.SourceRoleTemplates == 0 || report.MirroredRoleTemplates == 0 {
		t.Errorf("drift check compared %d source and %d mirrored role template(s); zero on either "+
			"side means it certified an empty universe",
			report.SourceRoleTemplates, report.MirroredRoleTemplates)
	}
}

// TestEquivalence_ACorruptedMirrorRowBreaksTheProof is the falsification, and
// it is what makes every assertion above worth reading.
//
// Each case corrupts registry's copy in ONE way a dual-write gap actually
// produces, and requires that BOTH the equivalence comparison and the drift
// check notice. A case where the equivalence held would mean the accessors are
// not reading registry's tables at all; a case where the drift check stayed
// clean would mean the gate cannot see the very defect it gates on.
func TestEquivalence_ACorruptedMirrorRowBreaksTheProof(t *testing.T) {
	cases := []struct {
		name string
		// corrupt mutates registry's copy and returns the principal it damaged.
		corrupt  func(t *testing.T, db *sql.DB, p principal)
		wantKind string
	}{
		{
			name: "the mirrored row is deleted (a membership that never mirrored)",
			corrupt: func(t *testing.T, db *sql.DB, p principal) {
				mustExec(t, db, `DELETE FROM organization_member_roles WHERE organization_id=$1 AND user_id=$2`,
					p.orgID, p.userID)
			},
			wantKind: DriftMembershipNotMirrored,
		},
		{
			name: "the mirrored row names a different template (a stale dual-write)",
			corrupt: func(t *testing.T, db *sql.DB, p principal) {
				var other string
				if err := db.QueryRow(
					`SELECT id FROM registry_role_templates WHERE id <> $1 LIMIT 1`, p.roleID).Scan(&other); err != nil {
					t.Fatalf("find another template: %v", err)
				}
				mustExec(t, db, `UPDATE organization_member_roles SET role_template_id=$3
				                 WHERE organization_id=$1 AND user_id=$2`, p.orgID, p.userID, other)
			},
			wantKind: DriftRoleDiffers,
		},
		{
			name: "the mirrored row's role is cleared (a lost re-role)",
			corrupt: func(t *testing.T, db *sql.DB, p principal) {
				mustExec(t, db, `UPDATE organization_member_roles SET role_template_id=NULL
				                 WHERE organization_id=$1 AND user_id=$2`, p.orgID, p.userID)
			},
			wantKind: DriftRoleDiffers,
		},
		{
			name: "the mirrored template's scopes were not updated",
			corrupt: func(t *testing.T, db *sql.DB, p principal) {
				mustExec(t, db, `UPDATE registry_role_templates SET scopes='["modules:read"]'::jsonb WHERE id=$1`,
					p.roleID)
			},
			wantKind: DriftTemplateScopesDiffer,
		},
		{
			name: "the mirrored template was renamed",
			corrupt: func(t *testing.T, db *sql.DB, p principal) {
				mustExec(t, db, `UPDATE registry_role_templates SET name='eq-renamed' WHERE id=$1`, p.roleID)
			},
			wantKind: DriftTemplateNameDiffers,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, repo, principals := equivalenceFixture(t)
			ctx := context.Background()

			// The admin in alpha: a principal whose role actually confers
			// something, so a corruption is observable as a scope change.
			var victim principal
			for _, p := range principals {
				if p.roleID != "" && len(p.scopes) > 1 {
					victim = p
					break
				}
			}
			if victim.roleID == "" {
				t.Fatal("no scoped principal in the fixture — nothing to corrupt")
			}

			before, err := repo.GetUserScopesForOrg(ctx, victim.userID, victim.orgID)
			if err != nil {
				t.Fatalf("GetUserScopesForOrg before: %v", err)
			}
			if !sameStringSet(before, victim.scopes) {
				t.Fatalf("the estate was already wrong before the corruption: %v vs %v",
					sortedCopy(before), sortedCopy(victim.scopes))
			}

			tc.corrupt(t, db, victim)

			// 1. The equivalence proof must now FAIL for this principal.
			//    A rename does not change what the template confers, so it is
			//    the one corruption the scope comparison legitimately cannot
			//    see -- which is exactly why the drift check compares names.
			if tc.wantKind != DriftTemplateNameDiffers {
				after, err := repo.GetUserScopesForOrg(ctx, victim.userID, victim.orgID)
				if err != nil {
					t.Fatalf("GetUserScopesForOrg after: %v", err)
				}
				identity := scopesTheOldWay(t, db, victim.orgID, victim.userID)
				if sameStringSet(after, identity) {
					t.Errorf("after corrupting registry's copy, GetUserScopesForOrg still returns %v, "+
						"which equals what the identity tables resolve. The accessor is NOT reading "+
						"registry's tables, so every equivalence assertion in this file is vacuous",
						sortedCopy(after))
				}
			}

			// 2. The gate must report it, with the right kind and naming the
			//    right row.
			report, err := CheckMemberRoleDrift(ctx, db, db)
			if err != nil {
				t.Fatalf("CheckMemberRoleDrift: %v", err)
			}
			if report.Clean() {
				t.Fatalf("the drift check reports no drift after %s — the gate cannot see the "+
					"defect it gates on", tc.name)
			}
			var found *DriftRow
			for i := range report.Rows {
				if report.Rows[i].Kind == tc.wantKind {
					found = &report.Rows[i]
					break
				}
			}
			if found == nil {
				var kinds []string
				for _, r := range report.Rows {
					kinds = append(kinds, r.Kind)
				}
				t.Fatalf("drift reported %v, want a %q row", kinds, tc.wantKind)
			}
			switch tc.wantKind {
			case DriftMembershipNotMirrored, DriftRoleDiffers:
				if found.OrganizationID != victim.orgID || found.UserID != victim.userID {
					t.Errorf("drift row names (%s, %s), corruption was to (%s, %s)",
						found.OrganizationID, found.UserID, victim.orgID, victim.userID)
				}
			default:
				if found.RoleTemplateID != victim.roleID {
					t.Errorf("drift row names template %s, corruption was to %s",
						found.RoleTemplateID, victim.roleID)
				}
			}

			// 3. And the repair must work: re-deriving from the source clears
			//    it. This is the operator's first remedy, and an unverified
			//    remedy in a runbook is a guess.
			if _, err := ReconcileMemberRoles(ctx, db, db); err != nil {
				t.Fatalf("reconcile after corruption: %v", err)
			}
			repaired, err := CheckMemberRoleDrift(ctx, db, db)
			if err != nil {
				t.Fatalf("CheckMemberRoleDrift after repair: %v", err)
			}
			if !repaired.Clean() {
				for _, row := range repaired.Rows {
					t.Errorf("drift survived the reconcile: %s", row)
				}
			}
			restored, err := repo.GetUserScopesForOrg(ctx, victim.userID, victim.orgID)
			if err != nil {
				t.Fatalf("GetUserScopesForOrg after repair: %v", err)
			}
			if !sameStringSet(restored, victim.scopes) {
				t.Errorf("after the repair the principal resolves %v, want %v",
					sortedCopy(restored), sortedCopy(victim.scopes))
			}
		})
	}
}

// TestEquivalence_MirrorRowWithoutMembershipConfersNothing pins the one drift
// direction that GRANTS rather than withholds.
//
// A row in `organization_member_roles` for somebody who is not a member is
// inert TODAY, because every accessor asks the shared store for the membership
// first. That is a property of the ordering in organization_repository.go, not
// a coincidence, and it stops holding the moment phase 4 moves the membership
// fact -- so it is pinned here, and the drift check reports the row meanwhile.
func TestEquivalence_MirrorRowWithoutMembershipConfersNothing(t *testing.T) {
	db, repo, principals := equivalenceFixture(t)
	ctx := context.Background()

	orgID := principals[0].orgID
	stranger := uuid.NewString()
	var adminTemplate string
	if err := db.QueryRow(`SELECT id FROM registry_role_templates WHERE name = 'eq-admin'`).Scan(&adminTemplate); err != nil {
		t.Fatalf("find eq-admin: %v", err)
	}
	// A user row, but NO membership: the grant exists only in registry's mirror.
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Stranger')`, stranger, stranger+"@example.com")
	mustExec(t, db, `INSERT INTO organization_member_roles (organization_id, user_id, role_template_id)
	                 VALUES ($1,$2,$3)`, orgID, stranger, adminTemplate)

	scopes, err := repo.GetUserScopesForOrg(ctx, stranger, orgID)
	if err != nil {
		t.Fatalf("GetUserScopesForOrg: %v", err)
	}
	if len(scopes) != 0 {
		t.Errorf("a mirrored role with no membership conferred %v — the accessor is resolving "+
			"authority from registry's tables WITHOUT confirming membership first, which turns "+
			"every stale mirror row into a live grant", sortedCopy(scopes))
	}
	isMember, _, err := repo.CheckMembership(ctx, orgID, stranger, identitystore.OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("CheckMembership: %v", err)
	}
	if isMember {
		t.Error("CheckMembership says a principal with only a mirrored role row is a member")
	}

	// And the gate reports it, because phase 4 is when it stops being inert.
	report, err := CheckMemberRoleDrift(ctx, db, db)
	if err != nil {
		t.Fatalf("CheckMemberRoleDrift: %v", err)
	}
	var found bool
	for _, row := range report.Rows {
		if row.Kind == DriftMirrorWithoutMembership && row.UserID == stranger {
			found = true
		}
	}
	if !found {
		t.Errorf("the drift check did not report the mirrored row with no membership; rows were %v",
			report.Rows)
	}
}

// derefOrEmpty renders an optional role template id as a comparable string.
func derefOrEmpty(id *string) string {
	if id == nil {
		return ""
	}
	return *id
}

// TestEquivalence_TheBootSequenceLeavesTheGateAtZero exercises the ACTUAL order
// internal/api/router.go runs on every start and requires `role-drift` to be
// clean afterwards, in BOTH topologies.
//
// This is the property most easily reasoned into existence and hardest to notice
// the loss of, and reasoning got it wrong once already: seeding registry's table
// unconditionally left permanent `template_scopes_differ` drift on a completely
// healthy default deployment, because migration 000018 added `scanning:read` to
// `devops` and `auditor` and models.PredefinedRoleTemplates() does not carry it.
// A gate that can never return zero is not a gate -- it gets ignored, and the
// real divergence it exists to catch is ignored with it.
//
// It also pins the ORDER. Seeding first and reconciling second leaves the
// reconcile's copy of identity's templates as the final state, which is the same
// failure with the two halves swapped.
func TestEquivalence_TheBootSequenceLeavesTheGateAtZero(t *testing.T) {
	// boot runs the startup sequence router.go performs, once.
	boot := func(t *testing.T, db *sql.DB, cutover bool) {
		t.Helper()
		ctx := context.Background()
		if cutover {
			// cmd/server, before NewRouter: the shared table gets registry's
			// scopes layered onto the identity module's core-only seed.
			if err := SeedSharedIdentityRoleTemplates(ctx, db, models.PredefinedRoleTemplates()); err != nil {
				t.Fatalf("seed the shared identity role templates: %v", err)
			}
		}
		if _, err := ReconcileMemberRoles(ctx, db, db); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if cutover {
			if err := SeedSystemRoleTemplates(ctx, db, models.PredefinedRoleTemplates()); err != nil {
				t.Fatalf("seed registry's own role templates: %v", err)
			}
		}
	}

	for _, tc := range []struct {
		name string
		// cutover is TFR_IDENTITY_SCHEMA_ENABLED: the only topology either seed
		// runs in. Both are modelled on one database because what is under test
		// is the DRIFT the sequence leaves, not which schema each statement
		// resolves to -- that is
		// TestReconcile_UsesTheEffectiveSourceUnderTheSchemaCutover's subject.
		cutover bool
	}{
		{"default topology (migrations are the policy; neither seed runs)", false},
		{"identity-schema cutover (both seeds run)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := reconcileScratchDB(t, 55)
			seedEquivalenceEstate(t, db)
			ctx := context.Background()

			boot(t, db, tc.cutover)

			report, err := CheckMemberRoleDrift(ctx, db, db)
			if err != nil {
				t.Fatalf("CheckMemberRoleDrift: %v", err)
			}
			if !report.Clean() {
				for _, row := range report.Rows {
					t.Errorf("boot left drift behind: %s", row)
				}
				t.Fatal("the startup sequence leaves `role-drift` non-zero on a healthy " +
					"deployment, which makes the gate on this whole phase un-passable")
			}

			// A second boot must be identical: both seeds are idempotent and
			// the reconcile must not undo either.
			boot(t, db, tc.cutover)
			report, err = CheckMemberRoleDrift(ctx, db, db)
			if err != nil {
				t.Fatalf("CheckMemberRoleDrift after a second boot: %v", err)
			}
			for _, row := range report.Rows {
				t.Errorf("the second boot introduced drift: %s", row)
			}

			// Whatever the topology, registry must resolve every system role
			// template by NAME, under the id its memberships name. A seed that
			// inserted a second row under a fresh uuid instead of updating the
			// reconciled one would strip every holder of their role.
			reader := NewMemberRoleReader(db)
			for _, want := range models.PredefinedRoleTemplates() {
				got, tErr := reader.GetRoleTemplateByName(ctx, want.Name)
				if tErr != nil {
					t.Errorf("registry cannot resolve role template %q: %v", want.Name, tErr)
					continue
				}
				identityScopes := templateScopesTheOldWay(t, db, want.Name)
				if !sameStringSet(got.Scopes, identityScopes) {
					t.Errorf("role template %q: registry resolves %v, the identity tables hold %v",
						want.Name, sortedCopy(got.Scopes), sortedCopy(identityScopes))
				}
			}
		})
	}
}

// templateScopesTheOldWay reads a system template's scopes from the shared table,
// the way the pre-cutover code did.
func templateScopesTheOldWay(t *testing.T, db *sql.DB, name string) []string {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`SELECT scopes FROM role_templates WHERE name = $1`, name).Scan(&raw); err != nil {
		t.Fatalf("read %q the old way: %v", name, err)
	}
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		t.Fatalf("parse %q scopes: %v", name, err)
	}
	return scopes
}
