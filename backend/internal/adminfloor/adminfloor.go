// Package adminfloor enforces the two never-zero administrator invariants
// (issue #766):
//
//	A. the DEPLOYMENT always has at least one platform administrator
//	B. every ORGANIZATION that has members has at least one member who can
//	   administer it
//
// # Why a package rather than a check in a handler
//
// Neither invariant is broken in one place. The reported path — an explicit
// platform-admin revoke — is guarded by
// platformadmin.Carrier.Revoke with the exercisable-admin predicate (PR #862), but
// the same authority is reduced by nine other write paths: the two membership
// handlers, user deletion, GDPR erasure, four SCIM deprovision entry points,
// the IdP login reconciliation's remove and downgrade branches, and
// organization deletion. A check that lives in one handler holds for one path;
// this package holds for all of them, and admin_floor_class_test.go fails when
// a new one appears without it.
//
// # What "administrator" means, derived rather than invented
//
// PLATFORM administrator is what the middleware treats as platform-admin
// authority today: a row in the platform_admins carrier (migration 000051).
// Nothing else, since migration 000054.
//
// It used to be `carrier OR union` — the carrier OR an admin-bearing role
// template held through any membership (the org-less scope union, #652) — and
// this paragraph went on saying so for a while after it stopped being true.
// #874 made authority carrier-only and rewrote checkPlatformFloor to match; the
// description here was not updated with it, so the package doc and the function
// 280 lines below disagreed about who counts. Corrected while closing #876,
// which was the other half of the same drift: mTLS was still publishing `admin`
// from a config file, so the carrier was not in fact the only source the
// sentence above claimed it was.
//
// The union half is gone deliberately, not by omission: the auth middleware
// strips `admin` from the session union, so an admin-bearing membership
// administers nothing, and counting one would report "an administrator remains"
// while the deployment's last real one was being deleted.
//
// ORGANIZATION administrator is a member whose role template carries `admin`
// or `organizations:write`. That is not a new definition: it is exactly what
// RequireOrgScopeForPathOrg demands to manage an organization's membership, so
// an organization with no such member cannot administer itself at all.
//
// # EXERCISABLE, not merely recorded
//
// A grant that resolves to no user is skipped rather than counted, the same
// rule PR #862 established on the carrier: both auth middlewares load the user
// before consulting the carrier, so an orphan row elevates nobody. Counting
// rows instead would let the last real administrator be removed against a
// count of two. Every query below therefore joins `users`.
//
// # Serialization
//
// Every check-then-write runs under ONE application-wide Postgres advisory
// lock, taken on the registry connection. A per-organization lock would be
// finer, but invariant A is application-wide and both invariants are decided by
// the same reads, so a single lock is the only one that makes the composition
// safe — including across the two connections this product may be deployed
// with (identity data can live in another schema or another database entirely,
// migration 000051). These are rare administrative writes, not a hot path.
//
// The lock itself is the carrier's (platformadmin.Carrier.Serialize), so this
// package and every carrier mutation take the SAME lock — and, because the
// library derives its key from the carrier's qualified table name rather than
// from a constant, a second application sharing this database takes a
// different one. The fixed key this package used to hash would have had
// registry and state-manager blocking each other on unrelated revocations the
// moment they shared a database, which is the deployment the identity model
// exists to support.
//
// # Mechanism from the library, policy here
//
// Invariant A's arithmetic — count only the grants that still RESOLVE, and
// treat a failed lookup as unresolved rather than as an orphan — is
// platformadmin.RequireAnotherExercisableAdmin. Invariant B is registry policy
// and has no equivalent anywhere else: it is decided from organization
// membership and this application's role templates.
package adminfloor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// Sentinels. Callers map these onto status codes; they are values rather than
// strings so a handler cannot accidentally serve a refusal as a success, and
// so a test can assert WHICH invariant refused rather than "not 200".
var (
	// ErrLastPlatformAdmin means the change would leave the deployment with no
	// principal holding platform-admin authority (invariant A).
	//
	// It IS the carrier mechanism's sentinel rather than a second one beside
	// it: the explicit revoke path refuses through platformadmin.Revoke and
	// every other authority-reducing path refuses through this package, and a
	// handler that had to test for two sentinels meaning one fact would
	// eventually test for one.
	ErrLastPlatformAdmin = platformadmin.ErrLastPlatformAdmin

	// ErrLastOrganizationAdmin means the change would leave an organization
	// with members but nobody able to administer it (invariant B).
	ErrLastOrganizationAdmin = errors.New("adminfloor: the organization would be left with members but no administrator")

	// ErrIndeterminate means the floor could not be established. It is NOT a
	// refusal for a policy reason and it is NOT permission to proceed: an
	// unresolved answer must not be served as a yes, which is the same posture
	// platform_admins.go takes on errIdentityUnavailable.
	ErrIndeterminate = errors.New("adminfloor: could not determine whether an administrator would remain")
)

// Change describes an authority reduction that is ABOUT TO BE WRITTEN. The
// floor evaluates the invariants against the state that would result from it,
// not against the state that exists now.
type Change struct {
	// UserID is the principal losing authority. Required.
	UserID string

	// OrganizationIDs are the organizations the change applies to. Empty means
	// EVERY organization the principal belongs to — user deletion, GDPR
	// erasure, and an all-organizations SCIM deprovision are all that shape.
	//
	// A SCIM caller whose tenancy is narrower than the whole platform passes
	// the organizations its scope actually reaches, so the floor evaluates
	// exactly the rows that will be deleted.
	OrganizationIDs []string

	// KeepsRoleTemplateID is the role template the membership will carry AFTER
	// the change. nil means the membership row (or its role) goes away
	// entirely. A move from one admin-bearing template to another is not a
	// reduction and is permitted without further argument.
	//
	// Only meaningful with exactly one OrganizationID: it describes a re-role,
	// and a re-role happens in one organization.
	KeepsRoleTemplateID *string

	// KeepsScopes says the same thing for a caller that already knows the
	// answer. The IdP reconciliation resolves the mapped template's scopes as
	// part of its own provisionable-role guard and re-reading them by id here
	// would be a second lookup that could disagree with the first.
	//
	// KeepsRoleTemplateID WINS when both are set; supply one or the other.
	KeepsScopes []string

	// RemovesMembership distinguishes a removal (the row is deleted, so the
	// organization loses a member) from a re-role (the row survives with a
	// different template). It changes invariant B's arithmetic: removing the
	// only member empties the organization, which is legitimate; re-roling the
	// only member leaves an organization with a member and no administrator,
	// which is not.
	RemovesMembership bool

	// DeletesOrganizations is true when the organizations named in
	// OrganizationIDs are themselves being deleted, taking EVERY membership in
	// them with them (organization_members.organization_id is ON DELETE
	// CASCADE, so no membership statement appears anywhere on that path — the
	// reason it is easy to miss).
	//
	// Invariant B is vacuous for a deleted organization: it cannot be stranded
	// because it will not exist. Invariant A is vacuous over it too from
	// migration 000054 — platform-admin authority lives in the carrier, which
	// an organization deletion does not touch — so this flag now only tells
	// invariant B to stand down. It is kept because the shape of the change is
	// worth naming at the call site, and because the write still runs under the
	// floor's lock.
	DeletesOrganizations bool

	// DestroysPrincipal is true when the change removes or anonymises the USER
	// rather than only its memberships — user deletion and GDPR erasure.
	//
	// It matters because platform_admins carries no foreign key to users
	// (migration 000051, deliberately). Destroying the principal makes its
	// carrier row inert without deleting it, so invariant A must stop counting
	// that row — and from migration 000054 this is the ONLY flag that can put
	// invariant A in play at all, because the carrier is the only thing that
	// carries the authority. A SCIM deprovision, by contrast, leaves the user
	// able to authenticate and its carrier grant exercisable, so it sets this
	// false.
	DestroysPrincipal bool
}

// Guard evaluates and serializes the two invariants.
//
// The carrier owns platform_admins and the advisory lock; identity owns
// organizations, organization_members, role_templates and users. They are the
// same *sql.DB in the default deployment mode and genuinely different
// databases under TFR_IDENTITY_DATABASE_* — which is why the floor never
// assumes it can put both sides in one transaction.
type Guard struct {
	carrier  *platformadmin.Carrier
	identity *sql.DB

	// beforeCheck runs inside the lock, before the invariant is evaluated.
	// Test-only: it is how adminfloor_postgres_test.go forces the interleaving
	// that a naive two-goroutine race is too fast to hit (the lesson PR #862
	// recorded). Always nil in production.
	beforeCheck func(context.Context)
}

// New constructs a Guard. carrier backs platform_admins and the advisory lock;
// identityDB backs the membership tables.
func New(carrier *platformadmin.Carrier, identityDB *sql.DB) *Guard {
	return &Guard{carrier: carrier, identity: identityDB}
}

// Protect serializes check-then-write for one authority reduction: it takes
// the application-wide lock, evaluates both invariants against the state that
// would result from ch, and runs write only if both still hold.
//
// A nil Guard runs write unprotected. That is the same "wired as a unit"
// convention OrganizationHandlers.creds follows, and it keeps the hundreds of
// existing handler tests that construct no floor working — but it is also the
// one way this package can be silently absent, which is why
// admin_floor_class_test.go asserts the wiring as well as the call sites.
//
// write runs INSIDE the lock. It must not be long-running, and it must not
// take the lock again.
func (g *Guard) Protect(ctx context.Context, ch Change, write func(context.Context) error) error {
	// Short-circuited HERE as well as in Serialize: the closure below closes
	// over g and dereferences it, so delegating the nil case to Serialize
	// would panic before Serialize ever saw it.
	if g == nil {
		return write(ctx)
	}
	return g.Serialize(ctx, func(ctx context.Context) error {
		if err := g.check(ctx, ch); err != nil {
			return err
		}
		return write(ctx)
	})
}

// Serialize runs fn under the application-wide administrator-floor lock WITHOUT
// evaluating the invariants itself.
//
// For the one caller that already has its own last-standing check and needs
// only to be ordered against the others: RevokePlatformAdmin, whose refusal
// runs inside a transaction holding SELECT ... FOR UPDATE over platform_admins
// (PR #862). That check is correct and is deliberately left alone — it is
// stricter than this package's, because it refuses to drop the last CARRIER
// row even when role-template administrators remain, which is the posture the
// carrier-only authority model needs. What it could not do on its own is
// serialise against a membership demotion on the OTHER connection, where its
// row lock reaches nothing. This does that.
//
// A nil Guard runs fn unprotected, on the same convention as Protect.
func (g *Guard) Serialize(ctx context.Context, fn func(context.Context) error) error {
	if g == nil {
		return fn(ctx)
	}
	if g.carrier == nil || g.identity == nil {
		return fmt.Errorf("%w: guard constructed without both the carrier and the identity connection", ErrIndeterminate)
	}

	// The carrier's lock, not one of this package's own: it is
	// pg_advisory_xact_lock on a write-free transaction, keyed by the carrier
	// table so two applications in one database do not serialise against each
	// other. A failure to TAKE it is ErrNotSerialized and fn does not run,
	// which this package reports as ErrIndeterminate — an unserialised change
	// is not a safe fallback for a serialised one.
	err := g.carrier.Serialize(ctx, func(ctx context.Context) error {
		if g.beforeCheck != nil {
			g.beforeCheck(ctx)
		}
		return fn(ctx)
	})
	if errors.Is(err, platformadmin.ErrNotSerialized) || errors.Is(err, platformadmin.ErrNotConfigured) {
		return fmt.Errorf("%w: %w", ErrIndeterminate, err)
	}
	return err
}

// check evaluates both invariants. Order is deliberate: invariant A first,
// because a change that would strand the whole deployment is the worse
// refusal to report, and because a caller reading the error should not have to
// guess which of two refusals came first.
func (g *Guard) check(ctx context.Context, ch Change) error {
	// An organization deletion legitimately names no principal; anything else
	// that does is a mis-wired call site, and answering "fine, go ahead" would
	// leave it writing unprotected forever.
	if strings.TrimSpace(ch.UserID) == "" && !ch.DeletesOrganizations {
		return fmt.Errorf("%w: change names no principal", ErrIndeterminate)
	}
	if ch.DeletesOrganizations && len(ch.OrganizationIDs) == 0 {
		return fmt.Errorf("%w: organization deletion names no organization", ErrIndeterminate)
	}

	if err := g.checkPlatformFloor(ctx, ch); err != nil {
		return err
	}

	// The scopes the principal is left holding in the organization being
	// re-roled. Read after invariant A rather than before it: A no longer needs
	// the answer (it counts the carrier alone), and a change refused there must
	// not have cost a role-template lookup to say so.
	keeps := ch.KeepsScopes
	if ch.KeepsRoleTemplateID != nil {
		var err error
		keeps, err = g.roleTemplateScopes(ctx, *ch.KeepsRoleTemplateID)
		if err != nil {
			return fmt.Errorf("%w: reading the replacement role template: %v", ErrIndeterminate, err)
		}
	}
	return g.checkOrganizationFloor(ctx, ch, keeps)
}

// ---------------------------------------------------------------------------
// Invariant A — the deployment
// ---------------------------------------------------------------------------

// checkPlatformFloor refuses a change that would leave no exercisable platform
// administrator anywhere.
//
// THE CARRIER IS THE ONLY SOURCE IT COUNTS (migration 000054). Until this
// release effective admin was `platform_admins OR an admin-bearing role
// template held through a membership`, and this function counted both. The
// union half is gone, for the reason the package doc gives: the middleware
// strips `admin` from a session whose principal has no carrier row, so a
// membership carrying an admin-bearing template administers nothing. A floor
// that still counted it would answer "an administrator remains" and permit the
// deployment's last real one to be deleted — the exact failure this package
// exists to prevent, arrived at by counting a source of authority that no
// longer is one.
//
// TWO CONSEQUENCES, both deliberate:
//
//  1. A MEMBERSHIP CHANGE CANNOT BREAK INVARIANT A. Removing a member,
//     re-roling one, or deleting an organization and cascading its memberships
//     away does not touch platform_admins, so there is nothing to check and
//     refusing would be a refusal with no hazard behind it. Only a change that
//     destroys the PRINCIPAL — user deletion and GDPR erasure — can make a
//     carrier grant unexercisable, because migration 000051 declines the
//     foreign key that would remove the row, so the arithmetic has to do it
//     here. Invariant B still runs on every one of those paths.
//  2. A PRINCIPAL WHO HOLDS NO CARRIER ROW IS NOT A REDUCTION EITHER. Deleting
//     an ordinary user cannot lower the administrator count, and the previous
//     shape refused it on an already-empty carrier — blocking unrelated work
//     on a deployment that was already broken, which detection
//     (admin_floor_violations), not this guard, is there to report.
//
// The explicit revoke path is unaffected: RevokePlatformAdmin keeps its own,
// stricter last-standing check under SELECT ... FOR UPDATE (PR #862) and uses
// Serialize rather than Protect.
func (g *Guard) checkPlatformFloor(ctx context.Context, ch Change) error {
	if !ch.DestroysPrincipal {
		return nil
	}

	grants, err := g.carrier.List(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading the platform-admin carrier: %v", ErrIndeterminate, err)
	}

	// The grants that would REMAIN exercisable: every row except this
	// principal's, whose row survives the delete but stops being exercisable.
	var remaining []platformadmin.Grant
	var holdsGrant bool
	for _, grant := range grants {
		if grant.UserID == ch.UserID {
			holdsGrant = true
			continue
		}
		remaining = append(remaining, grant)
	}
	if !holdsGrant {
		return nil
	}

	// The same predicate the explicit revoke path runs, so "an administrator
	// that remains" means one thing in this product: a grant that still
	// RESOLVES, with a lookup failure aborting rather than counting as an
	// orphan.
	err = platformadmin.RequireAnotherExercisableAdmin(
		platformadmin.ResolverFunc(g.userExists))(ctx, remaining)
	if err == nil || errors.Is(err, ErrLastPlatformAdmin) {
		return err
	}
	// An identity store that is down must not read as "every remaining grant
	// is an orphan" — the failure mode PR #862 named. Both sentinels survive:
	// this package's callers test ErrIndeterminate, and the cause says which
	// lookup failed.
	return fmt.Errorf("%w: %w", ErrIndeterminate, err)
}

// ---------------------------------------------------------------------------
// Invariant B — each organization
// ---------------------------------------------------------------------------

// checkOrganizationFloor refuses a change that would leave an organization
// with members but no administrator.
//
// AN EMPTY ORGANIZATION IS LEGITIMATE, AND THIS IS THE DELIBERATE DECISION.
// Invariant B is a statement about a STRANDED organization: one whose members
// exist but none of whom can add, remove or re-role anybody, so the
// organization can no longer administer itself and only a platform
// administrator can rescue it. An organization with nobody in it is not
// stranded — it is the empty set, and the invariant is vacuous over it. The
// alternative reading (an organization must always have >= 1 administrator,
// full stop) forbids offboarding the last person from a wound-down
// organization without deleting the organization itself, which is a refusal
// with no hazard behind it and would make DeleteOrganizationHandler the only
// way to remove a final member.
//
// So: members == 0 passes; members >= 1 with zero administrators does not.
func (g *Guard) checkOrganizationFloor(ctx context.Context, ch Change, keeps []string) error {
	// A deleted organization cannot be stranded — it will not exist. Invariant
	// A already covered the authority its members carried deployment-wide.
	if ch.DeletesOrganizations {
		return nil
	}

	orgIDs := ch.OrganizationIDs
	if len(orgIDs) == 0 {
		var err error
		orgIDs, err = g.organizationsOf(ctx, ch.UserID)
		if err != nil {
			return fmt.Errorf("%w: reading the principal's organizations: %v", ErrIndeterminate, err)
		}
	}

	// Whether the change leaves this principal administering the organization
	// it re-roles them in. A removal keeps nothing, whatever template the
	// caller happened to name.
	keepsOrgAdmin := !ch.RemovesMembership && isOrganizationAdmin(keeps)

	for _, orgID := range orgIDs {
		members, admins, err := g.organizationState(ctx, orgID)
		if err != nil {
			return fmt.Errorf("%w: reading organization %s: %v", ErrIndeterminate, orgID, err)
		}

		// Apply the change.
		if ch.RemovesMembership {
			if containsUser(members, ch.UserID) {
				members = withoutUser(members, ch.UserID)
			}
		}
		admins = withoutUser(admins, ch.UserID)
		if keepsOrgAdmin {
			admins = append(admins, ch.UserID)
		}

		if len(members) > 0 && len(admins) == 0 {
			return fmt.Errorf("%w: organization %s", ErrLastOrganizationAdmin, orgID)
		}
	}
	return nil
}

// isOrganizationAdmin reports whether a role template's scopes let its holder
// administer the organization it is held in. `organizations:write` is the
// scope RequireOrgScopeForPathOrg demands on every membership route, and
// `admin` is the platform-wide wildcard that subsumes it.
func isOrganizationAdmin(scopes []string) bool {
	return auth.HasScope(scopes, auth.ScopeAdmin) || auth.HasScope(scopes, auth.ScopeOrganizationsWrite)
}

func containsUser(users []string, id string) bool {
	for _, u := range users {
		if u == id {
			return true
		}
	}
	return false
}

func withoutUser(users []string, id string) []string {
	out := users[:0:0]
	for _, u := range users {
		if u != id {
			out = append(out, u)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// organizationState returns the organization's members and, of those, the ones
// who can administer it. Both lists name only users that still resolve.
// The membership and the user come from the identity tables -- who belongs
// where, and whether the grant resolves to somebody who can exercise it, are
// still identity's facts. The SCOPES come from registry's own tables
// (terraform-suite-identity#206, phase 3b): invariant B asks who can administer
// this organization IN REGISTRY, and since the read cutover that is decided by
// `organization_member_roles` joined to `registry_role_templates`. Reading the
// shared tables here would let the floor certify an administrator the request
// path does not recognise -- refusing a safe demotion, or permitting the one
// that empties the organization.
//
// Both LEFT JOINs, so a member with no mirrored role is still COUNTED AS A
// MEMBER and not as an administrator. That is the fail-closed direction for
// invariant B: it can only make the guard refuse more, never less.
func (g *Guard) organizationState(ctx context.Context, orgID string) (members, admins []string, err error) {
	rows, err := g.identity.QueryContext(ctx, `
		SELECT om.user_id, rrt.scopes
		  FROM organization_members om
		  JOIN users u ON u.id = om.user_id
		  LEFT JOIN organization_member_roles omr
		         ON omr.organization_id = om.organization_id AND omr.user_id = om.user_id
		  LEFT JOIN registry_role_templates rrt ON rrt.id = omr.role_template_id
		 WHERE om.organization_id = $1`, orgID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var userID string
		var raw []byte
		if err := rows.Scan(&userID, &raw); err != nil {
			return nil, nil, err
		}
		members = append(members, userID)
		if isOrganizationAdmin(parseRoleScopes(raw)) {
			admins = append(admins, userID)
		}
	}
	return members, admins, rows.Err()
}

// organizationsOf lists the organizations the principal belongs to.
func (g *Guard) organizationsOf(ctx context.Context, userID string) ([]string, error) {
	rows, err := g.identity.QueryContext(ctx,
		`SELECT organization_id FROM organization_members WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// roleTemplateScopes reads one template's scopes. A template that does not
// exist carries nothing, which is the fail-closed reading: the caller uses
// this to decide whether the principal KEEPS authority, so "unknown" must not
// answer yes.
//
// Registry's own table since phase 3b, matching organizationState above and the
// request path: the caller passes Change.KeepsRoleTemplateID, the id a
// membership write is ABOUT to store, and what that id will confer after the
// write is decided by `registry_role_templates`.
func (g *Guard) roleTemplateScopes(ctx context.Context, roleTemplateID string) ([]string, error) {
	var raw []byte
	err := g.identity.QueryRowContext(ctx,
		`SELECT scopes FROM registry_role_templates WHERE id = $1`, roleTemplateID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseRoleScopes(raw), nil
}

// userExists answers whether a carrier grant names a principal that still
// resolves, on the IDENTITY connection — the cross-connection lookup the
// carrier's missing foreign key makes necessary.
func (g *Guard) userExists(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	var exists bool
	if err := g.identity.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// parseRoleScopes decodes role_templates.scopes in EITHER of its two
// encodings: jsonb `["admin","users:read"]` in the registry's public schema,
// and TEXT[] `{admin,users:read}` in the shared identity schema.
//
// Reading only the jsonb form is not a theoretical omission — checkRoleAssignment
// does exactly that, so this package would have silently counted zero
// administrators in every identity-schema deployment, which for a floor means
// refusing every removal rather than allowing a dangerous one. Wrong either
// way; handled here rather than discovered later.
//
// An unparseable value yields no scopes, so its holder is not counted as an
// administrator. That is the fail-closed direction for a floor: it can only
// make a refusal more likely, never let the last administrator go.
func parseRoleScopes(raw []byte) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var scopes []string
		if err := json.Unmarshal([]byte(trimmed), &scopes); err != nil {
			return nil
		}
		return scopes
	}
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		if inner == "" {
			return nil
		}
		parts := strings.Split(inner, ",")
		scopes := make([]string, 0, len(parts))
		for _, p := range parts {
			// Postgres quotes an array element only when it has to; `admin`
			// and `"admin"` are the same element.
			scopes = append(scopes, strings.Trim(strings.TrimSpace(p), `"`))
		}
		return scopes
	}
	return nil
}
