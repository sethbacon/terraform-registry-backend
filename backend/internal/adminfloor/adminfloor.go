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
// PlatformAdminRepository.Revoke/requireAnotherExercisableAdmin (PR #862), but
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
// authority today: the platform_admins carrier (migration 000051) OR an
// admin-bearing role template held through any membership (the org-less scope
// union, #652). Effective admin is `carrier OR union`, so the floor counts the
// union of both — refusing a demotion because the carrier is empty when four
// union administrators remain would be a refusal with no hazard behind it.
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
// Every check-then-write runs under ONE deployment-wide Postgres advisory
// lock, taken on the registry connection. A per-organization lock would be
// finer, but invariant A is deployment-wide and both invariants are decided by
// the same reads, so a single lock is the only one that makes the composition
// safe — including across the two connections this product may be deployed
// with (identity data can live in another schema or another database entirely,
// migration 000051). These are rare administrative writes, not a hot path.
package adminfloor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// Sentinels. Callers map these onto status codes; they are values rather than
// strings so a handler cannot accidentally serve a refusal as a success, and
// so a test can assert WHICH invariant refused rather than "not 200".
var (
	// ErrLastPlatformAdmin means the change would leave the deployment with no
	// principal holding platform-admin authority (invariant A).
	ErrLastPlatformAdmin = errors.New("adminfloor: the deployment would be left with no platform administrator")

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
	// because it will not exist. Invariant A is not, and this is the only path
	// that can take a deployment's last administrator away without naming a
	// principal at all.
	DeletesOrganizations bool

	// DestroysPrincipal is true when the change removes or anonymises the USER
	// rather than only its memberships — user deletion and GDPR erasure.
	//
	// It matters because platform_admins carries no foreign key to users
	// (migration 000051, deliberately). Destroying the principal makes its
	// carrier row inert without deleting it, so the carrier side of invariant
	// A must stop counting that row. A SCIM deprovision, by contrast, leaves
	// the user able to authenticate and its carrier grant exercisable, so it
	// sets this false.
	DestroysPrincipal bool
}

// Guard evaluates and serializes the two invariants.
//
// registry owns platform_admins and the advisory lock; identity owns
// organizations, organization_members, role_templates and users. They are the
// same *sql.DB in the default deployment mode and genuinely different
// databases under TFR_IDENTITY_DATABASE_* — which is why the floor never
// assumes it can put both sides in one transaction.
type Guard struct {
	registry *sql.DB
	identity *sql.DB

	// beforeCheck runs inside the lock, before the invariant is evaluated.
	// Test-only: it is how adminfloor_postgres_test.go forces the interleaving
	// that a naive two-goroutine race is too fast to hit (the lesson PR #862
	// recorded). Always nil in production.
	beforeCheck func(context.Context)
}

// New constructs a Guard. registryDB backs platform_admins and the advisory
// lock; identityDB backs the membership tables.
func New(registryDB, identityDB *sql.DB) *Guard {
	return &Guard{registry: registryDB, identity: identityDB}
}

// advisoryLockKey namespaces the deployment-wide lock. Derived from a string
// rather than written as a magic number so it cannot be mistyped, and so a
// reader can see what else could collide with it (nothing: no other advisory
// lock is taken anywhere in this module).
var advisoryLockKey = func() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("terraform-registry/adminfloor"))
	return int64(h.Sum64())
}()

// Protect serializes check-then-write for one authority reduction: it takes
// the deployment-wide lock, evaluates both invariants against the state that
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

// Serialize runs fn under the deployment-wide administrator-floor lock WITHOUT
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
	if g.registry == nil || g.identity == nil {
		return fmt.Errorf("%w: guard constructed without both connections", ErrIndeterminate)
	}

	// A transaction that carries no writes. It exists ONLY to scope the
	// advisory lock: pg_advisory_xact_lock pins the lock to this transaction,
	// so it is released by the rollback below however this function exits.
	// The session-level pg_advisory_lock would need a hand-written unlock on
	// every path, and would leak the lock forever if one were missed.
	tx, err := g.registry.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIndeterminate, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("%w: %v", ErrIndeterminate, err)
	}

	if g.beforeCheck != nil {
		g.beforeCheck(ctx)
	}
	return fn(ctx)
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

	// The scopes the principal is left holding in the organization being
	// re-roled. Read ONCE, here, because both invariants need the answer and a
	// second read would be a second chance for the two to disagree.
	keeps := ch.KeepsScopes
	if ch.KeepsRoleTemplateID != nil {
		var err error
		keeps, err = g.roleTemplateScopes(ctx, *ch.KeepsRoleTemplateID)
		if err != nil {
			return fmt.Errorf("%w: reading the replacement role template: %v", ErrIndeterminate, err)
		}
	}

	if err := g.checkPlatformFloor(ctx, ch, keeps); err != nil {
		return err
	}
	return g.checkOrganizationFloor(ctx, ch, keeps)
}

// ---------------------------------------------------------------------------
// Invariant A — the deployment
// ---------------------------------------------------------------------------

// checkPlatformFloor refuses a change that would leave no exercisable platform
// administrator anywhere.
//
// Effective admin is the UNION of the two carriers, evaluated as the change
// would leave them:
//
//   - platform_admins, minus this principal when the change destroys it
//     (migration 000051 declines the foreign key that would do this in SQL, so
//     the arithmetic has to do it here);
//   - an admin-bearing role template held through a membership, minus the
//     memberships this change removes or re-roles.
//
// Both sides require the principal to still resolve to a user, because a grant
// nobody can exercise is a record rather than an administrator.
func (g *Guard) checkPlatformFloor(ctx context.Context, ch Change, keeps []string) error {
	// The union side first: it is the side a fresh deployment relies on
	// entirely, because the setup wizard's bootstrap grant predates the
	// carrier and migration 000051's backfill only ran once.
	admins, err := g.adminBearingMemberships(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading admin-bearing memberships: %v", ErrIndeterminate, err)
	}
	for _, m := range admins {
		if ch.survives(m) {
			return nil
		}
	}
	// Every surviving admin-bearing membership is being taken away — unless
	// the change re-roles the principal onto another admin-bearing template,
	// which is not a reduction at all.
	if !ch.RemovesMembership && !ch.DeletesOrganizations && auth.HasScope(keeps, auth.ScopeAdmin) {
		return nil
	}

	// The carrier side.
	holders, err := g.carrierHolders(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading the platform-admin carrier: %v", ErrIndeterminate, err)
	}
	for _, holder := range holders {
		if holder == ch.UserID && ch.DestroysPrincipal {
			continue // the row survives the delete but stops being exercisable
		}
		exercisable, err := g.userExists(ctx, holder)
		if err != nil {
			// An identity store that is down must not read as "every remaining
			// grant is an orphan" — the failure mode PR #862 named.
			return fmt.Errorf("%w: resolving carrier holder %s: %v", ErrIndeterminate, holder, err)
		}
		if exercisable {
			return nil
		}
	}

	return ErrLastPlatformAdmin
}

// survives reports whether an admin-bearing membership still confers
// platform-admin authority once the change has been written.
//
// One predicate for all four shapes, so a new shape cannot pick up a different
// answer by taking a different branch:
//
//	untouched organization  -> survives, whoever holds it
//	organization deleted    -> every membership in it goes, principal or not
//	somebody else's row     -> survives
//	this principal's row    -> goes
func (ch Change) survives(m membership) bool {
	if !ch.affects(m.orgID) {
		return true
	}
	if ch.DeletesOrganizations {
		return false
	}
	return m.userID != ch.UserID
}

// affects reports whether the change touches the principal's membership in
// orgID. An empty OrganizationIDs means every organization.
func (ch Change) affects(orgID string) bool {
	if len(ch.OrganizationIDs) == 0 {
		return true
	}
	for _, id := range ch.OrganizationIDs {
		if id == orgID {
			return true
		}
	}
	return false
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

type membership struct {
	orgID  string
	userID string
}

// adminScopePrefilter is an over-approximating SQL predicate, refined exactly
// in Go by parseRoleScopes.
//
// It cannot be an exact SQL test because role_templates.scopes has TWO
// encodings in this estate: jsonb in the registry's public schema
// (000001_initial_schema) and TEXT[] in the shared identity schema
// (terraform-suite-identity 000001) — the same split that forced migration
// 000051 to write its backfill twice. `scopes::text LIKE` reads both
// (`["admin"]` and `{admin}`) and never drops a row that the exact test would
// have kept, which is the only direction that matters for a floor.
const adminScopePrefilter = `(rt.scopes::text LIKE '%admin%' OR rt.scopes::text LIKE '%organizations:write%')`

// adminBearingMemberships returns every membership whose role template carries
// the platform-wide `admin` scope AND whose user still resolves.
func (g *Guard) adminBearingMemberships(ctx context.Context) ([]membership, error) {
	rows, err := g.identity.QueryContext(ctx, `
		SELECT om.organization_id, om.user_id, rt.scopes
		  FROM organization_members om
		  JOIN users u ON u.id = om.user_id
		  JOIN role_templates rt ON rt.id = om.role_template_id
		 WHERE `+adminScopePrefilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []membership
	for rows.Next() {
		var m membership
		var raw []byte
		if err := rows.Scan(&m.orgID, &m.userID, &raw); err != nil {
			return nil, err
		}
		if auth.HasScope(parseRoleScopes(raw), auth.ScopeAdmin) {
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

// organizationState returns the organization's members and, of those, the ones
// who can administer it. Both lists name only users that still resolve.
func (g *Guard) organizationState(ctx context.Context, orgID string) (members, admins []string, err error) {
	rows, err := g.identity.QueryContext(ctx, `
		SELECT om.user_id, rt.scopes
		  FROM organization_members om
		  JOIN users u ON u.id = om.user_id
		  LEFT JOIN role_templates rt ON rt.id = om.role_template_id
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
func (g *Guard) roleTemplateScopes(ctx context.Context, roleTemplateID string) ([]string, error) {
	var raw []byte
	err := g.identity.QueryRowContext(ctx,
		`SELECT scopes FROM role_templates WHERE id = $1`, roleTemplateID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseRoleScopes(raw), nil
}

// carrierHolders lists every platform_admins row. On the REGISTRY connection,
// which is where the carrier lives (migration 000051).
func (g *Guard) carrierHolders(ctx context.Context) ([]string, error) {
	rows, err := g.registry.QueryContext(ctx, `SELECT user_id FROM platform_admins`)
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
