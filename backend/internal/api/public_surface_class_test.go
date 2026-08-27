package api

// public_surface_class_test.go makes the unauthenticated API surface a DECLARED
// list rather than an emergent property of which gin group a route was
// registered on (#974).
//
// WHAT WAS WRONG. GET /api/v1/modules/search and /providers/search sit on a
// group with rate limiting and no authentication, and with the shipped default
// the query applies no organization predicate at all -- so an anonymous caller
// receives namespace, name, system, description, source, latest version,
// download count and publisher name for every module and provider in the
// deployment, across every organization.
//
// Under the shared-registry model that is defensible, and the repository relies
// on it elsewhere: internal/api/admin/stats.go declines to scope module and
// provider counts precisely because they "are already enumerable anonymously
// through" these endpoints. But it was an assumption nothing declared and no
// test asserted. orgscope_route_class_test.go skips every unauthenticated route
// with a bare `continue`, so the entire surface was exempt BY CONSTRUCTION --
// and a new public route joined it silently.
//
// WHAT THIS FILE ASSERTS. Every route in registerAPIV1Routes reachable without
// AuthMiddleware must appear below with a reason, and every entry below must
// still name a real unauthenticated route. Both directions, because a one-way
// check rots: adding a public route fails until someone writes down why, and an
// entry that stops matching reality fails rather than sitting as a stale claim.
//
// WHY THE returnsTenantContent FLAG. Per the estate tenancy model, names are
// exactly what isolation forbids leaking -- an isolated tenant must not see
// another tenant's module names. When content becomes host-scoped, these routes
// must filter by host, and a caller with no resolvable host must get NOTHING
// rather than everything. That flag is the work list, derived from the route
// table instead of transcribed into a design document where it would go stale.

import (
	"sort"
	"testing"
)

// publicRoute is the recorded decision for one unauthenticated route.
type publicRoute struct {
	// why the route is reachable without authentication.
	why string
	// returnsTenantContent marks routes that can return registry CONTENT --
	// module or provider names, versions, docs, sources. These are the routes
	// that must gain a host filter when content is partitioned; the rest are
	// structural (login, setup, callbacks, branding) and disclose nothing about
	// what is published.
	returnsTenantContent bool
}

// declaredPublicRoutes is the whole unauthenticated surface of
// registerAPIV1Routes, with the decision for each.
var declaredPublicRoutes = map[string]publicRoute{
	// --- Content discovery -------------------------------------------------
	// INTENTIONALLY PUBLIC under the shared-registry model, and the thing that
	// has to change first under the isolated one. Anonymous discovery of what a
	// registry publishes is the behaviour a Terraform user expects from a
	// registry host, and internal/api/admin/stats.go already depends on it.
	"GET /api/v1/modules/search": {
		why:                  "anonymous discovery of published modules; shared-registry model (#974)",
		returnsTenantContent: true,
	},
	"GET /api/v1/providers/search": {
		why:                  "anonymous discovery of published providers; shared-registry model (#974)",
		returnsTenantContent: true,
	},
	"GET /api/v1/modules/:namespace/:name/:system": {
		why:                  "module detail page; OptionalAuth only decorates it with management actions",
		returnsTenantContent: true,
	},
	"GET /api/v1/modules/:namespace/:name/:system/:version": {
		why:                  "module version detail; OptionalAuth only decorates it",
		returnsTenantContent: true,
	},
	"GET /api/v1/modules/:namespace/:name/:system/versions/:version/docs": {
		why:                  "generated module documentation, rendered on the public detail page",
		returnsTenantContent: true,
	},
	"GET /api/v1/providers/:namespace/:type": {
		why:                  "provider detail page; OptionalAuth only decorates it",
		returnsTenantContent: true,
	},
	"GET /api/v1/providers/:namespace/:type/versions/:version/docs": {
		why:                  "provider documentation index, rendered on the public detail page",
		returnsTenantContent: true,
	},
	"GET /api/v1/providers/:namespace/:type/versions/:version/docs/:category/:slug": {
		why:                  "provider documentation page, rendered on the public detail page",
		returnsTenantContent: true,
	},
	"GET /api/v1/advisories/active": {
		why:                  "CVE banner on the unauthenticated login page; names affected providers",
		returnsTenantContent: true,
	},

	// --- Sign-in ------------------------------------------------------------
	// Unauthenticated by definition: these are how a caller ACQUIRES a session.
	"GET /api/v1/auth/providers":     {why: "which IdPs to offer on the login page; no per-tenant content"},
	"GET /api/v1/auth/login":         {why: "starts the OIDC/OAuth redirect; pre-session by definition"},
	"GET /api/v1/auth/callback":      {why: "IdP redirect target; the principal comes from the IdP, not the caller"},
	"GET /api/v1/auth/saml/metadata": {why: "SAML SP metadata, published for the IdP to consume"},
	"POST /api/v1/auth/saml/acs":     {why: "SAML assertion consumer; the principal comes from a signed assertion"},
	"POST /api/v1/auth/ldap/login":   {why: "credential exchange; pre-session by definition"},
	"POST /api/v1/auth/logout":       {why: "must succeed for an expired or already-invalid session, so it cannot require one"},

	// --- First-boot setup ---------------------------------------------------
	// Reachable only until setup completes; each handler re-checks that. They
	// are unauthenticated because there is no administrator to authenticate as
	// yet -- that is what they create.
	"GET /api/v1/setup/status":            {why: "drives the setup wizard; refuses once setup is complete"},
	"POST /api/v1/setup/admin":            {why: "creates the first administrator; there is nobody to authenticate as yet"},
	"POST /api/v1/setup/complete":         {why: "closes the setup window; refuses once complete"},
	"POST /api/v1/setup/oidc":             {why: "first-boot IdP configuration; refuses once complete"},
	"POST /api/v1/setup/oidc/test":        {why: "first-boot IdP connectivity check; refuses once complete"},
	"POST /api/v1/setup/ldap":             {why: "first-boot LDAP configuration; refuses once complete"},
	"POST /api/v1/setup/ldap/test":        {why: "first-boot LDAP connectivity check; refuses once complete"},
	"POST /api/v1/setup/storage":          {why: "first-boot storage configuration; refuses once complete"},
	"POST /api/v1/setup/storage/test":     {why: "first-boot storage connectivity check; refuses once complete"},
	"POST /api/v1/setup/scanning":         {why: "first-boot scanner configuration; refuses once complete"},
	"POST /api/v1/setup/scanning/test":    {why: "first-boot scanner connectivity check; refuses once complete"},
	"POST /api/v1/setup/scanning/install": {why: "first-boot scanner install; refuses once complete"},
	"POST /api/v1/setup/validate-token":   {why: "validates the setup token itself; the token IS the credential"},
	"PUT /api/v1/setup/ui-theme":          {why: "first-boot branding; refuses once complete"},

	// --- Unauthenticated principals -----------------------------------------
	// These resolve a principal WITHOUT a session, from a server-side row keyed
	// by an unguessable secret. unauth_principal_class_test.go pins that
	// property for each of them; this file only records that they are public.
	"GET /api/v1/scm-providers/:id/oauth/callback":      {why: "SCM OAuth redirect target; principal from a single-use server-side state row"},
	"POST /webhooks/scm/:module_source_repo_id/:secret": {why: "SCM webhook; authenticated by the per-repo secret in the path plus signature verification"},
	"POST /webhooks/approvals/:token":                   {why: "email approval link; authenticated by the single-use token in the path"},

	// --- Pre-session UI -----------------------------------------------------
	// Consumed by the SPA before sign-in. Deployment-shaped, not content.
	"GET /api/v1/ui/theme":       {why: "white-label colours and logo, so the login page renders branded"},
	"GET /api/v1/ui/config":      {why: "feature flags the SPA needs before sign-in"},
	"GET /api/v1/suite/manifest": {why: "suite runtime discovery; advertises this app to its sibling"},

	// --- Development only ---------------------------------------------------
	// Not registered unless DEV_MODE is set (#740); dev_routes_test.go asserts
	// their absence otherwise. This test sets it so the table it reads is the
	// widest the binary can produce.
	"GET /api/v1/dev/status": {why: "dev-mode only; the group is not registered unless DEV_MODE is set (#740)"},
	"POST /api/v1/dev/login": {why: "dev-mode only impersonation; the group is not registered unless DEV_MODE is set (#740)"},
}

// minPublicRoutes is the empty-universe floor.
//
// Every assertion here iterates a set. If the set were empty they would all
// pass while checking nothing -- the one failure mode iteration cannot see, and
// the reason orgscope_route_class_test.go carries the same guard.
const minPublicRoutes = 30

func TestPublicSurfaceIsDeclared(t *testing.T) {
	astTable := readAPIV1RouteTable(t, moduleRoot(t))

	unauth := map[string]bool{}
	for key, route := range astTable {
		authed := false
		for _, mw := range route.mws {
			if middlewareBase(mw) == authMiddleware {
				authed = true
				break
			}
		}
		if !authed {
			unauth[key] = true
		}
	}

	if len(unauth) < minPublicRoutes {
		t.Fatalf("only %d unauthenticated routes were enumerated (floor %d) out of %d total: the "+
			"route table is not being read, so every assertion below is vacuous",
			len(unauth), minPublicRoutes, len(astTable))
	}

	// Direction 1: nothing reaches the public surface without a written reason.
	var undeclared []string
	for key := range unauth {
		if _, ok := declaredPublicRoutes[key]; !ok {
			undeclared = append(undeclared, key)
		}
	}
	sort.Strings(undeclared)
	for _, key := range undeclared {
		t.Errorf("%s is reachable without authentication and is not declared.\n"+
			"Add it to declaredPublicRoutes with the reason, and set returnsTenantContent if it can "+
			"return module/provider names, versions or docs. Public-by-accident is how an "+
			"organization's inventory leaks (#974).", key)
	}

	// Direction 2: no stale claims. An entry that no longer matches an
	// unauthenticated route is either a route that gained auth (delete the
	// entry) or one that was renamed (fix the key) -- and left alone it reads
	// as a considered decision about a route that is not there.
	var stale []string
	for key := range declaredPublicRoutes {
		if !unauth[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		if _, mounted := astTable[key]; mounted {
			t.Errorf("declaredPublicRoutes claims %s is public, but it is behind %s now. Delete the entry.", key, authMiddleware)
		} else {
			t.Errorf("declaredPublicRoutes names %s, which is not mounted at all. Renamed or removed?", key)
		}
	}

	for key, d := range declaredPublicRoutes {
		if d.why == "" {
			t.Errorf("%s is declared public with no reason; the entry records nothing", key)
		}
	}
}

// TestPublicContentRoutesAreTheHostScopingWorkList surfaces the subset that has
// to change when content is partitioned by host.
//
// It asserts the subset is non-empty rather than fixing its size: pinning a
// count makes every legitimate addition a test edit, and the value here is the
// LIST, which is logged. Under the estate tenancy model these are the routes
// that must filter by host and must return nothing -- not everything -- to a
// caller with no resolvable host.
func TestPublicContentRoutesAreTheHostScopingWorkList(t *testing.T) {
	var content []string
	for key, d := range declaredPublicRoutes {
		if d.returnsTenantContent {
			content = append(content, key)
		}
	}
	sort.Strings(content)

	if len(content) == 0 {
		t.Fatal("no public route is marked returnsTenantContent. Either every content route gained " +
			"authentication -- in which case delete this test -- or the flag has stopped being set " +
			"and the host-scoping work list is now silently empty.")
	}
	t.Logf("%d unauthenticated routes return tenant-visible content and must gain a host filter "+
		"when content is partitioned:", len(content))
	for _, key := range content {
		t.Logf("  %s", key)
	}
}
