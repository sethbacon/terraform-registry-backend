package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
)

// Issue #566 — the seven route tests in this package are hand-written tables.
//
// Every one of them names the routes it checks, so each is a statement about
// the routes that existed the day it was written and about nothing else. That
// is structurally unable to catch the defect that keeps recurring here: a NEW
// route mounted without the guard its siblings carry. POST
// /admin/policies/evaluate shipped that way and was fixed in #855 — one line
// below a sibling in the same block that had RequireOrgScopeForResource — and
// #718/#719/#783 are the same shape at four earlier addresses.
//
// This file asserts an authorization property over the REAL route table
// instead. It enumerates whatever registerAPIV1Routes actually mounts and
// requires every AUTHENTICATED route to answer the question the session JWT
// cannot: the token carries a FLAT, org-less union of the caller's scopes
// across every organization they belong to (#652), so holding `mirrors:read`
// proves nothing about WHICH organization's mirrors may be read. Something on
// the request path has to re-derive that, and this test says what "something"
// is allowed to be:
//
//	1. the route's middleware chain requires the platform-wide `admin` wildcard,
//	   which deliberately crosses organization boundaries (see the AUTHORITY
//	   MODEL comment in internal/tenantscope);
//	2. the chain carries one of the org-resolving guards in internal/middleware;
//	3. the handler itself reaches a tenant-scope resolver;
//	4. the route is named in tenantGuardExemptRoutes with a reason.
//
// A new route that does none of those fails here, once, on the commit that adds
// it.
//
// TWO TABLES, CROSS-CHECKED. Middleware is not observable from gin's
// Engine.Routes() — RouteInfo reports only the terminal handler — so the
// middleware chain is read from the AST of router_routes.go. An AST parse can
// silently miss a route, which would make the whole check vacuous for exactly
// the routes most likely to be unusual. So the AST table is required to match
// the RUNTIME table exactly, in both directions, before anything else is
// asserted: gin is the oracle for WHICH routes exist, the AST is the oracle for
// WHAT GUARDS THEM.

// ---------------------------------------------------------------------------
// The exemption map
// ---------------------------------------------------------------------------

// tenantGuardExemptRoutes are the authenticated routes that legitimately carry
// no per-organization check, each with the reason. Keyed "METHOD /path".
//
// Checked in BOTH directions. An entry naming a route the table no longer
// mounts fails the test, so the list cannot rot into a standing permission
// nobody has re-read — and a renamed route cannot inherit an exemption that was
// granted to something else.
//
// Being a map rather than a prefix or path-pattern rule is the point: a new
// route cannot join this list by living under a plausible-looking prefix,
// somebody has to type it here next to a reason.
var tenantGuardExemptRoutes = map[string]string{
	// --- Reads over platform-global tables --------------------------------
	// None of terraform_mirror_configs, terraform_versions,
	// terraform_version_platforms, terraform_sync_history or releases_gpg_keys
	// carries an organization_id column, so there is no tenant to scope to and
	// no per-org guard that could apply. The authority has to come from the
	// scope itself, which is what platform_mirror_routes_test.go asserts for
	// this family (and why its mutating half requires mirrors:manage).
	"GET /api/v1/admin/terraform-mirrors":                                 "platform-global binary-mirror catalogue; no organization_id on any table it reads",
	"GET /api/v1/admin/terraform-mirrors/:id":                             "platform-global binary-mirror catalogue; no organization_id on any table it reads",
	"GET /api/v1/admin/terraform-mirrors/:id/status":                      "platform-global binary-mirror catalogue; no organization_id on any table it reads",
	"GET /api/v1/admin/terraform-mirrors/:id/history":                     "platform-global binary-mirror catalogue; no organization_id on any table it reads",
	"GET /api/v1/admin/terraform-mirrors/:id/versions":                    "platform-global binary-mirror catalogue; no organization_id on any table it reads",
	"GET /api/v1/admin/terraform-mirrors/:id/versions/:version":           "platform-global binary-mirror catalogue; no organization_id on any table it reads",
	"GET /api/v1/admin/terraform-mirrors/:id/versions/:version/platforms": "platform-global binary-mirror catalogue; no organization_id on any table it reads",
	"GET /api/v1/admin/terraform-mirrors/releases-gpg-keys":               "platform-global HashiCorp releases signing keys; releases_gpg_keys has no organization_id",
	"GET /api/v1/admin/scanning/latest":                                   "reads no table at all — asks the upstream release API which scanner version is current",

	// --- The principal's own data -----------------------------------------
	// The discriminator on these is the CALLER, resolved from c.Get("user_id")
	// by the auth middleware. An organization predicate would be the wrong
	// question: a user is not reachable from an organization by column, only
	// through organization_members.
	"GET /api/v1/auth/me":              "returns the calling principal's own identity and scopes",
	"POST /api/v1/auth/refresh":        "re-mints the calling principal's own token",
	"GET /api/v1/users/me/memberships": "the caller's own memberships, keyed on the authenticated user_id",
	"GET /api/v1/apikeys/:id":          "self-service: authorizes on api_keys.user_id == caller (403 otherwise, unless platform admin); the discriminator is the owning user, not organization_id",
	"DELETE /api/v1/apikeys/:id":       "self-service: authorizes on api_keys.user_id == caller (403 otherwise, unless platform admin); the discriminator is the owning user, not organization_id",

	// --- No organization exists yet, or the table has none -----------------
	"POST /api/v1/organizations": "creates the organization; there is no membership to check against a row that does not exist yet. The auto-grant of org_owner it performs is the named bootstrapExemption in platform_admin_grant_class_test.go",
	"POST /api/v1/users":         "the users table carries no organization_id; gated on users:write",

	// --- Proxy, no local table --------------------------------------------
	"GET /api/v1/suite/modules/:namespace/:name/:system/consumers": "server-side proxy to a sibling suite application (2s timeout, [] on any failure); reads no table in this database",

	// --- SCIM: the IdP-driven platform provisioning surface ----------------
	// SCIM is how an external identity provider administers the whole
	// deployment's users and groups; it passes OrgScopeAllOrganizations
	// explicitly and deliberately, and is gated on scim:provision, which no
	// seeded per-organization role template grants. Narrowing it to the
	// caller's memberships would break provisioning of users who have none yet
	// — which is every user, at the moment they are created.
	"GET /scim/v2/Users":      "IdP-driven platform provisioning; explicitly OrgScopeAllOrganizations, gated on scim:provision",
	"GET /scim/v2/Users/:id":  "IdP-driven platform provisioning; explicitly OrgScopeAllOrganizations, gated on scim:provision",
	"POST /scim/v2/Users":     "IdP-driven platform provisioning; explicitly OrgScopeAllOrganizations, gated on scim:provision",
	"GET /scim/v2/Groups":     "IdP-driven platform provisioning; explicitly OrgScopeAllOrganizations, gated on scim:provision",
	"GET /scim/v2/Groups/:id": "IdP-driven platform provisioning; explicitly OrgScopeAllOrganizations, gated on scim:provision",

	// --- Development-only --------------------------------------------------
	// Not registered at all unless DEV_MODE is set (#740); this test sets it so
	// the table it checks is the widest one the binary can produce.
	// dev_routes_test.go asserts they are absent otherwise.
	"GET /api/v1/dev/users":                 "dev-mode-only impersonation picker; the group is not registered unless DEV_MODE is set (#740)",
	"POST /api/v1/dev/impersonate/:user_id": "dev-mode-only impersonation; the group is not registered unless DEV_MODE is set (#740)",
}

// ---------------------------------------------------------------------------
// The guard vocabularies
// ---------------------------------------------------------------------------

// orgGuardMiddleware are the middleware that resolve the addressed row's — or
// the addressed namespace's — owning organization and authorize the caller
// against THAT organization rather than against the token's org-less union.
var orgGuardMiddleware = map[string]bool{
	"nsAuthz.RequireOrgScopeForResource":     true,
	"nsAuthz.RequireNamespaceAccessFromPath": true,
	"nsAuthz.RequirePublishAccessFromForm":   true,
	"nsAuthz.RequirePublishAccessFromJSON":   true,
	"nsAuthz.RequireModuleAccessByID":        true,
	"nsAuthz.RequireModuleUpdateAccess":      true,
	"nsAuthz.RequireProviderAccessByID":      true,
	"middleware.RequireOrgScopeForPathOrg":   true,
}

// platformAdminMiddleware is the wildcard that deliberately crosses
// organization boundaries. A route behind it is not exempt by omission — it is
// authorized by a scope that no per-organization role template grants.
const platformAdminMiddleware = "middleware.RequireScope(ScopeAdmin)"

// authMiddleware marks the routes this test is about. Routes reachable without
// authentication (the Terraform protocol surface, public search, the setup
// wizard, the login endpoints) answer a different question and are covered by
// public_routes_ratelimit_test.go and unauth_principal_class_test.go.
const authMiddleware = "middleware.AuthMiddleware"

// tenantResolverCalls are the handler-side ways to re-derive the caller's
// per-organization authority. Each one ends at a membership lookup against the
// identity store: tenantscope.Resolve and its package-local wrappers, the two
// axis helpers in internal/api/admin, and the two direct per-org membership
// reads that predate the shared resolver.
//
// OrgScopeAllOrganizations is deliberately NOT here: it is the explicit
// platform-wide widening, the opposite of a check.
var tenantResolverCalls = map[string]bool{
	"tenantscope.Resolve":      true,
	"tenantscope.OwnerOrg":     true,
	"resolveTenantScope":       true,
	"callerTenantScope":        true,
	"requireTenantScopeForOrg": true,
	"userAxisScope":            true,
	"auditScope":               true,
	"GetUserScopesForOrg":      true,
	"GetMemberWithRole":        true,
}

// ---------------------------------------------------------------------------
// AST route table
// ---------------------------------------------------------------------------

// routeGroup mirrors a gin *RouterGroup: a base path plus the middleware in
// effect for routes registered on it FROM THIS POINT ON. Middleware is
// accumulated in source order because gin's Use only applies to routes
// registered after it — devGroup relies on exactly that, mounting two
// unauthenticated routes before it attaches AuthMiddleware.
type routeGroup struct {
	basePath string
	mws      []string
}

// mountedRoute is one row of the route table as read from the AST.
type mountedRoute struct {
	method string
	path   string
	mws    []string
	pos    token.Position
}

func (r mountedRoute) key() string { return r.method + " " + r.path }

var routeHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// joinRoutePaths reproduces gin's joinPaths.
func joinRoutePaths(base, rel string) string {
	if rel == "" {
		return base
	}
	final := path.Join(base, rel)
	if strings.HasSuffix(rel, "/") && !strings.HasSuffix(final, "/") {
		return final + "/"
	}
	if final == "" {
		return "/"
	}
	return final
}

// callSymbol renders a call's callee as "pkg.Func" / "recv.Method" / "Func".
func callSymbol(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
		if sel, ok := f.X.(*ast.SelectorExpr); ok {
			return sel.Sel.Name + "." + f.Sel.Name
		}
		return f.Sel.Name
	}
	return ""
}

// middlewareName names a middleware argument. RequireScope's argument is folded
// into the name because ScopeAdmin is the distinction that matters.
func middlewareName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.CallExpr:
		name := callSymbol(v)
		if len(v.Args) > 0 {
			if sel, ok := v.Args[0].(*ast.SelectorExpr); ok {
				return name + "(" + sel.Sel.Name + ")"
			}
		}
		return name + "()"
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return middlewareName(v.X) + "." + v.Sel.Name
	}
	return fmt.Sprintf("%T", e)
}

func middlewareBase(name string) string {
	if i := strings.Index(name, "("); i >= 0 {
		return name[:i]
	}
	return name
}

// routeTableReader walks registration functions and collects the route table.
type routeTableReader struct {
	fset  *token.FileSet
	funcs map[string]*ast.FuncDecl
	// factories are local `f := func(...) gin.HandlerFunc { ... }` middleware
	// builders. router_routes.go uses four of them (scmProviderOrg,
	// mirrorConfigOrg, approvalOrg, policyOrg); without expanding them, the
	// guard they wrap is invisible and 20 correctly-guarded routes would look
	// unguarded.
	factories map[string][]string
	routes    []mountedRoute
}

// read walks fn in source order. groups binds in-scope identifiers to groups.
func (rr *routeTableReader) read(fn *ast.FuncDecl, groups map[string]*routeGroup, depth int) {
	if fn == nil || fn.Body == nil || depth > 4 {
		return
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			rr.readAssign(node, groups)
		case *ast.ExprStmt:
			call, ok := node.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			// A call into a sibling registration helper — registerSCIMRoutes,
			// registerAuthenticatedGroupMiddleware — with the group passed as
			// its first argument. Recursing with the caller's *routeGroup bound
			// to the parameter name means middleware the helper attaches lands
			// on the caller's group, exactly as it does at run time.
			if id, ok := call.Fun.(*ast.Ident); ok {
				rr.readHelperCall(id, call, groups, depth)
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			g := groups[recv.Name]
			if g == nil {
				return true
			}
			if sel.Sel.Name == "Use" {
				for _, a := range call.Args {
					g.mws = append(g.mws, middlewareName(a))
				}
				return true
			}
			if routeHTTPMethods[sel.Sel.Name] && len(call.Args) >= 2 {
				rr.readRoute(sel.Sel.Name, call, g)
			}
		}
		return true
	})
}

func (rr *routeTableReader) readAssign(node *ast.AssignStmt, groups map[string]*routeGroup) {
	if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
		return
	}
	lhs, ok := node.Lhs[0].(*ast.Ident)
	if !ok {
		return
	}
	if lit, ok := node.Rhs[0].(*ast.FuncLit); ok {
		var inner []string
		ast.Inspect(lit.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				inner = append(inner, callSymbol(c))
			}
			return true
		})
		rr.factories[lhs.Name] = inner
		return
	}
	call, ok := node.Rhs[0].(*ast.CallExpr)
	if !ok {
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Group" || len(call.Args) < 1 {
		return
	}
	parentIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	parent := groups[parentIdent.Name]
	if parent == nil {
		return
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return
	}
	prefix, err := strconv.Unquote(lit.Value)
	if err != nil {
		return
	}
	g := &routeGroup{basePath: joinRoutePaths(parent.basePath, prefix)}
	g.mws = append(g.mws, parent.mws...)
	groups[lhs.Name] = g
}

func (rr *routeTableReader) readHelperCall(id *ast.Ident, call *ast.CallExpr, groups map[string]*routeGroup, depth int) {
	helper := rr.funcs[id.Name]
	if helper == nil || len(call.Args) == 0 || helper.Type.Params == nil || len(helper.Type.Params.List) == 0 {
		return
	}
	argIdent, ok := call.Args[0].(*ast.Ident)
	if !ok {
		return
	}
	g := groups[argIdent.Name]
	if g == nil {
		return
	}
	names := helper.Type.Params.List[0].Names
	if len(names) == 0 {
		return
	}
	rr.read(helper, map[string]*routeGroup{names[0].Name: g}, depth+1)
}

func (rr *routeTableReader) readRoute(method string, call *ast.CallExpr, g *routeGroup) {
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return
	}
	rel, err := strconv.Unquote(lit.Value)
	if err != nil {
		return
	}
	r := mountedRoute{
		method: method,
		path:   joinRoutePaths(g.basePath, rel),
		pos:    rr.fset.Position(call.Pos()),
	}
	r.mws = append(r.mws, g.mws...)
	for _, a := range call.Args[1 : len(call.Args)-1] {
		name := middlewareName(a)
		if inner, ok := rr.factories[middlewareBase(name)]; ok {
			r.mws = append(r.mws, inner...)
			continue
		}
		r.mws = append(r.mws, name)
	}
	rr.routes = append(rr.routes, r)
}

// readAPIV1RouteTable parses router_routes.go and returns the route table
// registerAPIV1Routes mounts, keyed "METHOD /path".
func readAPIV1RouteTable(t *testing.T, root string) map[string]mountedRoute {
	t.Helper()
	fset := token.NewFileSet()
	src := filepath.Join(root, "internal/api/router_routes.go")
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
			funcs[fd.Name.Name] = fd
		}
	}
	entry := funcs["registerAPIV1Routes"]
	if entry == nil || entry.Type.Params == nil || len(entry.Type.Params.List) == 0 ||
		len(entry.Type.Params.List[0].Names) == 0 {
		t.Fatal("registerAPIV1Routes not found in internal/api/router_routes.go, or its first " +
			"parameter is unnamed — this reader is looking at the wrong function and would " +
			"certify an empty table")
	}
	rr := &routeTableReader{fset: fset, funcs: funcs, factories: map[string][]string{}}
	rr.read(entry, map[string]*routeGroup{entry.Type.Params.List[0].Names[0].Name: {}}, 0)

	table := map[string]mountedRoute{}
	for _, r := range rr.routes {
		table[r.key()] = r
	}
	return table
}

// ---------------------------------------------------------------------------
// Runtime route table
// ---------------------------------------------------------------------------

// mountRealAPIV1Routes builds the production route table with sparse
// dependencies. Handlers are never invoked here — only the shape of the table
// is read — so a nil dependency a handler would have dereferenced is harmless.
func mountRealAPIV1Routes(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	sqlxDB := sqlx.NewDb(db, "sqlmock")

	limiter := middleware.NewRateLimiter(middleware.RateLimitConfig{
		RequestsPerMinute: 600, BurstSize: 100, CleanupInterval: time.Minute,
	})
	t.Cleanup(limiter.Stop)

	r := gin.New()
	registerAPIV1Routes(r, &apiV1RouteDeps{
		cfg:                &config.Config{},
		db:                 db,
		identityDB:         db,
		sqlxDB:             sqlxDB,
		userRepo:           repositories.NewUserRepository(db),
		generalRateLimiter: limiter,
		orgRateLimiter:     limiter,
		nsAuthz: middleware.NewNamespaceAuthorizer(
			repositories.NewOrganizationRepository(db),
			repositories.NewNamespaceClaimRepository(db),
			repositories.NewModuleRepository(db),
			repositories.NewProviderRepository(db),
		),
		mirrorRepo:       repositories.NewMirrorRepository(sqlxDB),
		rbacRepo:         repositories.NewRBACRepositoryWithIdentity(sqlxDB, sqlxDB),
		auditLogHandlers: admin.NewAuditLogHandlers(db),
	})
	return r
}

// ---------------------------------------------------------------------------
// Handler index and reachability
// ---------------------------------------------------------------------------

// handlerIndex maps declared functions and methods across the module so a gin
// handler symbol can be resolved back to source.
type handlerIndex struct {
	byMethod map[string]*ast.FuncDecl // "(*Type).Method"
	byFunc   map[string]*ast.FuncDecl // "pkg.Func"
	recvType map[*ast.FuncDecl]string
	pkgName  map[*ast.FuncDecl]string
}

func buildHandlerIndex(t *testing.T, root string) *handlerIndex {
	t.Helper()
	idx := &handlerIndex{
		byMethod: map[string]*ast.FuncDecl{},
		byFunc:   map[string]*ast.FuncDecl{},
		recvType: map[*ast.FuncDecl]string{},
		pkgName:  map[*ast.FuncDecl]string{},
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "vendor" || n == "testdata" || strings.HasPrefix(n, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", p, perr)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			idx.pkgName[fd] = f.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				rt := receiverTypeName(fd.Recv.List[0].Type)
				idx.recvType[fd] = rt
				idx.byMethod["(*"+rt+")."+fd.Name.Name] = fd
				continue
			}
			idx.byFunc[f.Name.Name+"."+fd.Name.Name] = fd
		}
		return nil
	})
	if err != nil {
		t.Fatalf("index module: %v", err)
	}
	return idx
}

func receiverTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return receiverTypeName(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		return receiverTypeName(v.X)
	}
	return ""
}

// closureSuffix strips the ".funcN" gin appends for a handler that is a closure
// returned by a constructor, including nested forms like ".func3.1".
var closureSuffix = regexp.MustCompile(`(\.func\d+)+(\.\d+)*$`)

// resolveHandlerSymbol maps a gin RouteInfo.Handler to the function that
// declares it. Two shapes occur:
//
//	.../internal/api/admin.(*MirrorHandler).GetMirrorConfig-fm
//	.../internal/api.registerAPIV1Routes.(*APIKeyHandlers).ListAPIKeysHandler.func92
//
// The second is a closure the runtime attributes to the package of the
// ENCLOSING function rather than the declaring one, so a package-qualified
// lookup fails for it and the bare name is used — rejected if ambiguous rather
// than guessed.
func (idx *handlerIndex) resolveHandlerSymbol(sym string) (*ast.FuncDecl, string) {
	s := closureSuffix.ReplaceAllString(strings.TrimSuffix(sym, "-fm"), "")
	if i := strings.Index(s, ".(*"); i >= 0 {
		key := s[i+1:]
		return idx.byMethod[key], key
	}
	parts := strings.Split(s, "/")
	last := parts[len(parts)-1]
	if fd := idx.byFunc[last]; fd != nil {
		return fd, last
	}
	segs := strings.Split(last, ".")
	bare := segs[len(segs)-1]
	var hit *ast.FuncDecl
	var hitKey string
	matches := 0
	for k, fd := range idx.byFunc {
		if strings.HasSuffix(k, "."+bare) {
			matches++
			hit, hitKey = fd, k
		}
	}
	if matches == 1 {
		return hit, hitKey
	}
	return nil, last
}

// reachesTenantResolver reports whether fd calls a tenant-scope resolver, or
// reaches one through a function in its own package or a method on its own
// receiver. Expansion is deliberately limited to those two edges: both are
// resolvable from the AST without type information, which keeps the answer
// exact. A resolver reached only through some other package's type would not be
// seen — that direction produces a demand for an exemption, never a silent
// pass, so the failure mode is a test that asks for justification rather than
// one that grants it.
func (idx *handlerIndex) reachesTenantResolver(fd *ast.FuncDecl, depth int, seen map[*ast.FuncDecl]bool) (string, bool) {
	if fd == nil || depth > 4 || seen[fd] {
		return "", false
	}
	seen[fd] = true

	recvIdent := ""
	if fd.Recv != nil && len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1 {
		recvIdent = fd.Recv.List[0].Names[0].Name
	}
	recvType := idx.recvType[fd]
	pkg := idx.pkgName[fd]

	via := ""
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if via != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callSymbol(call)
		short := name
		if i := strings.LastIndex(name, "."); i >= 0 {
			short = name[i+1:]
		}
		if tenantResolverCalls[name] || tenantResolverCalls[short] {
			via = name
			return false
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			if next := idx.byFunc[pkg+"."+id.Name]; next != nil {
				if v, ok := idx.reachesTenantResolver(next, depth+1, seen); ok {
					via = v
					return false
				}
			}
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == recvIdent && recvType != "" {
				if next := idx.byMethod["(*"+recvType+")."+sel.Sel.Name]; next != nil {
					if v, ok := idx.reachesTenantResolver(next, depth+1, seen); ok {
						via = v
						return false
					}
				}
			}
		}
		return true
	})
	return via, via != ""
}

// ---------------------------------------------------------------------------
// Vacuity
// ---------------------------------------------------------------------------

// These are floors, not counts. The real figures when this landed were 208
// routes, 170 of them authenticated, 146 of those guarded; the floors sit well
// below so they only fire when a table stops being enumerated at all. They must
// never be raised to track the real figures, or every new route becomes a test
// edit and the floor stops meaning "this is not vacuous".
const (
	minAPIV1Routes         = 150
	minAuthenticatedRoutes = 100
	minGuardedRoutes       = 60
)

// checkNotVacuous is the empty-universe guard, factored out as a pure function
// so it can be falsified directly (TestOrgScopeRouteClass_RefusesAnEmptyUniverse
// hands it nothing and requires it to complain). Every other assertion in this
// file iterates a set; if that set is empty they all pass while checking
// nothing, which is the one failure mode iteration cannot see.
func checkNotVacuous(routes map[string]mountedRoute, authenticated, guarded int) error {
	if len(routes) < minAPIV1Routes {
		return fmt.Errorf("registerAPIV1Routes yielded only %d routes (floor %d): the route "+
			"table is not being enumerated, so every assertion over it is vacuous",
			len(routes), minAPIV1Routes)
	}
	if authenticated < minAuthenticatedRoutes {
		return fmt.Errorf("only %d of %d routes were classified as authenticated (floor %d): %q "+
			"no longer matches the middleware chain, so the routes this test exists for are "+
			"being skipped", authenticated, len(routes), minAuthenticatedRoutes, authMiddleware)
	}
	if guarded < minGuardedRoutes {
		return fmt.Errorf("only %d authenticated routes resolved a tenant scope (floor %d): the "+
			"guard vocabularies (orgGuardMiddleware / tenantResolverCalls) have gone stale, so "+
			"guarded routes are being reported as exempt-or-broken", guarded, minGuardedRoutes)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

// TestOrgScopeRouteClass_ASTTableMatchesTheRealRouter is the prerequisite for
// everything below it. The middleware chain is only visible in the AST, and the
// set of routes is only authoritative at run time; if the two disagree, the
// classification is being applied to a table that is not the one gin serves.
//
// Checked in both directions. A route the reader misses would be silently
// unchecked (the dangerous direction); a route the reader invents would be
// classified against middleware no request ever runs.
func TestOrgScopeRouteClass_ASTTableMatchesTheRealRouter(t *testing.T) {
	// Dev routes are registered only when DEV_MODE is set (#740). Setting it
	// here makes the runtime table the WIDEST the binary can produce, so the
	// dev endpoints are classified rather than quietly absent.
	t.Setenv("DEV_MODE", "true")

	astTable := readAPIV1RouteTable(t, moduleRoot(t))
	runtimeTable := map[string]string{}
	for _, ri := range mountRealAPIV1Routes(t).Routes() {
		runtimeTable[ri.Method+" "+ri.Path] = ri.Handler
	}

	var onlyRuntime, onlyAST []string
	for k := range runtimeTable {
		if _, ok := astTable[k]; !ok {
			onlyRuntime = append(onlyRuntime, k)
		}
	}
	for k := range astTable {
		if _, ok := runtimeTable[k]; !ok {
			onlyAST = append(onlyAST, k)
		}
	}
	sort.Strings(onlyRuntime)
	sort.Strings(onlyAST)

	if len(onlyRuntime) > 0 {
		t.Errorf("gin serves %d route(s) the AST reader did not find: %s.\nThese are "+
			"UNCHECKED by the guard below. Teach readAPIV1RouteTable the registration shape "+
			"they use — do not narrow the guard to match the reader.",
			len(onlyRuntime), strings.Join(onlyRuntime, ", "))
	}
	if len(onlyAST) > 0 {
		t.Errorf("the AST reader invented %d route(s) gin does not serve: %s.\nThe "+
			"classification below would be judging middleware that never runs.",
			len(onlyAST), strings.Join(onlyAST, ", "))
	}
	if len(astTable) < minAPIV1Routes {
		t.Fatalf("only %d routes read (floor %d) — the table is not being enumerated",
			len(astTable), minAPIV1Routes)
	}
}

// TestOrgScopeRouteClass_EveryAuthenticatedRouteResolvesATenant is the guard.
func TestOrgScopeRouteClass_EveryAuthenticatedRouteResolvesATenant(t *testing.T) {
	t.Setenv("DEV_MODE", "true")

	root := moduleRoot(t)
	astTable := readAPIV1RouteTable(t, root)
	idx := buildHandlerIndex(t, root)

	runtimeTable := map[string]string{}
	for _, ri := range mountRealAPIV1Routes(t).Routes() {
		runtimeTable[ri.Method+" "+ri.Path] = ri.Handler
	}

	var keys []string
	for k := range astTable {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	authenticated, guarded := 0, 0
	claimedExemptions := map[string]bool{}

	for _, key := range keys {
		route := astTable[key]

		isAuthenticated, isPlatformAdmin := false, false
		orgGuard := ""
		for _, mw := range route.mws {
			base := middlewareBase(mw)
			switch {
			case base == authMiddleware:
				isAuthenticated = true
			case mw == platformAdminMiddleware:
				isPlatformAdmin = true
			case orgGuardMiddleware[base]:
				orgGuard = base
			}
		}
		if !isAuthenticated {
			continue
		}
		authenticated++

		if isPlatformAdmin || orgGuard != "" {
			guarded++
			// An exemption on an already-guarded route is a claim nobody
			// re-reads; surface it rather than letting it sit.
			if _, exempt := tenantGuardExemptRoutes[key]; exempt {
				claimedExemptions[key] = true
				via := orgGuard
				if isPlatformAdmin {
					via = platformAdminMiddleware
				}
				t.Errorf("%s carries a guard (%s) AND a tenantGuardExemptRoutes entry — "+
					"drop the exemption, it is describing something that is no longer true",
					key, via)
			}
			continue
		}

		sym, ok := runtimeTable[key]
		if !ok {
			// The cross-check test reports the mismatch; do not double-report,
			// but do not certify the route either.
			t.Errorf("%s is in the AST table but not the runtime table — cannot resolve its "+
				"handler, so it cannot be certified", key)
			continue
		}
		fd, symKey := idx.resolveHandlerSymbol(sym)
		if fd == nil {
			t.Errorf("%s: cannot resolve handler %q (looked for %q) to a declaration. A handler "+
				"this test cannot read is a handler it cannot certify — teach "+
				"resolveHandlerSymbol the shape, do not exempt the route.", key, sym, symKey)
			continue
		}
		if via, ok := idx.reachesTenantResolver(fd, 0, map[*ast.FuncDecl]bool{}); ok {
			guarded++
			if _, exempt := tenantGuardExemptRoutes[key]; exempt {
				claimedExemptions[key] = true
				t.Errorf("%s resolves a tenant scope in its handler (via %s) AND has a "+
					"tenantGuardExemptRoutes entry — drop the exemption", key, via)
			}
			continue
		}
		if _, exempt := tenantGuardExemptRoutes[key]; exempt {
			claimedExemptions[key] = true
			continue
		}

		t.Errorf(`%s (%s) is authenticated but re-checks nothing about the caller's organization.

  handler: %s
  chain:   %s

The session JWT carries a FLAT, org-less union of the caller's scopes across
every organization they belong to (#652), so passing RequireScope proves the
caller holds the scope SOMEWHERE, not here. Give the route one of:

  * an org guard in its chain (%s), or
  * a tenant-scope resolver in the handler (tenantscope.Resolve /
    resolveTenantScope / requireTenantScopeForOrg), or
  * an entry in tenantGuardExemptRoutes naming the reason it needs none.

This is the defect #855 fixed at POST /admin/policies/evaluate, which sat one
line below a sibling that had the guard.`,
			key, route.pos, symKey, strings.Join(route.mws, " -> "),
			strings.Join(sortedKeys(orgGuardMiddleware), " / "))
	}

	if err := checkNotVacuous(astTable, authenticated, guarded); err != nil {
		t.Fatal(err)
	}

	// The other direction: an exemption that no longer names an unguarded
	// authenticated route.
	var stale []string
	for key := range tenantGuardExemptRoutes {
		if !claimedExemptions[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		if _, mounted := astTable[key]; !mounted {
			t.Errorf("tenantGuardExemptRoutes names %q, which registerAPIV1Routes no longer "+
				"mounts — remove the entry. An exemption for a route that does not exist is "+
				"waiting for the next route to take that path and inherit it.", key)
			continue
		}
		t.Errorf("tenantGuardExemptRoutes names %q, which is no longer an unguarded "+
			"authenticated route — remove the entry.", key)
	}

	t.Logf("classified %d authenticated routes: %d guarded, %d exempt",
		authenticated, guarded, len(claimedExemptions))
}

// TestOrgScopeRouteClass_RefusesAnEmptyUniverse falsifies the vacuity guard.
// Without this, checkNotVacuous is itself untested: a floor that never fires is
// indistinguishable from no floor at all.
func TestOrgScopeRouteClass_RefusesAnEmptyUniverse(t *testing.T) {
	tests := []struct {
		name          string
		routes        map[string]mountedRoute
		authenticated int
		guarded       int
	}{
		{"no routes at all", map[string]mountedRoute{}, 0, 0},
		{"nil table", nil, 0, 0},
		{"table read, but nothing recognised as authenticated",
			fakeRouteTable(minAPIV1Routes + 10), 0, 0},
		{"authenticated routes found, but no guard vocabulary matched",
			fakeRouteTable(minAPIV1Routes + 10), minAuthenticatedRoutes + 10, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkNotVacuous(tt.routes, tt.authenticated, tt.guarded); err == nil {
				t.Fatal("checkNotVacuous certified an empty/degenerate universe — it must " +
					"refuse rather than pass, or the guard reports green while checking nothing")
			}
		})
	}

	// Positive control: the real shape must still pass, otherwise the floors
	// above are simply unreachable and the check is a constant failure.
	if err := checkNotVacuous(fakeRouteTable(minAPIV1Routes+10), minAuthenticatedRoutes+10, minGuardedRoutes+10); err != nil {
		t.Fatalf("checkNotVacuous rejected a well-formed universe: %v", err)
	}
}

// TestOrgScopeRouteClass_ReaderSeesTheGuardsItLooksFor pins the AST reader
// against the two shapes that would otherwise make it lie by omission: a group
// whose middleware is attached by a helper function, and a per-route guard
// built by a local factory closure. Both are used by router_routes.go today,
// and a reader blind to either reports correctly-guarded routes as unguarded —
// which pressures whoever hits it into adding exemptions for routes that are
// fine.
func TestOrgScopeRouteClass_ReaderSeesTheGuardsItLooksFor(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	astTable := readAPIV1RouteTable(t, moduleRoot(t))

	// Attached by registerAuthenticatedGroupMiddleware, not by a .Use in
	// registerAPIV1Routes itself.
	viaHelper, ok := astTable["GET /api/v1/auth/me"]
	if !ok {
		t.Fatal("GET /api/v1/auth/me is not in the table")
	}
	if !hasMiddlewareBase(viaHelper, authMiddleware) {
		t.Errorf("the reader did not follow registerAuthenticatedGroupMiddleware: %v", viaHelper.mws)
	}

	// Built by the local scmProviderOrg closure, which wraps
	// nsAuthz.RequireOrgScopeForResource.
	viaFactory, ok := astTable["GET /api/v1/scm-providers/:id"]
	if !ok {
		t.Fatal("GET /api/v1/scm-providers/:id is not in the table")
	}
	if !hasMiddlewareBase(viaFactory, "nsAuthz.RequireOrgScopeForResource") {
		t.Errorf("the reader did not expand the scmProviderOrg factory closure: %v", viaFactory.mws)
	}

	// Ordering within a group: devGroup mounts two routes BEFORE attaching
	// AuthMiddleware. A reader that hoisted group middleware would mark them
	// authenticated and demand a tenant guard for an unauthenticated route.
	preUse, ok := astTable["POST /api/v1/dev/login"]
	if !ok {
		t.Fatal("POST /api/v1/dev/login is not in the table (is DEV_MODE set?)")
	}
	if hasMiddlewareBase(preUse, authMiddleware) {
		t.Errorf("the reader hoisted a later .Use onto an earlier route: %v", preUse.mws)
	}
	postUse, ok := astTable["GET /api/v1/dev/users"]
	if !ok {
		t.Fatal("GET /api/v1/dev/users is not in the table")
	}
	if !hasMiddlewareBase(postUse, authMiddleware) {
		t.Errorf("the reader dropped a .Use that precedes the route: %v", postUse.mws)
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod, so the scan covers the whole module however it is invoked.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs cwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test's working directory")
		}
		dir = parent
	}
}

func hasMiddlewareBase(r mountedRoute, base string) bool {
	for _, mw := range r.mws {
		if middlewareBase(mw) == base {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fakeRouteTable builds n distinct routes for the vacuity falsification tests.
func fakeRouteTable(n int) map[string]mountedRoute {
	out := make(map[string]mountedRoute, n)
	for i := 0; i < n; i++ {
		r := mountedRoute{method: "GET", path: fmt.Sprintf("/fake/%d", i)}
		out[r.key()] = r
	}
	return out
}
