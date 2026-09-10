package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// GUARD router-phases-do-not-regrow (issue #565 finding [39]).
//
// NewRouter was ~1240 lines mixing dependency construction, key material,
// background-job orchestration, persisted-config reload and ~150 route
// registrations. Route registration moved to router_routes.go, the reloads and
// the authorization-mirror reconcile to router_startup.go, and the key material
// and rate limiters to router_wiring.go. What stops it growing back is this ceiling: nothing else
// can see the rule, because .golangci.yml enables neither funlen nor gocyclo
// nor cyclop, and enabling one repo-wide would flag eight unrelated functions
// and turn into a list of exclusions.
//
// THE CEILING MAY ONLY BE LOWERED. Raising it to make a change fit is the
// change this guard exists to refuse: extract the new phase instead, next to
// the ones already in router_wiring.go. Lower it whenever a phase comes out,
// so the ratchet keeps what the extraction won.
const newRouterLineCeiling = 622

// registerAPIV1Routes is longer still and is deliberately NOT ratcheted here.
// It is a flat list of route registrations -- the length is the route count,
// not tangled control flow -- and #565's finding is about NewRouter mixing
// concerns, which a list of routes does not do.

func TestNewRouterStaysWithinItsCeiling(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}

	var lines int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewRouter" || fn.Recv != nil {
			continue
		}
		lines = fset.Position(fn.End()).Line - fset.Position(fn.Pos()).Line + 1
	}
	if lines == 0 {
		t.Fatal("NewRouter not found in router.go: this guard is measuring nothing")
	}
	if lines > newRouterLineCeiling {
		t.Fatalf("NewRouter is %d lines, ceiling is %d. Extract the new work into a phase "+
			"in router_wiring.go rather than raising the ceiling -- growing back is what "+
			"this guard refuses (#565).", lines, newRouterLineCeiling)
	}
	if lines < newRouterLineCeiling {
		t.Fatalf("NewRouter is %d lines, below the %d ceiling. Lower the ceiling to %d so "+
			"the ratchet keeps what the extraction won.", lines, newRouterLineCeiling, lines)
	}
}

// GUARD router-phases-are-still-called (issue #565 finding [39]).
//
// Extracting a phase out of NewRouter makes it deletable in a way it was not
// before: the body it came from no longer shows the work, only a call, and a
// call is one line to lose in a merge. Proven, not assumed -- deleting
// reconcileAuthorizationMirror's call, or installGlobalMiddleware's, failed
// NOTHING in the whole suite until this test existed. The second is the worse
// of the two: it would have silently removed panic recovery, request IDs,
// metrics, CORS, the security headers and mTLS from every route at once.
//
// Wiring like this cannot be caught by the route-table guards, which see the
// registrations rather than the setup around them, and a unit test cannot
// construct NewRouter without a live database. An AST check is what is left,
// and it is enough: the failure mode is a MISSING call, not a subtly wrong one.
//
// Add a phase here whenever one is extracted. A phase nothing asserts is a
// phase that can be dropped in silence.
var newRouterRequiredPhases = map[string]string{
	"egressAndAuditShipping":       "outbound egress policy for this router, package scm and the identity module's OIDC client; losing it opens every outbound path to internal addresses",
	"reconcileAuthorizationMirror": "brings registry's own role tables into agreement with identity at boot; losing it serves authorization from a stale mirror",
	"installGlobalMiddleware":      "panic recovery, request IDs, metrics, logging, CORS, security headers and mTLS; losing it strips all of them from every route",
}

func TestNewRouterCallsEveryStartupPhase(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}

	var newRouter *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "NewRouter" && fn.Recv == nil {
			newRouter = fn
		}
	}
	if newRouter == nil {
		t.Fatal("NewRouter not found in router.go: this guard is measuring nothing")
	}

	called := map[string]bool{}
	ast.Inspect(newRouter, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				called[id.Name] = true
			}
		}
		return true
	})

	for phase, why := range newRouterRequiredPhases {
		if !called[phase] {
			t.Errorf("NewRouter no longer calls %s. That phase %s. If it moved somewhere NewRouter no longer reaches, update this guard deliberately; do not delete the entry to make the test pass (#565).", phase, why)
		}
	}

	// Non-vacuity: if the walk stopped finding calls at all -- a rename, a
	// refactor that wrapped them -- every assertion above would pass on an
	// empty set.
	if len(called) < 10 {
		t.Fatalf("found only %d direct calls in NewRouter; this guard has stopped "+
			"matching and would pass vacuously", len(called))
	}
}
