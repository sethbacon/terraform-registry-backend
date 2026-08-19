package api

import (
	"go/ast"
	"path/filepath"
	"testing"
)

// Issue #899 — the two guards that replace the dropped foreign keys are only
// as good as their wiring, and the wiring is exactly what no behavioural test
// can see.
//
// Both guards skip when their dependency is nil, on this codebase's standing
// "an unwired optional dependency is a no-op, not a refusal" convention (creds,
// floor, scmTokens all behave that way, and dozens of handler tests rely on
// it). That convention is safe only while something holds the router to
// actually wiring them — otherwise organization deletion silently stops
// refusing, and the unauthenticated webhook silently stops checking, with every
// test still green.
//
// The CONNECTION each repository is built on is load-bearing and is the second
// half of this check:
//
//	scm_providers and mirror_configurations are registry feature tables that
//	stay in the registry's schema at the identity cutover, so their repositories
//	must come off sqlxDB. Building them on identityDB would resolve tables that
//	do not exist in the separate-identity-database topology — the very topology
//	that made migration 000056 drop the foreign keys in the first place.
//
//	organizations is the opposite: it MOVES to the identity schema, so the
//	webhook's existence lookup must come off identityDB or it would ask the
//	wrong database whether a tenant still exists and answer "no" for every one
//	of them — turning a fail-closed guard into a total outage of the webhook
//	route.
//
// Structural, like identity_db_wiring_test.go beside it, and for the same
// reason: the failure is invisible until two schemas exist.

// repoConnections are the repository constructions this guard pins, mapped to
// the connection each MUST be built on.
var repoConnections = map[string]string{
	"scmRepo":    "sqlxDB",
	"mirrorRepo": "sqlxDB",
	"orgRepo":    "identityDB",
}

// guardWirings are the wiring calls that must appear, mapped to the arguments
// they must be handed, in order.
var guardWirings = map[string][]string{
	"WithOrgIntegrationGuards":  {"scmRepo", "mirrorRepo"},
	"WithOrganizationExistence": {"orgRepo"},
}

func TestRouterWiresOrgDeletionAndWebhookOrphanGuards(t *testing.T) {
	path := filepath.Join("router.go")
	_, file := parseGoFile(t, path)

	// 1. Each repository is built on the connection its tables actually live on.
	seenRepo := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name := exprString(assign.Lhs[0])
		if _, watched := repoConnections[name]; !watched {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		seenRepo[name] = exprString(call.Args[0])
		return true
	})
	for name, wantConn := range repoConnections {
		got, ok := seenRepo[name]
		if !ok {
			t.Errorf("%s is no longer constructed in router.go; the guard that depends on it may be unwired", name)
			continue
		}
		if got != wantConn {
			t.Errorf("%s is built on %s, want %s — it would resolve the wrong database once identity moves",
				name, got, wantConn)
		}
	}

	// 2. Each guard is actually handed those repositories.
	seenWiring := map[string][]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, watched := guardWirings[sel.Sel.Name]; !watched {
			return true
		}
		args := make([]string, 0, len(call.Args))
		for _, a := range call.Args {
			args = append(args, exprString(a))
		}
		seenWiring[sel.Sel.Name] = args
		return true
	})
	for method, wantArgs := range guardWirings {
		got, ok := seenWiring[method]
		if !ok {
			t.Errorf("router.go never calls %s: the guard it enables is a no-op in production", method)
			continue
		}
		if len(got) != len(wantArgs) {
			t.Errorf("%s got %d arguments %v, want %d %v", method, len(got), got, len(wantArgs), wantArgs)
			continue
		}
		for i := range wantArgs {
			if got[i] != wantArgs[i] {
				t.Errorf("%s argument %d is %q, want %q", method, i, got[i], wantArgs[i])
			}
		}
	}
}
