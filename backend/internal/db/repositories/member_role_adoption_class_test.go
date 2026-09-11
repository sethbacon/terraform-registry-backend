package repositories

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// Class guard for the boot reconcile's ONE remaining write of a role
// (sethbacon/terraform-registry-backend#1056).
//
// # The property
//
// `ReconcileMemberRoles` may not decide a member's role. It confirms membership
// FACTS; the only place in this file that writes a role is
// `adoptSourceAssignments`, the one-time adoption for a deployment whose mirror
// is empty.
//
// # Why a guard and not a test
//
// The defect this replaces was one `mirror.AssignRole` call in the reconcile's
// main loop, copying `organization_members.role_template_id` into registry's
// table on every boot. In a coupled deployment that imported the SIBLING's role
// opinions: the state manager granted `editor`, the shared library wrote
// identity's `editor` id into the shared column, and registry's next boot handed
// the principal registry's `editor` scopes, granted by nobody in registry.
//
// Restoring it is one line, it looks like a repair while you write it, and
// nothing observable fails afterwards -- the tables converge, every request
// succeeds, and the only symptom is people holding roles no administrator in
// this application granted. A behavioural test can prove the current code does
// not do it; only a structural guard makes putting it back fail the build.
//
// # What it checks, and what it deliberately does not
//
// It reads the reconcile file alone. It cannot tell a role-writing call in some
// other file from a legitimate one, and does not try: every other writer of
// `organization_member_roles` is an administrative action reached from a
// request, which is precisely what `member_role_mirror_class_test.go` requires
// to exist.
const reconcileFile = "member_role_reconcile.go"

// roleWritingMirrorCalls are the mirror methods that DECIDE a role. Confirming a
// membership (`ConfirmMembership`) and withdrawing one (`ClearMember`) are not
// here: the first writes no role and the second follows identity's removal of
// the membership fact, which is still identity's to own.
var roleWritingMirrorCalls = map[string]bool{
	"AssignRole": true,
}

// adoptionFunc is the only function in the reconcile file permitted to reach
// them.
const adoptionFunc = "adoptSourceAssignments"

// parseReconcileFile returns the reconcile file's function declarations by name.
func parseReconcileFile(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, reconcileFile, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", reconcileFile, err)
	}
	out := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && fn.Recv == nil {
			out[fn.Name.Name] = fn
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s declares no plain functions: the guard parsed an empty universe", reconcileFile)
	}
	return out
}

// TestReconcileClass_OnlyTheAdoptionWritesARole is the guard.
func TestReconcileClass_OnlyTheAdoptionWritesARole(t *testing.T) {
	funcs := parseReconcileFile(t)

	var writers []string
	for name, fn := range funcs {
		for called := range calledMethodNames(fn) {
			if roleWritingMirrorCalls[called] {
				writers = append(writers, name)
				break
			}
		}
	}
	sort.Strings(writers)

	// NON-VACUITY. A guard that finds no role-writing call at all would pass on
	// a file that had been renamed, gutted, or had its calls spelled some way
	// this cannot see -- certifying whatever it could not read. The adoption
	// MUST be found.
	if len(writers) == 0 {
		t.Fatalf("no call to %v anywhere in %s. The adoption is gone, renamed, or spelled in a form "+
			"this guard cannot see; either way it is no longer checking anything.",
			sortedNames(roleWritingMirrorCalls), reconcileFile)
	}

	for _, name := range writers {
		if name != adoptionFunc {
			t.Errorf("%s.%s writes a member's role (%v). Only %s may: the boot reconcile confirms "+
				"membership FACTS, and copying identity's role_template_id into registry's table is "+
				"how a role granted in the SIBLING application became a registry role at the next boot "+
				"(#1056). If a deployment needs its assignments seeded, that is the one-time adoption, "+
				"and it is gated on an empty mirror.",
				reconcileFile, name, sortedNames(roleWritingMirrorCalls), adoptionFunc)
		}
	}
}

// TestReconcileClass_TheAdoptionIsReachedAndGuarded pins the two halves the
// guard above cannot see on its own: that the adoption is actually called, and
// that the steady-state path exists beside it.
//
// Without the first, `adoptSourceAssignments` could sit unreferenced while the
// reconcile did something else entirely and the guard above still passed. Without
// the second, a reconcile that adopted UNCONDITIONALLY would satisfy every
// assertion here while restoring the defect exactly.
func TestReconcileClass_TheAdoptionIsReachedAndGuarded(t *testing.T) {
	funcs := parseReconcileFile(t)

	entry, ok := funcs["ReconcileMemberRoles"]
	if !ok {
		t.Fatal("ReconcileMemberRoles is not declared in " + reconcileFile)
	}
	called := map[string]bool{}
	ast.Inspect(entry.Body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			called[fun.Name] = true
		case *ast.SelectorExpr:
			called[fun.Sel.Name] = true
		}
		return true
	})

	if !called[adoptionFunc] {
		t.Errorf("ReconcileMemberRoles never calls %s, so the one-time adoption cannot run. "+
			"A deployment upgrading from before migration 000055 arrives with an empty "+
			"organization_member_roles and would be left with every principal holding no role.",
			adoptionFunc)
	}
	if !called["ConfirmMembership"] {
		t.Errorf("ReconcileMemberRoles never calls ConfirmMembership, so the steady-state path is gone. " +
			"Identity owns the membership fact: a membership registry has no row for must be recorded " +
			"with NO role, or the principal is invisible to every authorization read here.")
	}
}
