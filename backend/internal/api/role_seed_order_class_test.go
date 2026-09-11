package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Class guard for the startup order of the role-template seed and the membership
// reconcile (sethbacon/terraform-registry-backend#1057).
//
// # The property
//
// `SeedSystemRoleTemplates` must be called BEFORE `ReconcileMemberRoles`, in the
// same startup phase.
//
// # Why this needs a guard rather than a comment
//
// The order INVERTED in #1057, and both directions look reasonable in isolation.
//
// It used to be seed-after-reconcile, and that was right: the reconcile derived
// `registry_role_templates` from the shared `role_templates`, so a seed running
// first was overwritten on the same boot. That reasoning is written down in
// several places and is now wrong.
//
// It is now seed-before-reconcile, because the reconcile stopped deriving
// templates and instead VALIDATES each adopted membership's role against the
// template set registry itself defines. On a deployment whose
// `organization_member_roles` is empty — a fresh install, or an upgrade from
// before migration 000055 — the reconcile's one-time adoption reads that set. If
// the seed has not run, the set is empty, every assignment fails the validation,
// and every principal is adopted with NO ROLE. The deployment comes up with
// nobody able to do anything.
//
// That failure is silent in every test that stubs one of the two calls, and it
// only reproduces on a FRESH database — which is exactly the case a unit test
// suite running against an existing fixture does not have. So the order is
// pinned structurally.
const startupFile = "router_startup.go"

// TestRoleSeedRunsBeforeTheMembershipReconcile is the guard.
func TestRoleSeedRunsBeforeTheMembershipReconcile(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, startupFile, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", startupFile, err)
	}

	var seedAt, reconcileAt token.Pos
	var seeds, reconciles int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "SeedSystemRoleTemplates":
			seeds++
			if !seedAt.IsValid() {
				seedAt = call.Pos()
			}
		case "ReconcileMemberRoles":
			reconciles++
			if !reconcileAt.IsValid() {
				reconcileAt = call.Pos()
			}
		}
		return true
	})

	// NON-VACUITY. A guard that finds neither call passes on a file that has
	// been renamed or gutted, certifying an order it never read.
	if seeds == 0 {
		t.Fatalf("%s never calls SeedSystemRoleTemplates. Registry's own role templates are no longer "+
			"derived from anything (#1057), so without this call registry_role_templates holds whatever "+
			"it already had — on a fresh deployment, nothing, and every principal resolves to no role.",
			startupFile)
	}
	if reconciles == 0 {
		t.Fatalf("%s never calls ReconcileMemberRoles: identity memberships would never be recorded "+
			"here, so a principal who is a member in identity is invisible to every authorization read.",
			startupFile)
	}

	if seedAt > reconcileAt {
		t.Errorf("%s calls ReconcileMemberRoles before SeedSystemRoleTemplates. The order inverted in "+
			"#1057 and this is the old one: the reconcile validates an adopted membership's role against "+
			"the templates REGISTRY defines, so on a deployment with an empty organization_member_roles "+
			"it would read an unseeded table, fail every validation, and adopt every principal with NO "+
			"ROLE. Seed first.", startupFile)
	}
}
