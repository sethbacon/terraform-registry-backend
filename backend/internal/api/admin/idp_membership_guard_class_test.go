package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Issue #766 — every IdP-driven membership write must pass the provisionable
// guard before it lands.
//
// The seeded `admin` role template carries the wildcard scope, and the session
// scope union is org-less (#652), so holding it in ONE organization confers it
// everywhere. auth.ValidateProvisionableScopes exists to keep an IdP-driven
// mapping from granting it without a human in the loop, and
// guardProvisionableRole is the wrapper that applies it.
//
// It was applied on two of the three membership-write branches in
// reconcileGroupMemberships. The third — the default_role first-login fallback
// — wrote the membership directly. That branch is the WIDEST of the three: a
// group mapping grants to members of a mapped group, while default_role grants
// to every user who can authenticate, on first login. With
// auth.<provider>.default_role naming an admin-bearing template, anyone who
// could log in received the platform-wide wildcard.
//
// The defect is an ABSENT CALL, so no test of any branch's behaviour
// generalises to the next branch someone adds. This walks the AST instead and
// requires the guard on every membership write in the file, which is the shape
// that fails when a fourth branch appears without one.

// membershipWriteMethods are the repository calls that create or change a
// member's role. A new one added to this file without a row here would go
// unexamined, so the vocabulary check below pins the list against the source.
var membershipWriteMethods = map[string]bool{
	"AddMemberWithParams":       true,
	"AddMemberWithRoleTemplate": true,
	"UpdateMemberRole":          true,
	"UpdateMemberRoleTemplate":  true,
}

// guardCallNames are the accepted ways to reach auth.ValidateProvisionableScopes.
// resolveProvisionableRole is the closure in reconcileGroupMemberships that
// wraps guardProvisionableRole and logs the rejection.
var guardCallNames = map[string]bool{
	"guardProvisionableRole":   true,
	"resolveProvisionableRole": true,
}

func parseAuthFile(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "auth.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse auth.go: %v", err)
	}
	return fset, f
}

// callName returns the method or function name of a call expression.
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

// guardPositionsIn collects the offsets of calls named in names, inside n, that
// could actually run on the path to writePos.
//
// names is a parameter rather than the guardCallNames global it started as
// because platform_admin_grant_class_test.go runs the same path analysis over
// the whole module with a wider set (the human-driven checkRoleAssignment
// ceiling as well as the IdP guard). One walker, two vocabularies — a second
// copy of this is the divergence the three false results below were caused by.
//
// Path-awareness is the whole point, and this test reported a FALSE PASS twice
// before it had any:
//
//  1. reconcileGroupMemberships defines resolveProvisionableRole as a closure
//     whose body calls guardProvisionableRole. A naive walk finds that call at a
//     position earlier than every membership write in the function.
//  2. Two sibling `case` clauses call resolveProvisionableRole(). Those calls are
//     also textually earlier than the default_role block that follows the loop,
//     so ascending to the function body counted them for a write in a different
//     branch entirely.
//
// Both made the unguarded default_role branch — the exact defect this test
// exists to catch — look guarded. Verified each time by reverting the fix and
// watching the test still pass.
//
// So a branch construct that does not contain writePos is not descended into.
// But its HEADER still is: `if _, ok := resolveProvisionableRole(); !ok` puts
// the guard in the if-statement's Init, which runs unconditionally even though
// the write sits after the if rather than inside it. Skipping the whole node
// there produced the opposite error — a false FAILURE on a correctly guarded
// branch. Init/Cond/Post run on the way past; Body/Else do not.
func guardPositionsIn(n ast.Node, writePos token.Pos, names map[string]bool) []token.Pos {
	contains := func(x ast.Node) bool {
		return x != nil && writePos >= x.Pos() && writePos <= x.End()
	}
	var out []token.Pos
	var collect func(ast.Node)

	// header gathers guard calls from parts that execute unconditionally when
	// control reaches the construct at all.
	header := func(parts ...ast.Node) {
		for _, p := range parts {
			if p != nil && !isNilNode(p) {
				collect(p)
			}
		}
	}

	collect = func(root ast.Node) {
		ast.Inspect(root, func(x ast.Node) bool {
			if x == nil {
				return false
			}
			if x != root && !contains(x) {
				switch st := x.(type) {
				case *ast.FuncLit:
					return false // a definition, not a call on this path
				case *ast.IfStmt:
					header(st.Init, st.Cond)
					return false
				case *ast.SwitchStmt:
					header(st.Init, st.Tag)
					return false
				case *ast.TypeSwitchStmt:
					header(st.Init, st.Assign)
					return false
				case *ast.ForStmt:
					header(st.Init, st.Cond, st.Post)
					return false
				case *ast.RangeStmt:
					header(st.X)
					return false
				case *ast.SelectStmt, *ast.CaseClause, *ast.CommClause:
					return false
				}
			}
			if call, ok := x.(*ast.CallExpr); ok && names[callName(call)] {
				out = append(out, call.Pos())
			}
			return true
		})
	}
	collect(n)
	return out
}

// isNilNode reports whether an ast.Node interface holds a typed nil, which the
// optional Init/Cond/Post fields above frequently are.
func isNilNode(n ast.Node) bool {
	switch v := n.(type) {
	case *ast.AssignStmt:
		return v == nil
	case *ast.ExprStmt:
		return v == nil
	case *ast.BinaryExpr:
		return v == nil
	case *ast.CallExpr:
		return v == nil
	case *ast.Ident:
		return v == nil
	}
	return false
}

func TestIdPMembershipWrites_AreAllBehindTheProvisionableGuard(t *testing.T) {
	fset, file := parseAuthFile(t)

	// Every enclosing node of each write, innermost first, so a guard applied
	// anywhere up the chain within the same function counts.
	var found int
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Stack of enclosing block-ish nodes as we descend.
		var stack []ast.Node
		var walk func(ast.Node) bool
		walk = func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch n.(type) {
			case *ast.BlockStmt, *ast.CaseClause, *ast.IfStmt, *ast.FuncLit:
				stack = append(stack, n)
				defer func() { stack = stack[:len(stack)-1] }()
			}

			if call, ok := n.(*ast.CallExpr); ok && membershipWriteMethods[callName(call)] {
				found++
				pos := call.Pos()

				var guarded bool
				for _, enclosing := range stack {
					for _, g := range guardPositionsIn(enclosing, pos, guardCallNames) {
						// Strictly before the write: a guard that runs after the
						// membership has already landed is not a guard.
						if g < pos {
							guarded = true
							break
						}
					}
					if guarded {
						break
					}
				}

				if !guarded {
					t.Errorf("%s: %s is called in %s with no guardProvisionableRole/"+
						"resolveProvisionableRole ahead of it. An IdP-driven membership "+
						"write must reject admin-bearing templates before it lands "+
						"(issue #766) — the default_role fallback shipped without this "+
						"and granted the platform-wide wildcard to every user on first "+
						"login.", fset.Position(pos), callName(call), fn.Name.Name)
				}
			}

			for _, child := range childrenOf(n) {
				walk(child)
			}
			return true
		}
		walk(fn.Body)
		return false // walk() already descended this function
	})

	// The failure mode the loop cannot see: if the method names drift, the
	// walk matches nothing and reports green while checking nothing.
	if found == 0 {
		t.Fatal("found no membership-write calls in auth.go — membershipWriteMethods " +
			"is stale, so this guard is vacuous. Re-derive it from the repository's " +
			"organization-member write methods.")
	}
	t.Logf("checked %d membership-write call site(s)", found)
}

// childrenOf enumerates a node's direct children. ast.Inspect cannot be used
// for the walk above because it gives no way to maintain an enclosing-node
// stack across the descent.
func childrenOf(n ast.Node) []ast.Node {
	var out []ast.Node
	first := true
	ast.Inspect(n, func(c ast.Node) bool {
		if first {
			first = false
			return true
		}
		if c != nil {
			out = append(out, c)
		}
		return false // direct children only
	})
	return out
}

// TestMembershipWriteVocabulary_MatchesTheRepository keeps the method list above
// honest. A repository method that writes a membership but is missing from
// membershipWriteMethods would make the guard above silently skip it.
func TestMembershipWriteVocabulary_MatchesTheRepository(t *testing.T) {
	_, file := parseAuthFile(t)

	// Every h.orgRepo.X(...) call in auth.go whose name looks like a membership
	// mutation must be classified — either as a write we guard, or knowingly
	// excluded below.
	notAMembershipRoleWrite := map[string]bool{
		"RemoveMember":                true, // deprovision: an authority DECREASE
		"RemoveAllMembershipsForUser": true, // deprovision
		"CheckMembership":             true, // read
		"GetDefaultOrganization":      true, // read
		"GetOrganizationByName":       true, // read
		"ListOrganizations":           true, // read
		"GetUserMemberships":          true, // read
		"GetUserCombinedScopes":       true, // read
		"GetByName":                   true, // read
	}

	var unclassified []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// Only calls on the organization repository.
		recv, ok := sel.X.(*ast.SelectorExpr)
		if !ok || recv.Sel.Name != "orgRepo" {
			return true
		}
		name := sel.Sel.Name
		if membershipWriteMethods[name] || notAMembershipRoleWrite[name] {
			return true
		}
		unclassified = append(unclassified, name)
		return true
	})

	if len(unclassified) > 0 {
		t.Errorf("unclassified orgRepo method(s) called in auth.go: %s. If one writes "+
			"a membership role, add it to membershipWriteMethods so the guard check "+
			"covers it; if it does not, add it to notAMembershipRoleWrite.",
			strings.Join(unclassified, ", "))
	}
}
