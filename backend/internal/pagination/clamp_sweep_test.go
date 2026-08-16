package pagination_test

// clamp_sweep_test.go is the re-runnable signature for issue #893's defect
// class, and the reason this package exists rather than nine corrected
// one-liners.
//
// The defect is a range guard whose OVER-MAXIMUM branch collapses to the
// endpoint's default:
//
//	if perPage < 1 || perPage > 100 {
//		perPage = 20          // <- 200 requested, 20 served
//	}
//
// It is invisible in review — it reads as an ordinary two-sided bounds check —
// it fails silently with a 200 and a well-formed body, and it had been
// copy-pasted into nine sites before anyone noticed the one that mattered. A
// list of the nine would have been obsolete at the tenth, so this walks the
// source for the SHAPE instead, and fails when it reappears.
//
// What it matches: an `if` whose condition contains `X > LIT` and whose body is
// exactly `X = OTHER`, where OTHER is not LIT. That is "over the maximum, take
// something other than the maximum", which is always either this bug or a
// deliberate decision worth writing down in clampsAllowedToCollapse below.
//
// What it deliberately does not match, so the signature stays crisp rather than
// noisy:
//   - `if x > max { x = max }` — the correct clamp, and the shape every fixed
//     site now has (via ClampPerPage, which has no such `if` at all).
//   - `if x < 1 || x > max { return error }` — validation, not clamping; the
//     body assigns nothing. Config port checks live here.
//   - `>=` comparisons. The honest replacement for `x >= n` is `n-1`, which
//     cannot be recognised textually, and the estate has no instance of it.
//     A future clamp written with `>=` would slip past: that is a known edge of
//     this signature, not an oversight.
//
// EMPTY IS THE FINISH LINE for `found`, but clampsAllowedToCollapse is not
// expected to empty out — each entry there is a claim that collapsing to the
// default is right for that call site, and the claim has to survive review.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clampsAllowedToCollapse maps a repo-relative file to how many
// collapse-to-default clamps in it are DELIBERATE, with the reason.
//
// Both entries are SCM connectors normalising a page size for an upstream API,
// and both are exempt for the same verifiable reason: no user input reaches
// them. Every production construction of scm.Pagination in this module is
// scm.DefaultPagination() —
//
//	grep -rn 'Pagination{' --include='*.go' internal/ | grep -v _test
//
// returns exactly one hit, DefaultPagination's own literal — so PageSize is
// always 30 and the over-maximum branch is unreachable. There is no caller that
// can ask for more and be given less, which is the whole defect. Falling back
// to each API's documented default (GitHub/GitLab 30, Bitbucket 25) rather than
// to its maximum is the better behaviour for a client that has expressed no
// preference at all.
//
// If either connector ever takes a caller-supplied page size, it leaves this
// map and goes through ClampPerPage.
var clampsAllowedToCollapse = map[string]int{
	"internal/scm/connector.go":           1, // ClampPagination — GitHub/GitLab, 1..100 else 30
	"internal/scm/bitbucket/connector.go": 1, // clampWindow — Bitbucket DC, 1..100 else 25
}

// collapsingClamp reports whether an if-statement is the defect shape, i.e.
// `if ... X > LIT ... { X = OTHER }` with OTHER != LIT.
func collapsingClamp(stmt *ast.IfStmt) bool {
	if stmt.Else != nil || stmt.Body == nil || len(stmt.Body.List) != 1 {
		return false
	}
	assign, ok := stmt.Body.List[0].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return false
	}
	// `=` and `:=` both count; a clamp written either way is the same defect.
	target := types.ExprString(assign.Lhs[0])
	replacement := types.ExprString(assign.Rhs[0])

	for _, disjunct := range disjuncts(stmt.Cond) {
		cmp, ok := disjunct.(*ast.BinaryExpr)
		if !ok || cmp.Op != token.GTR {
			continue
		}
		if types.ExprString(cmp.X) != target {
			continue
		}
		if types.ExprString(cmp.Y) != replacement {
			return true
		}
	}
	return false
}

// disjuncts flattens a `||` tree into its operands, so that the over-maximum
// comparison is found whether it is written first, last, or behind an
// `err != nil` guard.
func disjuncts(expr ast.Expr) []ast.Expr {
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.LOR {
		return append(disjuncts(bin.X), disjuncts(bin.Y)...)
	}
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return disjuncts(paren.X)
	}
	return []ast.Expr{expr}
}

func TestNoClampsCollapseToTheDefault(t *testing.T) {
	root := moduleRoot(t)
	found := map[string]int{}

	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(n ast.Node) bool {
			if stmt, ok := n.(*ast.IfStmt); ok && collapsingClamp(stmt) {
				found[rel]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// A signature that can no longer see anything looks exactly like a clean
	// tree. Refuse to certify one: the exempt sites below are the sweep's own
	// positive control, and their disappearance means the matcher broke, not
	// that the estate got tidy.
	if len(found) == 0 {
		t.Error("the sweep found no collapse-to-default clamps AT ALL, including the two " +
			"deliberate ones in clampsAllowedToCollapse. That is not a clean tree, it is a " +
			"blind matcher: collapsingClamp is no longer recognising the shape it exists to " +
			"recognise. Fix the matcher before trusting this test's green.")
	}

	for file, n := range found {
		want, listed := clampsAllowedToCollapse[file]
		if !listed {
			t.Errorf("%s has %d clamp(s) that collapse to the default instead of the maximum.\n"+
				"That is issue #893: a caller asking for more than the maximum is served the "+
				"DEFAULT, so asking for more returns less — silently, with a 200. Use "+
				"pagination.ClampPerPage(requested, default, max), or add the file to "+
				"clampsAllowedToCollapse with the reason no caller can trigger it.", file, n)
			continue
		}
		if n != want {
			t.Errorf("%s has %d collapse-to-default clamp(s), expected %d.\n"+
				"A NEW one needs pagination.ClampPerPage. A REMOVED one means the count here "+
				"should come down.", file, n, want)
		}
	}

	for file, want := range clampsAllowedToCollapse {
		if _, ok := found[file]; !ok {
			t.Errorf("clampsAllowedToCollapse lists %s (expecting %d) but it has no "+
				"collapse-to-default clamps left. Remove the entry — a stale exemption is an "+
				"exemption nobody re-justified.", file, want)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root (no go.mod found walking up)")
	return ""
}
