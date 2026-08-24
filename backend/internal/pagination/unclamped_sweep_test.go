package pagination_test

// unclamped_sweep_test.go is the re-runnable signature for issue #900.
//
// clamp_sweep_test.go, next to this file, catches a clamp that resolves to the
// WRONG value. It cannot catch a page size that is never clamped AT ALL,
// because there is no `if` for it to match — and that is a strictly worse
// defect. `?limit=1000000` reached the database verbatim in three handlers.
//
// The two shapes it is blind to, both found in the estate while fixing #900:
//
//	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))   // no ceiling at all
//	// ...limit used directly
//
//	if parsed, err := strconv.Atoi(l); err == nil && parsed <= 100 {
//		limit = parsed                                          // over-max keeps the
//	}                                                           // default: #893 again,
//	                                                            // as an accept-guard
//
// The second is issue #893's own defect wearing different syntax, which is the
// more uncomfortable finding: the guard for #893 had been green over a live
// instance of #893 since the day it was written. A signature that matches one
// spelling of a defect certifies every other spelling.
//
// So this sweep does not match a shape. It asks a question that has the same
// answer in every spelling: does this function read a page-size parameter and
// then never pass anything through pagination.ClampPerPage? The helper has no
// `if` to get wrong and no branch to omit, so "went through the helper" is the
// property worth checking, and it is one grep from being re-run.
//
// Granularity is the enclosing top-level func: a read in one closure and a
// clamp in a sibling closure of the same function would pass. No such pair
// exists, and tightening it to per-closure scope would report the many
// handlers that legitimately resolve their window in a helper. That is a known
// edge, stated rather than papered over.
//
// EMPTY IS THE FINISH LINE for `unclamped`. readsAllowedUnclamped is not
// expected to empty out — each entry claims an unbounded read is safe there,
// and the claim has to survive review.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pageSizeParams are the query parameters that decide how many rows a request
// gets back. A new spelling is added here, not worked around at the call site.
var pageSizeParams = map[string]bool{
	"limit": true, "per_page": true, "perPage": true,
	"page_size": true, "pageSize": true, "count": true,
}

// readsAllowedUnclamped maps a repo-relative file to the number of page-size
// reads in it that are DELIBERATELY unbounded, with the reason.
//
// There are none. The entry set is empty because every read in the api tree
// resolves through ClampPerPage — not because the sweep cannot see any.
// TestPageSizeReadsAreClamped fails loudly if that ever becomes the reason.
var readsAllowedUnclamped = map[string]int{}

// paramsInUse are the page-size parameters the api tree is KNOWN to serve. Each
// is a positive control on the matcher, not documentation.
//
// The whole-sweep check that `readsSeen > 0` only catches TOTAL blindness: drop
// "limit" from pageSizeParams and the sweep still sees per_page and count, still
// reports zero unclamped reads, and still passes — while eleven handlers go
// unwatched. Verified: that mutation survived the first version of this test.
// A per-parameter floor is what makes losing one spelling visible.
var paramsInUse = []string{"limit", "per_page", "count"}

// readsPageSizeParam reports whether the call reads one of pageSizeParams
// FROM THE REQUEST. Matching the literal alone is not enough: `slog.Info(msg,
// "count", n)` names one too, and an early draft of this sweep reported it.
//
// A read is either a context method — c.Query("limit"),
// c.DefaultQuery("limit", "100") — or any call that takes both the gin context
// and the parameter name, which is what every helper in this repo looks like
// (queryInt(c, "per_page")). The second form is deliberately not a list of
// helper names: a new helper is caught the day it is written, whereas a name
// list would silently stop matching and look exactly like a clean tree.
func readsPageSizeParam(call *ast.CallExpr) (string, bool) {
	isPageSizeLit := func(e ast.Expr) (string, bool) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		name := strings.Trim(lit.Value, `"`)
		return name, pageSizeParams[name]
	}

	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		switch sel.Sel.Name {
		case "Query", "DefaultQuery", "GetQuery":
			if len(call.Args) == 0 {
				return "", false
			}
			return isPageSizeLit(call.Args[0])
		}
	}

	takesContext, param := false, ""
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && ident.Name == "c" {
			takesContext = true
		}
		if name, ok := isPageSizeLit(arg); ok {
			param = name
		}
	}
	return param, takesContext && param != ""
}

// hasCeiling reports whether a function bounds its page size ABOVE, by either
// of the two means this repo accepts.
//
// The second — a hand-written `if x > 1000 { x = 1000 }` — is accepted rather
// than rewritten because it is already correct, and because the companion
// sweep in clamp_sweep_test.go is what makes accepting it safe: that sweep
// fails any `if x > LIT` whose body assigns something OTHER than LIT. So an
// inline ceiling here has already been checked to resolve to the maximum.
// Together the two sweeps say: every page-size read is bounded above, and
// every bound resolves to the maximum rather than collapsing to the default.
//
// Converting those five to ClampPerPage would also change `?limit=0` from one
// row to the default, which is a behaviour change that belongs in its own
// change rather than smuggled into a fix for unbounded reads.
func hasCeiling(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if found {
			return false
		}
		if sel, ok := node.(*ast.SelectorExpr); ok && sel.Sel.Name == "ClampPerPage" {
			found = true
			return false
		}
		stmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		for _, cond := range disjuncts(stmt.Cond) {
			bin, ok := cond.(*ast.BinaryExpr)
			if !ok || bin.Op != token.GTR {
				continue
			}
			lit, ok := bin.Y.(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				continue
			}
			// The body must assign to the thing being compared, or the
			// comparison is a test that reports rather than bounds.
			for _, bodyStmt := range stmt.Body.List {
				assign, ok := bodyStmt.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 {
					continue
				}
				lhs, lok := assign.Lhs[0].(*ast.Ident)
				cmp, cok := bin.X.(*ast.Ident)
				if lok && cok && lhs.Name == cmp.Name {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func TestPageSizeReadsAreClamped(t *testing.T) {
	root := moduleRoot(t)
	unclamped := map[string]int{}
	readsSeen := 0
	seenByParam := map[string]int{}

	err := filepath.Walk(filepath.Join(root, "internal", "api"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			reads := false
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if name, isRead := readsPageSizeParam(call); isRead {
						reads = true
						seenByParam[name]++
						return false
					}
				}
				return true
			})
			if !reads {
				continue
			}
			readsSeen++
			if !hasCeiling(fn.Body) {
				unclamped[rel]++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// A sweep that can no longer find a single page-size read looks exactly
	// like a fully-clamped tree. Refuse to certify one — this is the positive
	// control, and it is the check that would have caught the #893 sweep's
	// blindness years earlier than fixing #900 did.
	if readsSeen == 0 {
		t.Fatal("the sweep found NO page-size reads at all in internal/api. That is not a " +
			"clamped tree, it is a blind matcher: readsPageSizeParam is no longer " +
			"recognising a parameter read. Fix the matcher before trusting this green.")
	}
	for _, param := range paramsInUse {
		if seenByParam[param] == 0 {
			t.Errorf("the sweep no longer finds ANY read of %q, a parameter this api is "+
				"known to serve. Either every handler using it was deleted — in which case "+
				"remove it from paramsInUse — or the matcher stopped recognising it and is "+
				"now certifying those handlers without looking at them.", param)
		}
	}

	for file, n := range unclamped {
		want, listed := readsAllowedUnclamped[file]
		if !listed {
			t.Errorf("%s has %d function(s) that read a page-size parameter without passing "+
				"anything through pagination.ClampPerPage.\n"+
				"That is issue #900: the caller's number reaches the query verbatim, so "+
				"?limit=1000000 asks the database for a million rows. Use "+
				"pagination.ClampPerPage(requested, default, max), or add the file to "+
				"readsAllowedUnclamped with the reason an unbounded read is safe there.", file, n)
			continue
		}
		if n != want {
			t.Errorf("%s has %d unclamped page-size read(s), expected %d.", file, n, want)
		}
	}

	for file, want := range readsAllowedUnclamped {
		if _, ok := unclamped[file]; !ok {
			t.Errorf("readsAllowedUnclamped lists %s (expecting %d) but every page-size read "+
				"in it is clamped now. Remove the entry — a stale exemption is an exemption "+
				"nobody re-justified.", file, want)
		}
	}
}
