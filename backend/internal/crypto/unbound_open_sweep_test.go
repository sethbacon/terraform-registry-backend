package crypto_test

// unbound_open_sweep_test.go is the READ-side companion to
// unbound_seal_sweep_test.go.
//
// The write side has always been the visible half of the suite-identity #153
// adoption, and it is the half that fails loudly: a Seal that should have been a
// SealWithContext leaves the inventory count wrong and the sweep test says so.
//
// The read side has neither property. `Open` and `OpenWithContextOrLegacy`
// differ by an argument and a return value, so a converted column whose read is
// missed still COMPILES, still passes every test that only round-trips through
// the writer, and fails for the first real user whose credential was written
// after the conversion — by which point the change that caused it is several
// merges back. That has already happened once in this migration, on a column
// where the follow-up write simply errored and the handler returned success
// anyway.
//
// So the reads get the same treatment: an inventory that has to be edited when a
// column is converted, and that fails when a converted read quietly reverts.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unboundOpenSites maps a repo-relative file to how many TokenCipher.Open calls
// it still contains, with the column and why.
//
// Every entry here belongs to a column whose WRITE is also still unbound; the
// two inventories are converted together, per column, and shrink together. An
// entry that outlives its Seal counterpart is a bug: it means a column is being
// written bound and read without a context, which fails at runtime for exactly
// the rows the conversion just created.
var unboundOpenSites = map[string]int{
	// The SMTP password, read out of the notifications JSON config blob during
	// router construction. Was 2; the OIDC client secret alongside it is now
	// bound.
	"internal/api/router_startup.go": 1,

	// The SMTP password again, on the admin test-send path.
	"internal/api/admin/notifications.go": 1,
}

// isCipherOpen reports whether a call is <something cipher-ish>.Open(...).
//
// Matched on the receiver name for the same reason isCipherSeal is: this is a
// lint-style sweep, not type resolution. Naming the receiver is what keeps
// sql.Open, os.Open and zip entry Open() — all over this repo — out of the
// result without an exclusion list that would need maintaining.
func isCipherOpen(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Open" {
		return false
	}
	var recv string
	switch x := sel.X.(type) {
	case *ast.Ident:
		recv = x.Name
	case *ast.SelectorExpr:
		recv = x.Sel.Name
	default:
		return false
	}
	return strings.Contains(strings.ToLower(recv), "cipher")
}

func TestNoNewUnboundOpenSites(t *testing.T) {
	root := backendRoot(t)
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
			if call, ok := n.(*ast.CallExpr); ok && isCipherOpen(call) {
				found[rel]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for file, n := range found {
		want, listed := unboundOpenSites[file]
		if !listed {
			t.Errorf("%s has %d unbound Open call(s) and is not in unboundOpenSites.\n"+
				"Reading a bound column without its context does not fail the build — it fails at "+
				"runtime for a real user, on a credential only an operator can restore. Use "+
				"OpenWithContextOrLegacy with the column's context function, or add the file here "+
				"with the reason it is deferred.", file, n)
			continue
		}
		if n != want {
			t.Errorf("%s has %d unbound Open call(s), expected %d.\n"+
				"If a column was converted, lower the count (or remove the entry). If a read was "+
				"ADDED against a column that is already bound, it needs OpenWithContextOrLegacy.",
				file, n, want)
		}
	}

	for file, want := range unboundOpenSites {
		if _, ok := found[file]; !ok {
			t.Errorf("unboundOpenSites lists %s (expecting %d) but it has no unbound Open calls left. "+
				"Remove the entry — a stale inventory is worse than none.", file, want)
		}
	}
}
