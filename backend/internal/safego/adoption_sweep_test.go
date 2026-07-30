package safego_test

// adoption_sweep_test.go is a lint-style regression test for issue #562
// ("internal/safego's panic-recovering goroutine launcher is adopted in only
// 7 files; numerous request-triggered fire-and-forget goroutines use raw `go
// func()` with no recovery"). It statically walks the request/webhook/admin
// packages swept to adopt safego.Go and fails if a new bare `go` statement is
// introduced there without either wrapping its function in safego.Go or
// having its own local `defer recover()` (e.g. a goroutine that must set an
// error variable on panic instead of just logging it — see
// internal/services/storage_migration.go's upload-pipe goroutine).
//
// This intentionally does NOT cover every goroutine in the codebase: several
// packages start long-lived background daemons once at process/component
// startup (cleanup tickers, file watchers, discovery pollers) rather than
// per request, which is a different — and separately tracked — concern than
// the "numerous request-triggered fire-and-forget goroutines" this finding
// describes.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sweptDirs are the packages containing request/webhook/admin-triggered
// fire-and-forget goroutines converted to safego.Go for issue #562. Adding a
// new raw `go` statement here should be caught by this test.
var sweptDirs = []string{
	"../api/admin",
	"../api/mirror",
	"../api/modules",
	"../api/providers",
	"../api/setup",
	"../api/terraform_binaries",
	"../mirror",
	"../services",
	"../jobs",
}

func TestNoUnrecoveredGoroutinesInSweptPackages(t *testing.T) {
	fset := token.NewFileSet()

	// Parsed per-file rather than with parser.ParseDir, which is deprecated as
	// of Go 1.25 (SA1019) for not honouring build tags. This sweep only needs
	// each non-test .go file's AST, so a plain directory read avoids both the
	// deprecation and a dependency on golang.org/x/tools/go/packages.
	for _, dir := range sweptDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("failed to read %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			filename := filepath.Join(dir, name)
			file, err := parser.ParseFile(fset, filename, nil, 0)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", filename, err)
			}
			{
				ast.Inspect(file, func(n ast.Node) bool {
					goStmt, ok := n.(*ast.GoStmt)
					if !ok {
						return true
					}
					if isSafegoGoCall(goStmt.Call) || hasLocalRecover(goStmt.Call) {
						return true
					}
					pos := fset.Position(goStmt.Pos())
					t.Errorf(
						"%s:%d: raw `go` statement without safego.Go or a local recover() — "+
							"wrap the function body in safego.Go(...) (see internal/safego), or "+
							"add a local `defer func() { recover() }()` if the goroutine must react "+
							"to the panic itself (e.g. set an error variable)",
						filepath.Base(filename), pos.Line,
					)
					return true
				})
			}
		}
	}
}

// isSafegoGoCall reports whether call is safego.Go(...).
func isSafegoGoCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkgIdent.Name == "safego" && sel.Sel.Name == "Go"
}

// hasLocalRecover reports whether call is a function literal invocation whose
// body contains its own `recover()` call, guarding against an unrecovered
// panic even without going through safego.Go.
func hasLocalRecover(call *ast.CallExpr) bool {
	lit, ok := call.Fun.(*ast.FuncLit)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		callExpr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := callExpr.Fun.(*ast.Ident); ok && ident.Name == "recover" {
			found = true
			return false
		}
		return true
	})
	return found
}
