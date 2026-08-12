// goroutine_guard_test.go statically enforces the rule this package exists to serve: a
// goroutine started anywhere under backend/internal must recover its own panics.
//
// Go does not propagate a panic from a goroutine to whoever started it, and gin.Recovery()
// only guards the request goroutine. An unrecovered panic in any fire-and-forget goroutine
// or background job — a nil map in an audit payload, an edge case in a scheduled job — takes
// down the whole OS process and every tenant with it. safego.Go wraps that recover once, but
// nothing in the type system stops the next `go func(){...}()` from being written bare, which
// is exactly how the six long-lived background loops this guard was added alongside came to
// be unprotected. This test parses the whole internal tree and fails when it happens again.
package safego

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// internalTreeRoot is the directory walked by the guard: backend/internal, relative to this
// package's directory.
const internalTreeRoot = ".."

// Non-empty-universe floors. A guard that certifies an empty file set is worse than no guard,
// so the walk has to actually find the tree it claims to police.
const (
	minScannedFiles   = 100
	minSafegoCallSite = 20
)

// TestGoroutineGuard_EveryGoStatementRecovers fails when a `go` statement under
// backend/internal starts work that is not panic-guarded. There are exactly two shapes that
// pass, and no path-based exemption list — an exemption keyed on a filename becomes a
// standing permission for whatever else is later written into that file:
//
//   - `go func(){ defer func(){ recover() }(); ... }()` — the goroutine recovers inline. This
//     is what safego.Go itself does, and what a caller must do when it needs the recovered
//     panic to set a variable the caller reads (see services/storage_migration.go).
//   - anything else must be launched with safego.Go(...), which emits no `go` statement at
//     the call site and so is invisible to this walk.
func TestGoroutineGuard_EveryGoStatementRecovers(t *testing.T) {
	found := 0

	for _, pf := range parseInternalTree(t) {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			gostmt, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			found++

			lit, ok := gostmt.Call.Fun.(*ast.FuncLit)
			if !ok {
				t.Errorf("%s: `go %s(...)` starts a goroutine that cannot recover its own panic — "+
					"launch it with safego.Go(func() { ... }) so a panic is logged instead of "+
					"killing the process", pf.pos(gostmt), types.ExprString(gostmt.Call.Fun))
				return true
			}
			if !bodyDefersRecover(lit.Body) {
				t.Errorf("%s: `go func(){...}()` has no deferred recover() — use safego.Go, or "+
					"defer a recover() as the first thing the literal does if the caller needs "+
					"the recovered value", pf.pos(gostmt))
			}
			return true
		})
	}

	if found == 0 {
		t.Fatalf("found no `go` statements under %s — the guard is not seeing the tree it is "+
			"meant to police", internalTreeRoot)
	}
}

// TestGoroutineGuard_SafegoIsTheEstablishedRoute pins the other half of the rule: the guard
// above is only meaningful while safego.Go is what background work actually uses. If the
// helper fell out of use, every `go` statement could vanish from the tree and the guard would
// pass over a codebase that had simply moved its unguarded goroutines somewhere else.
func TestGoroutineGuard_SafegoIsTheEstablishedRoute(t *testing.T) {
	callSites := 0

	for _, pf := range parseInternalTree(t) {
		if strings.HasSuffix(filepath.ToSlash(pf.path), "safego/safego.go") {
			continue
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if types.ExprString(call.Fun) == "safego.Go" {
				callSites++
			}
			return true
		})
	}

	if callSites < minSafegoCallSite {
		t.Fatalf("found %d safego.Go call sites under %s, want at least %d — background work has "+
			"stopped routing through the panic-recovering launcher", callSites, internalTreeRoot, minSafegoCallSite)
	}
}

// bodyDefersRecover reports whether block defers a function that calls recover(). Only
// top-level defers in the goroutine body count: a recover() buried in a nested call runs on
// that call's stack frame, where it does not stop the goroutine's panic.
func bodyDefersRecover(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	for _, stmt := range block.List {
		deferred, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		if callsRecover(deferred.Call) {
			return true
		}
	}
	return false
}

// callsRecover reports whether call is `recover()` or a function literal containing one.
func callsRecover(call *ast.CallExpr) bool {
	if types.ExprString(call.Fun) == "recover" {
		return true
	}
	lit, ok := call.Fun.(*ast.FuncLit)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		inner, ok := n.(*ast.CallExpr)
		if ok && types.ExprString(inner.Fun) == "recover" {
			found = true
		}
		return !found
	})
	return found
}

type parsedFile struct {
	path string
	file *ast.File
	fset *token.FileSet
}

func (p parsedFile) pos(n ast.Node) string {
	return p.fset.Position(n.Pos()).String()
}

// parseInternalTree parses every non-test .go file under backend/internal.
func parseInternalTree(t *testing.T) []parsedFile {
	t.Helper()

	var out []parsedFile
	fset := token.NewFileSet()

	err := filepath.WalkDir(internalTreeRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		out = append(out, parsedFile{path: path, file: f, fset: fset})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", internalTreeRoot, err)
	}

	if len(out) < minScannedFiles {
		t.Fatalf("scanned %d files under %s, want at least %d — the guard is looking at the wrong tree",
			len(out), internalTreeRoot, minScannedFiles)
	}
	return out
}
