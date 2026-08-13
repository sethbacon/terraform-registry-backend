package repositories

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Issue #766 — the re-runnable signature for "a privileged mutation with no
// audit record".
//
// TestPlatformAdminRepository_Grant_NilIntentWriter and its Revoke twin prove
// the two accessors that exist today refuse to run unaudited. They cannot say
// anything about the third one somebody adds next year. This does: it fails the
// moment ANY function in this package writes to `platform_admins` without
// taking an AuditIntentWriter, including a helper nobody thought to write a
// behavioural test for.
//
// It is a source scan rather than a type assertion because the property is
// about the shape of the API, not about a value: "you cannot express this
// mutation without also expressing its audit record". Migration 000052's
// deferred constraint trigger is the runtime half of the same rule and holds
// for callers that never come through this package at all.
var carrierMutationSQL = regexp.MustCompile(`(?is)(insert\s+into|delete\s+from|update)\s+platform_admins`)

func TestCarrierMutationsRequireAnAuditIntentWriter(t *testing.T) {
	// filepath.Glob + ParseFile, matching migration_conn_leak_test.go's idiom,
	// rather than the deprecated parser.ParseDir.
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	var scanned, mutators int
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		scanned++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !bodyMutatesCarrier(fn.Body) {
				continue
			}
			mutators++
			if !takesAuditIntentWriter(fn) {
				t.Errorf("%s: %s writes to platform_admins but takes no repositories.AuditIntentWriter. "+
					"The highest privilege in the product must not be changeable without a record of the "+
					"change committing with it (issue #766, migration 000052).",
					fset.Position(fn.Pos()), funcName(fn))
			}
		}
	}

	// Guard the guard. A renamed table, a moved file or a changed SQL idiom
	// would otherwise make every assertion above vacuously true, and this test
	// would keep reporting green while protecting nothing.
	if scanned == 0 {
		t.Fatal("scanned no non-test sources — the guard is vacuous")
	}
	if mutators < 2 {
		t.Fatalf("found %d function(s) writing to platform_admins across %d source file(s); expected at "+
			"least the Grant and Revoke accessors. The scan is not looking at what it thinks it is.",
			mutators, scanned)
	}
}

// bodyMutatesCarrier reports whether any string literal in the body is a write
// against platform_admins.
func bodyMutatesCarrier(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			text = lit.Value
		}
		if carrierMutationSQL.MatchString(text) {
			found = true
			return false
		}
		return true
	})
	return found
}

// takesAuditIntentWriter reports whether fn declares an AuditIntentWriter
// parameter.
func takesAuditIntentWriter(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "AuditIntentWriter" {
			return true
		}
		if sel, ok := field.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "AuditIntentWriter" {
			return true
		}
	}
	return false
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) == 1 {
		return "(receiver)." + fn.Name.Name
	}
	return fn.Name.Name
}
