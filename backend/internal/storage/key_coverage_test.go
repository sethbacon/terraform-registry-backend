package storage_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Issue #752 — every backend method that takes a key must validate it.
//
// This is the guard against the real maintenance hazard of the fix: it is 6
// methods × 4 backends = 24 call sites, and a guarantee that holds in 23 of
// them is not a guarantee. Nothing about "S3 forgot Exists" is visible in a
// behavioural test of the other 23, and nobody re-reads four files to check.
//
// It is also the shape that catches the NEXT backend. A new implementation of
// storage.Storage lands with its methods unguarded exactly once.

// keyedMethods are the storage.Storage methods whose first string parameter is
// an object key. Derived from the interface below, not hand-maintained.
var keyedMethods = map[string]bool{
	"Upload":      true,
	"Download":    true,
	"Delete":      true,
	"GetURL":      true,
	"Exists":      true,
	"GetMetadata": true,
}

// TestStorageInterface_MethodListIsCurrent keeps keyedMethods honest. If a
// method is added to the interface and not classified here, the coverage check
// below would silently not require validation on it.
func TestStorageInterface_MethodListIsCurrent(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "storage.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse storage.go: %v", err)
	}

	// Methods on the Storage interface that take a `path string` parameter.
	found := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Storage" {
			return true
		}
		iface, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		for _, m := range iface.Methods.List {
			fn, ok := m.Type.(*ast.FuncType)
			if !ok || len(m.Names) == 0 {
				continue
			}
			for _, p := range fn.Params.List {
				id, ok := p.Type.(*ast.Ident)
				if !ok || id.Name != "string" {
					continue
				}
				for _, pn := range p.Names {
					if pn.Name == "path" || pn.Name == "key" {
						found[m.Names[0].Name] = true
					}
				}
			}
		}
		return false
	})

	if len(found) == 0 {
		t.Fatal("found no key-taking methods on the Storage interface — this guard " +
			"is not reading the interface, so the coverage check below is vacuous")
	}

	var missing, stale []string
	for name := range found {
		if !keyedMethods[name] {
			missing = append(missing, name)
		}
	}
	for name := range keyedMethods {
		if !found[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)

	if len(missing) > 0 {
		t.Errorf("Storage interface method(s) take a key but are not in keyedMethods: %s — "+
			"add them, or the backends are free to skip validation on them",
			strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("keyedMethods lists %s, which the Storage interface no longer declares — "+
			"drop the entries", strings.Join(stale, ", "))
	}
}

// TestAllBackendsValidateEveryKeyedMethod walks the backend packages and
// requires ValidateKey in the body of each keyed method.
func TestAllBackendsValidateEveryKeyedMethod(t *testing.T) {
	// os.ReadDir, not filepath.Glob("*/"): Go's Glob does not treat a trailing
	// separator as "directories only" and matches nothing, which the
	// empty-universe check below caught on the first run.
	dirents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var backends []string
	for _, d := range dirents {
		if d.IsDir() {
			backends = append(backends, d.Name())
		}
	}
	if len(backends) == 0 {
		t.Fatal("no backend subdirectories found — the walk is broken")
	}

	type site struct{ pkg, method string }
	var checked, unguarded []site

	for _, dir := range backends {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil || !keyedMethods[fn.Name.Name] {
					continue
				}
				s := site{pkg: dir, method: fn.Name.Name}
				checked = append(checked, s)

				var guarded bool
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ValidateKey" {
						guarded = true
					}
					return true
				})
				if !guarded {
					unguarded = append(unguarded, s)
				}
			}
		}
	}

	// The universe must not be empty: a rename of the backend layout would
	// otherwise make this pass while checking nothing.
	if len(checked) == 0 {
		t.Fatal("found no keyed backend methods — the guard is vacuous")
	}
	// 4 backends × 6 keyed methods.
	if len(checked) < len(keyedMethods)*2 {
		t.Fatalf("only found %d keyed backend methods across %d package(s); expected every "+
			"backend to implement all %d — the walk is missing packages",
			len(checked), len(backends), len(keyedMethods))
	}

	for _, s := range unguarded {
		t.Errorf("%s.%s does not call storage.ValidateKey. Every backend method that "+
			"takes an object key must validate it (issue #752) — a guarantee that "+
			"holds in 23 of 24 places is not a guarantee.", s.pkg, s.method)
	}
	t.Logf("checked %d keyed backend methods across %d packages", len(checked), len(backends))
}
