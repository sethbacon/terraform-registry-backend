package middleware_test

// scope_publisher_class_test.go is the re-runnable signature for issue #876.
//
// The gin key "scopes" is what middleware.RequireScope reads, and the literal
// element "admin" in it is an unconditional grant-all wildcard that
// tenantscope.Resolve turns into cross-organization reach. So every place that
// writes that key is deciding who is a platform administrator.
//
// #874 brought three of the four credential classes under the platform_admins
// carrier: sessions resolve through Carrier.SessionScopes per request, API keys
// are stripped by platformadmin.KeyScopes and can never be elevated. It did not
// touch mTLS, which published a subject→scope mapping's slice verbatim — so an
// `admin` written into a config file produced a platform administrator with no
// grant record, no audit entry, and no revocation short of a restart, while the
// carrier's own documentation said it was the only source. Five of six
// publishers were governed and one was not, which is exactly the shape a
// per-site fix leaves behind.
//
// This test is what stops a seventh publisher arriving ungoverned. It does not
// check that the scopes are CORRECT — it checks that the value published was
// produced by something whose job is to answer the authority question, rather
// than read from a token, a config file, or a database row and forwarded.
//
// EMPTY IS NOT THE FINISH LINE HERE. Unlike a defect sweep, the expected state
// is a NON-EMPTY set of publishers, all governed. A run that finds no
// publishers at all means the matcher broke, not that the estate got tidy.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// governingFuncs answer "what authority does this principal actually have,
// right now?". Each either consults the carrier or removes `admin` outright.
//
// Adding a name here is a claim that it cannot return an unearned `admin`, and
// that claim has to survive review. It is deliberately a short list.
var governingFuncs = map[string]string{
	"SessionScopes":       "carrier lookup per request; strips `admin` on every return path, re-adds only on a live carrier row",
	"KeyScopes":           "strips `admin` unconditionally — an API key is never elevated",
	"platformAdminScopes": "middleware's wrapper over SessionScopes; returns stripped scopes even on error",
	"currentKeyScopes":    "re-derives a key's authority at its binding; bottoms out in KeyScopes",
	"resolveScopes":       "mTLS: carrier for a mapping that names a user, KeyScopes for one that does not (#876)",
}

// minimumPublishers is a floor, not a count. It exists so a broken matcher —
// a renamed key, a rotted walk — reports a failure instead of a clean tree.
const minimumPublishers = 5

type publisher struct {
	file string
	line int
	how  string
}

// governingCallIn reports the governing function called anywhere in n, if any.
func governingCallIn(n ast.Node) (string, bool) {
	found, why := "", false
	ast.Inspect(n, func(node ast.Node) bool {
		if why {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if _, ok := governingFuncs[name]; ok {
			found, why = name, true
			return false
		}
		return true
	})
	return found, why
}

// assignedFrom finds where ident was last assigned within fn and reports the
// governing call that produced it, if any.
func assignedFrom(fn ast.Node, ident string) (string, bool) {
	got, ok := "", false
	ast.Inspect(fn, func(node ast.Node) bool {
		assign, isAssign := node.(*ast.AssignStmt)
		if !isAssign {
			return true
		}
		for _, lhs := range assign.Lhs {
			id, isIdent := lhs.(*ast.Ident)
			if !isIdent || id.Name != ident {
				continue
			}
			for _, rhs := range assign.Rhs {
				if name, isGov := governingCallIn(rhs); isGov {
					got, ok = name, true
				}
			}
		}
		return true
	})
	return got, ok
}

func TestEveryScopePublisherIsGoverned(t *testing.T) {
	root := repoRootForScopeSweep(t)
	var governed, ungoverned []publisher

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
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall || len(call.Args) != 2 {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "Set" {
					return true
				}
				key, isLit := call.Args[0].(*ast.BasicLit)
				if !isLit || key.Kind != token.STRING || strings.Trim(key.Value, `"`) != "scopes" {
					return true
				}

				p := publisher{file: rel, line: fset.Position(call.Pos()).Line}

				// The value is a governing call written inline.
				if name, isGov := governingCallIn(call.Args[1]); isGov {
					p.how = name
					governed = append(governed, p)
					return true
				}
				// Or an identifier this function assigned from one.
				if id, isIdent := call.Args[1].(*ast.Ident); isIdent {
					if name, isGov := assignedFrom(fn.Body, id.Name); isGov {
						p.how = name + " (via " + id.Name + ")"
						governed = append(governed, p)
						return true
					}
				}
				ungoverned = append(ungoverned, p)
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	total := len(governed) + len(ungoverned)
	if total < minimumPublishers {
		t.Fatalf("found only %d publisher(s) of the \"scopes\" key, expected at least %d.\n"+
			"That is not a tidy estate, it is a blind matcher: the key was renamed, or the walk "+
			"stopped reaching the middleware. Fix this test before trusting its green.", total, minimumPublishers)
	}

	for _, p := range ungoverned {
		t.Errorf("%s:%d publishes the \"scopes\" gin key with a value no governing function produced.\n"+
			"That key is what RequireScope reads, and `admin` in it is a grant-all wildcard that "+
			"tenantscope turns into cross-organization reach — so this line decides who is a platform "+
			"administrator. Route the value through one of: %s.\n"+
			"This is issue #876: mTLS published a config file's slice verbatim while every other "+
			"credential class went through the carrier.", p.file, p.line, strings.Join(governingNames(), ", "))
	}

	for _, p := range governed {
		t.Logf("governed: %s:%d via %s", p.file, p.line, p.how)
	}
}

func governingNames() []string {
	names := make([]string, 0, len(governingFuncs))
	for n := range governingFuncs {
		names = append(names, n)
	}
	return names
}

func repoRootForScopeSweep(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root")
	return ""
}
