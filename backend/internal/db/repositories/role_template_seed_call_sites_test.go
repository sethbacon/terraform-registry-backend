package repositories

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// backendRoot is this package's distance to the module root.
const backendRoot = "../../.."

// seedFunctions are the two writes of the registry's role -> scope policy, and
// the reason issue #891 needed a guard rather than an edit.
//
// They target DIFFERENT TABLES and are called from DIFFERENT FILES:
//
//	SeedSystemRoleTemplates         -> registry_role_templates  (internal/api/router.go)
//	SeedSharedIdentityRoleTemplates -> role_templates           (cmd/server/main.go)
//
// The first is what this application authorizes against. The second is what the
// STATE MANAGER adopts every role name it does not define itself from, and what
// a rollback to the previous image reads. A policy correction applied to one of
// them leaves the other stating the old policy, on a table another application
// reads -- which is a fix that looks complete and is not.
var seedFunctions = map[string]string{
	"SeedSystemRoleTemplates":         "registry_role_templates",
	"SeedSharedIdentityRoleTemplates": "role_templates",
}

// policyFunc is the single source both seeds must be handed.
const policyFunc = "PredefinedRoleTemplates"

// TestEverySeedCallSiteUsesTheOnePolicyList walks the whole backend and requires
// that every call to either seed passes models.PredefinedRoleTemplates() as its
// templates argument.
//
// WHAT IT ACTUALLY PREVENTS. #891's fix is one edit to one Go list precisely
// BECAUSE both paths read that list. Nothing enforced that. A future change that
// hands one seed a filtered slice, a topology-specific list, or a second
// definition of "the system roles" would re-open the defect on one table only --
// and it would present, exactly as #891 did, as an application whose pages are
// empty for a role that ought to be able to see them, with no error anywhere.
//
// It also fails on an EMPTY universe. A source-walking guard that finds no call
// sites passes silently, which is the failure mode that makes such a guard worse
// than none: it certifies whatever it could not see.
func TestEverySeedCallSiteUsesTheOnePolicyList(t *testing.T) {
	root, err := filepath.Abs(backendRoot)
	if err != nil {
		t.Fatalf("resolve the backend root: %v", err)
	}

	type site struct {
		file string
		fn   string
		ok   bool
		arg  string
	}
	var sites []site

	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		// Production call sites only: a test may legitimately drive the seeds
		// with a hand-built slice, which is what makes them testable.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil // not this guard's business
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			name := calleeName(call.Fun)
			if _, watched := seedFunctions[name]; !watched {
				return true
			}
			s := site{file: rel, fn: name}
			if len(call.Args) >= 3 {
				s.arg = exprString(call.Args[2])
				s.ok = calleeName(underlyingCall(call.Args[2])) == policyFunc
			}
			sites = append(sites, s)
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking %s: %v", root, walkErr)
	}

	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.fn] = true
		if !s.ok {
			t.Errorf("%s calls %s with %q, not models.%s(). The registry's role -> scope "+
				"policy is one list, written to %s by this path and to the other table by "+
				"the other; a second definition re-opens issue #891 on whichever table it "+
				"reaches.", s.file, s.fn, s.arg, policyFunc, seedFunctions[s.fn])
		}
	}
	for _, fn := range sortedSeedNames(seedFunctions) {
		if !seen[fn] {
			t.Errorf("found no production call site for %s, which writes %s. Either the "+
				"seed was removed and this guard should go with it, or the walk is not "+
				"seeing the tree -- and a guard that sees nothing passes everything.",
				fn, seedFunctions[fn])
		}
	}
}

// calleeName is the identifier a call resolves to, through a package selector.
func calleeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

// underlyingCall unwraps `models.PredefinedRoleTemplates()` to its Fun.
func underlyingCall(e ast.Expr) ast.Expr {
	if c, ok := e.(*ast.CallExpr); ok {
		return c.Fun
	}
	return e
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.CallExpr:
		return exprString(v.Fun) + "()"
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.Ident:
		return v.Name
	}
	return "<expression>"
}

func sortedSeedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
