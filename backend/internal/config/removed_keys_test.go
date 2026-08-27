package config

// removed_keys_test.go keeps multi_tenancy.* deleted, and keeps the operator
// warning honest (#976).
//
// WHY A GUARD FOR A DELETION. The flag looked exactly like the multi-tenancy
// switch, which is why it existed and why someone will reach for that name
// again. Both of its positions were wrong: false applied no organization
// predicate to search, and true filtered to the organization literally named
// "default" -- never the caller's -- so every real tenant saw an EMPTY REGISTRY
// while the default organization's inventory stayed visible to everyone.
// Re-adding a key by that name is far more likely than re-adding the specific
// broken code behind it, and a name that implies isolation is the part that
// misleads.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// minScannedGoFiles is the floor for the walk below. The tree held ~630 Go
// files when this was written; the floor is set well under that so ordinary
// growth and pruning do not trip it, and well over zero so a broken walk does.
const minScannedGoFiles = 200

func TestMultiTenancyKeysStayRemoved(t *testing.T) {
	root := ".."
	var offenders []string

	scanned := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// NEVER SKIP THE ROOT. filepath.Walk calls this with path == root
			// first, and root here is "..", whose Name() is ".." -- which the
			// hidden-directory test below matches. The first version of this
			// guard skipped the root and walked ZERO files, passing while
			// looking at nothing. It was caught by mutation: planting a
			// reference in modules/search.go did not fail it, and neither did
			// the real reference already sitting in that file's comment.
			if path != root {
				if info.Name() == "vendor" || info.Name() == "node_modules" || strings.HasPrefix(info.Name(), ".") {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// These two name the keys in code on purpose: config.go carries the
		// warning list, and this file asserts against it.
		if filepath.Base(path) == "removed_keys_test.go" || filepath.Base(path) == "config.go" {
			return nil
		}
		scanned++
		// PARSED, NOT GREPPED. A textual match also fires on the comments that
		// explain the removal -- in search.go, in the identity-wiring list, and
		// in this file -- and a guard that flags the documentation of a fix is
		// one that gets deleted or blanket-suppressed. What must not come back
		// is CODE that reads the flag: an identifier or a config key string.
		// parser.ParseFile without ParseComments drops comments entirely, so
		// prose is free and references are not.
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// A file this package cannot parse is not evidence of anything;
			// the compiler will object long before this test does.
			return nil //nolint:nilerr // parse failures are the compiler's business
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				if v.Name == "MultiTenancy" || v.Name == "MultiTenancyConfig" {
					offenders = append(offenders, path)
				}
			case *ast.BasicLit:
				if v.Kind == token.STRING && strings.Contains(v.Value, "multi_tenancy") {
					offenders = append(offenders, path)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// The empty-universe guard, and the reason this test is trustworthy at all:
	// "no offenders" and "looked at nothing" are the same green.
	if scanned < minScannedGoFiles {
		t.Fatalf("scanned only %d Go files (floor %d): the walk is not reaching the tree, so this "+
			"test passes without examining anything", scanned, minScannedGoFiles)
	}

	sort.Strings(offenders)
	for _, p := range offenders {
		t.Errorf("%s references multi_tenancy, which #976 removed.\n"+
			"If you need per-tenant isolation, it is carried by the HOST -- see the estate tenancy "+
			"model. A search filter named after multi-tenancy is what made the original flag "+
			"dangerous: it looked like the isolation switch and was not one.", p)
	}
}

// TestRemovedKeysAreOnlyDeclaredInConfig stops the warning list itself from
// becoming the thing that reintroduces the keys.
func TestRemovedKeysAreOnlyDeclaredInConfig(t *testing.T) {
	if len(removedMultiTenancyKeys) == 0 {
		t.Fatal("removedMultiTenancyKeys is empty, so an operator who still sets these keys is told " +
			"nothing and their registry silently changes shape on upgrade")
	}
	for k, why := range removedMultiTenancyKeys {
		if !strings.HasPrefix(k, "multi_tenancy.") {
			t.Errorf("removedMultiTenancyKeys has %q, which is not a multi_tenancy key", k)
		}
		if why == "" {
			t.Errorf("%q is warned about with no reason; a warning an operator cannot act on gets ignored", k)
		}
	}
}

// TestSuppliedRemovedKeyWarns is the behavioural half.
//
// The condition that matters is "the operator SUPPLIED it", not "it has a
// value" -- which is why the defaults for these keys were deleted rather than
// left in place. A SetDefault would make viper.IsSet true on every boot and
// turn this warning into noise that everyone learns to skip.
func TestSuppliedRemovedKeyWarns(t *testing.T) {
	for key := range removedMultiTenancyKeys {
		t.Run(key, func(t *testing.T) {
			v := viper.New()
			setDefaults(v)
			if v.IsSet(key) {
				t.Fatalf("%s still has a default, so IsSet is true for every deployment and the "+
					"warning fires whether or not the operator set anything", key)
			}
			v.Set(key, "whatever")
			if !v.IsSet(key) {
				t.Errorf("%s was supplied but IsSet is false, so the operator would be told nothing", key)
			}
		})
	}
}
