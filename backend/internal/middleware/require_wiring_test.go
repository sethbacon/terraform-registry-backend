package middleware

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Issue #748: RequireOrgMembership and RequireOrgScope were exported guards,
// documented in this package's header as part of the enforcement model, and
// wired to zero routes. Worse, both read an "organization_id" context key that
// AuthMiddleware sets only for API-key principals, so wiring either would have
// 403'd every browser session. They sat beside a live guard, under the same
// naming convention, looking like a sanctioned option.
//
// Deleting them fixes the instance. This fixes the class: an exported Require*
// middleware that no route reaches is a claim about enforcement that nothing
// enforces, and it should have to be declared rather than accumulate quietly.

// unwiredByDesign lists exported Require* middlewares that intentionally have no
// caller, with the reason. Entries are checked in BOTH directions — an entry
// that has gained a caller, or that no longer names a real function, fails the
// test. A one-way allowlist rots into a list of names nobody has re-examined.
var unwiredByDesign = map[string]string{
	"RequireAnyScope": "General-purpose OR-combinator over the `scopes` context key. " +
		"Unlike the guards deleted in #748 it reads a key AuthMiddleware sets for " +
		"both JWT and API-key principals, so it is dead but sound — it would work " +
		"if a route wired it. Kept pending a decision on whether to wire or drop it.",
	"RequireAllScopes": "AND-combinator sibling of RequireAnyScope; same reasoning.",
}

var requireFuncRe = regexp.MustCompile(`(?m)^func (Require\w+)\(`)

// exportedRequireMiddlewares returns every Require* function declared in this
// package's non-test sources.
func exportedRequireMiddlewares(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		for _, m := range requireFuncRe.FindAllStringSubmatch(string(src), -1) {
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	return names
}

// callerCount counts non-test `middleware.<name>(` references under backend/.
func callerCount(t *testing.T, name string) int {
	t.Helper()
	needle := "middleware." + name + "("
	root := filepath.Join("..", "..") // backend/
	count := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable paths are not findings for this guard
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == "node_modules" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		count += strings.Count(string(src), needle)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return count
}

func TestEveryRequireMiddlewareIsWiredOrDeclaredUnwired(t *testing.T) {
	names := exportedRequireMiddlewares(t)

	// An empty universe would make every assertion below vacuous — the exact
	// failure mode this guard exists to prevent, reached through the guard.
	if len(names) == 0 {
		t.Fatal("found no Require* middlewares in this package; the scan is broken, " +
			"so this test is proving nothing")
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			callers := callerCount(t, name)
			reason, declared := unwiredByDesign[name]

			switch {
			case callers > 0 && declared:
				t.Errorf("%s is listed in unwiredByDesign but now has %d caller(s). "+
					"Remove the entry — a stale exemption hides the next unwired guard.\n"+
					"  recorded reason: %s", name, callers, reason)
			case callers == 0 && !declared:
				t.Errorf("%s is exported but no non-test code calls it. An unwired "+
					"Require* guard is a claim about enforcement that nothing enforces "+
					"(issue #748). Either wire it to the routes it protects, delete it, "+
					"or add it to unwiredByDesign with the reason it stays.", name)
			}
		})
	}
}

// TestUnwiredByDesignNamesRealFunctions is the other direction: an entry for a
// function that no longer exists is a note about nothing, and it makes the
// allowlist look maintained when it is not.
func TestUnwiredByDesignNamesRealFunctions(t *testing.T) {
	declared := exportedRequireMiddlewares(t)
	present := make(map[string]bool, len(declared))
	for _, n := range declared {
		present[n] = true
	}
	for name := range unwiredByDesign {
		if !present[name] {
			t.Errorf("unwiredByDesign names %q, which is not a Require* function in "+
				"this package any more. Remove the entry.", name)
		}
	}
}
