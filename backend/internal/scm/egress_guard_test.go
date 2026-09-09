// egress_guard_test.go statically enforces that every outbound HTTP path in internal/scm
// still goes through the SSRF-safe egress client (internal/httpsafe).
//
// The connectors used to repeat the send/status/decode sequence at ~39 call sites, each
// carrying its own copy of `scm.HTTPClient.Do(req)`. Now that most of them delegate to the
// shared DoJSON/ExchangeOAuthForm helpers, nothing in the type system stops a new connector
// (or a future edit to an existing one) from reaching for http.DefaultClient or building a
// bare &http.Client{} instead — which would silently route that call around the
// resolve-and-pin private-range deny-list and the per-hop redirect re-validation. These
// tests parse the whole internal/scm tree and fail when that happens.
package scm

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

// scmTreeRoot is the directory walked by every guard below: internal/scm and its connector
// subpackages, relative to this package's directory.
const scmTreeRoot = "."

// Non-empty-universe floors. A guard that certifies an empty file set is worse than no
// guard, so the walk has to actually find the tree it claims to police.
const (
	minScannedFiles = 8
	minDoCallSites  = 5
)

// allowedDoReceivers maps every expression permitted to receive a .Do(...) call in
// internal/scm to the reason it is safe. Adding a connector that calls .Do on anything else
// fails TestEgressGuard_DoCallsUseTheSharedClient; the map is also checked in the other
// direction, so an entry that stops being used has to be deleted rather than left to rot
// into a standing permission for whatever later takes that name.
var allowedDoReceivers = map[string]string{
	"HTTPClient":     "package scm's own httpsafe-backed client (httpclient.go)",
	"scm.HTTPClient": "the shared httpsafe-backed client, called from a connector subpackage",
}

// NOTE: "m.httpClient" was removed when appcreds stopped performing its own
// token exchanges (suite-identity#301). The exchanges moved to the shared
// identity/appcreds package, so the .Do call is no longer in this tree at all
// and this allow-list must not keep a standing permission for a name nothing
// uses. The egress guarantee did not move with it -- see
// TestEgressGuard_SharedMinterIsBuiltWithAGuardedClient below, which pins the
// client this tree HANDS to that package.

// forbiddenExprs are net/http entry points that use the unguarded, timeout-less
// http.DefaultClient.
var forbiddenExprs = map[string]string{
	"http.DefaultClient": "http.DefaultClient has no timeout and no egress guard",
	"http.Get":           "http.Get uses http.DefaultClient",
	"http.Post":          "http.Post uses http.DefaultClient",
	"http.PostForm":      "http.PostForm uses http.DefaultClient",
	"http.Head":          "http.Head uses http.DefaultClient",
}

type parsedFile struct {
	path string
	file *ast.File
	fset *token.FileSet
}

// parseSCMTree parses every non-test .go file under internal/scm.
func parseSCMTree(t *testing.T) []parsedFile {
	t.Helper()

	var out []parsedFile
	fset := token.NewFileSet()

	err := filepath.WalkDir(scmTreeRoot, func(path string, d fs.DirEntry, err error) error {
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
		t.Fatalf("walking %s: %v", scmTreeRoot, err)
	}

	if len(out) < minScannedFiles {
		t.Fatalf("scanned %d files under %s, want at least %d — the guard is looking at the wrong tree",
			len(out), scmTreeRoot, minScannedFiles)
	}
	return out
}

func (p parsedFile) pos(n ast.Node) string {
	return p.fset.Position(n.Pos()).String()
}

// TestEgressGuard_NoUnguardedHTTPConstructs fails when any connector reaches for
// http.DefaultClient, one of net/http's package-level request helpers, or rolls its own
// http.Client / http.Transport instead of the httpsafe-backed client.
func TestEgressGuard_NoUnguardedHTTPConstructs(t *testing.T) {
	for _, pf := range parseSCMTree(t) {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if why, bad := forbiddenExprs[types.ExprString(node)]; bad {
					t.Errorf("%s: %s — route the request through scm.HTTPClient (%s)",
						pf.pos(node), types.ExprString(node), why)
				}
			case *ast.CompositeLit:
				switch types.ExprString(node.Type) {
				case "http.Client", "http.Transport":
					t.Errorf("%s: constructs a bare %s — build it with httpsafe.NewClient so the "+
						"egress guard applies", pf.pos(node), types.ExprString(node.Type))
				}
			case *ast.CallExpr:
				if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "new" && len(node.Args) == 1 {
					if types.ExprString(node.Args[0]) == "http.Client" {
						t.Errorf("%s: constructs a bare http.Client — build it with httpsafe.NewClient",
							pf.pos(node))
					}
				}
			}
			return true
		})
	}
}

// TestEgressGuard_DoCallsUseTheSharedClient fails when a .Do(...) call is made on anything
// other than a known httpsafe-backed client, and fails just as loudly when an entry in
// allowedDoReceivers no longer corresponds to any call site.
func TestEgressGuard_DoCallsUseTheSharedClient(t *testing.T) {
	seen := map[string]bool{}
	total := 0

	for _, pf := range parseSCMTree(t) {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Do" {
				return true
			}
			receiver := types.ExprString(sel.X)
			total++
			if _, allowed := allowedDoReceivers[receiver]; !allowed {
				t.Errorf("%s: %s.Do(...) does not use an httpsafe-backed client; send through "+
					"scm.HTTPClient (or scm.DoJSON / scm.ExchangeOAuthForm)", pf.pos(call), receiver)
				return true
			}
			seen[receiver] = true
			return true
		})
	}

	if total < minDoCallSites {
		t.Fatalf("found %d .Do(...) call sites under %s, want at least %d — the guard is not "+
			"seeing the connectors it is meant to police", total, scmTreeRoot, minDoCallSites)
	}
	for receiver := range allowedDoReceivers {
		if !seen[receiver] {
			t.Errorf("allowedDoReceivers still permits %q but nothing calls it any more — delete "+
				"the entry rather than leaving a standing exemption", receiver)
		}
	}
}

// TestEgressGuard_SharedMinterIsBuiltWithAGuardedClient pins the one
// indirection this tree's egress policy now depends on.
//
// appcreds no longer performs its own token exchanges: it hands credentials to
// terraform-suite-identity/identity/appcreds, which performs them with whatever
// *http.Client it was given (suite-identity#301). The shared package defaults to
// its OWN strict httpsafe policy, so an unguarded exchange is not possible by
// omission -- but this repository has its own httpsafe with its own allow-list
// plumbing, and the point of passing a client is to keep ONE egress policy in
// force rather than two that can disagree. If a future edit drops the option, or
// builds the client from anything but httpsafe.NewClient, the exchanges silently
// fall back to a policy this repository's operators never configured.
//
// This is deliberately a REPLACEMENT for the older
// TestEgressGuard_HTTPClientFieldsComeFromHTTPSafe, which pinned the
// appcreds.Minter.httpClient field that no longer exists. Deleting that guard
// without putting this in its place would have removed the coverage silently,
// which is the failure mode the whole file exists to prevent.
func TestEgressGuard_SharedMinterIsBuiltWithAGuardedClient(t *testing.T) {
	var (
		sharedNewCalls int
		newMinterCalls int
	)

	// containsGuardedClientOption reports whether a WithHTTPClient(httpsafe.NewClient(...))
	// appears anywhere inside e. The search is nested because the option list is
	// built with append(...), so the option is not a direct argument.
	var containsGuardedClientOption func(e ast.Expr) bool
	containsGuardedClientOption = func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || types.ExprString(call.Fun) != "sharedcreds.WithHTTPClient" || len(call.Args) != 1 {
				return true
			}
			// The argument may be the client expression itself or a parameter
			// carrying one; the parameter case is covered by the newMinter
			// check below, which pins what its callers may pass.
			found = true
			return false
		})
		return found
	}

	isHTTPSafeClient := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		return ok && types.ExprString(call.Fun) == "httpsafe.NewClient"
	}

	for _, pf := range parseSCMTree(t) {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch types.ExprString(call.Fun) {
			case "sharedcreds.New":
				// Every construction of the shared minter must carry a literal
				// WithHTTPClient. Without one it silently runs under the shared
				// package's own egress policy instead of this repository's.
				sharedNewCalls++
				if !containsGuardedClientOption(call) {
					t.Errorf("%s: sharedcreds.New is built without a literal "+
						"sharedcreds.WithHTTPClient option", pf.pos(call))
				}
			case "newMinter":
				// The client is newMinter's third parameter precisely so this is
				// checkable; passed as one option among many it would be
				// invisible here.
				newMinterCalls++
				if len(call.Args) < 3 || !isHTTPSafeClient(call.Args[2]) {
					got := "«missing»"
					if len(call.Args) >= 3 {
						got = types.ExprString(call.Args[2])
					}
					t.Errorf("%s: newMinter's client argument is %s, not httpsafe.NewClient(...)",
						pf.pos(call), got)
				}
			}
			return true
		})
	}

	// Non-vacuity, in both directions. If the constructor is renamed or the
	// package alias changes, every assertion above passes because nothing was
	// found.
	if sharedNewCalls == 0 {
		t.Fatal("found no sharedcreds.New call under " + scmTreeRoot + " — appcreds stopped " +
			"building a shared minter, or the package alias changed. Update this guard " +
			"deliberately rather than letting it pass vacuously.")
	}
	if newMinterCalls == 0 {
		t.Fatal("found no newMinter call under " + scmTreeRoot + " — the constructor was renamed " +
			"or inlined, and the client argument this guard pins no longer exists.")
	}
}
