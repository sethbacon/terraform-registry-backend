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
	"m.httpClient":   "appcreds.Minter's client, pinned to httpsafe.NewClient by TestEgressGuard_HTTPClientFieldsComeFromHTTPSafe",
}

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

// TestEgressGuard_HTTPClientFieldsComeFromHTTPSafe pins the one indirection the receiver
// allow-list depends on: appcreds.Minter holds its own *http.Client, so that field must only
// ever be built by httpsafe.NewClient. Without this, allowing "m.httpClient" above would
// permit any client at all to be smuggled in behind that name.
func TestEgressGuard_HTTPClientFieldsComeFromHTTPSafe(t *testing.T) {
	assignments := 0

	isHTTPSafeClient := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		return types.ExprString(call.Fun) == "httpsafe.NewClient"
	}

	for _, pf := range parseSCMTree(t) {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := node.Key.(*ast.Ident); ok && id.Name == "httpClient" {
					assignments++
					if !isHTTPSafeClient(node.Value) {
						t.Errorf("%s: httpClient is initialised from %s, not httpsafe.NewClient",
							pf.pos(node), types.ExprString(node.Value))
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "httpClient" || i >= len(node.Rhs) {
						continue
					}
					assignments++
					if !isHTTPSafeClient(node.Rhs[i]) {
						t.Errorf("%s: httpClient is assigned from %s, not httpsafe.NewClient",
							pf.pos(node), types.ExprString(node.Rhs[i]))
					}
				}
			}
			return true
		})
	}

	if assignments == 0 {
		t.Fatal("found no httpClient field initialisation — either appcreds stopped holding its " +
			"own client (drop the \"m.httpClient\" entry from allowedDoReceivers) or this guard " +
			"has stopped matching it")
	}
}
