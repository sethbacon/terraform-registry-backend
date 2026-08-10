package crypto_test

// unbound_seal_sweep_test.go is a lint-style regression test for the
// suite-identity #153 adoption: TokenCipher.Seal produces a ciphertext with no
// binding to the row or column it belongs to, so a value sealed by it can be
// moved between rows (or between columns of one row) by anyone with database
// write access and GCM will authenticate the move.
//
// SealWithContext is the bound form. Converting every column is staged, because
// each needs its own context derivation and — for the columns that cannot
// self-convert — a backfill over live credentials.
//
// This test is the inventory of what has NOT been converted yet. It fails when:
//
//   - a Seal call appears in a file not listed below (a NEW unbound column, or
//     an old one that grew a call site), or
//   - a listed file's count changes without the expectation being updated
//     (which is what happens when a column IS converted).
//
// Both directions matter. The first stops the class quietly growing while the
// migration is in progress, which is exactly how this kind of effort stalls
// half-done. The second forces the inventory to stay honest: converting a
// column means editing this map, so the remaining work is always readable here
// rather than reconstructed by grep.
//
// A count rather than a line number on purpose — line numbers churn on every
// unrelated edit, and a stale allowlist is one people delete.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unboundSealSites maps a repo-relative file to how many TokenCipher.Seal calls
// it still contains, with the column and why it has not been converted yet.
//
// Converted so far: scm_provider_tokens.access_token (the app-token cache), the
// user OAuth access + refresh tokens across scm_oauth.go, scm_linking.go and
// scm_publisher.go, the four storage_config credential columns, and the
// scm_providers client secret + GitHub App private key. What remains is the rest
// of the operator-entered material, which needs a backfill per column before its
// reads can stop accepting the unbound form.
//
// Ordered by recoverability, which is the order the conversion follows: a column
// whose failure mode is "re-mint" is safe to convert first; one whose failure
// mode is "an operator re-enters the secret by hand" is converted last, with a
// verified backfill.
var unboundSealSites = map[string]int{
	// The LDAP bind password. IRREPLACEABLE, and deferred with the SMTP
	// password because it is the same shape: a field inside a JSON config blob
	// on the system_settings singleton, not a column of a row, so it has no row
	// axis to bind to and needs the blob-aware handling that column has been
	// waiting for.
	//
	// Was 6, then 2. Four were this file's half of the storage_config
	// credential columns — buildEncryptedStorageConfig writes the SAME four
	// columns as internal/api/admin/storage.go, so they had to convert
	// together: a column with one converted writer and one unconverted one
	// cannot be declared bound, and its backfill would be undone by the next
	// first-run save. The fifth was the OIDC client secret.
	"internal/api/setup/handlers.go": 1,

	// This service's own notification channel target is BOUND. The one Seal left
	// is deliberate and transient: ChannelRepository.Create uses
	// `INSERT ... RETURNING` and takes no caller-supplied id, so the row is
	// inserted with an unbound ciphertext and immediately re-sealed against its
	// own id. The value is unbound only between those two writes, and the
	// notifier reads both forms, so nothing is exposed by the gap.
	//
	// Kept in the inventory rather than exempted, so that if the re-seal is ever
	// removed the count still has to be justified by someone.
	"internal/api/admin/notification_channels.go": 1,

	// SMTP password.
	"internal/api/admin/notifications.go": 1,
}

// backendRoot walks up to the module root so the test is runnable from its own
// package directory.
func backendRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root (no go.mod found walking up)")
	return ""
}

// isCipherSeal reports whether a call is <something cipher-ish>.Seal(...).
//
// Matches on the receiver name rather than resolving types: this is a
// lint-style sweep, and a rename that defeated it would have to rename the
// cipher field itself, which is the kind of change that gets read carefully
// anyway. aead.Seal (the raw GCM primitive) lives in the identity module, not
// here, but is excluded explicitly so this stays correct if that ever changes.
func isCipherSeal(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Seal" {
		return false
	}
	var recv string
	switch x := sel.X.(type) {
	case *ast.Ident:
		recv = x.Name
	case *ast.SelectorExpr:
		recv = x.Sel.Name
	default:
		return false
	}
	if recv == "aead" {
		return false
	}
	return strings.Contains(strings.ToLower(recv), "cipher")
}

func TestNoNewUnboundSealSites(t *testing.T) {
	root := backendRoot(t)
	found := map[string]int{}

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
			return nil // unparseable files are not this test's business
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isCipherSeal(call) {
				found[rel]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for file, n := range found {
		want, listed := unboundSealSites[file]
		if !listed {
			t.Errorf("%s has %d unbound Seal call(s) and is not in unboundSealSites.\n"+
				"A new column sealed without a context can be moved between rows by anyone with "+
				"database write access. Use SealWithContext with a row-derived context (see "+
				"internal/scm/aad.go), or add the file here with the reason it is deferred.", file, n)
			continue
		}
		if n != want {
			t.Errorf("%s has %d unbound Seal call(s), expected %d.\n"+
				"If a column was converted, lower the count (or remove the entry) so the remaining "+
				"work stays readable. If a call site was ADDED, it needs SealWithContext instead.",
				file, n, want)
		}
	}

	for file, want := range unboundSealSites {
		if _, ok := found[file]; !ok {
			t.Errorf("unboundSealSites lists %s (expecting %d) but it has no unbound Seal calls left. "+
				"Remove the entry — a stale inventory is worse than none.", file, want)
		}
	}
}
