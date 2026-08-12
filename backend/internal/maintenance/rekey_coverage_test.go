package maintenance

// rekey_coverage_test.go is an inventory guard, in the same spirit as
// internal/crypto/unbound_{seal,open}_sweep_test.go, for the claim
// `rekey-secrets verify` makes.
//
// That claim is load-bearing and unusually expensive to get wrong: a zero exit
// is what tells an operator ENCRYPTION_KEY_PREVIOUS can be deleted, and deleting
// it while any secret is still sealed under it destroys that secret. The gate is
// therefore only as wide as the registry the sweep walks, and the registry is a
// hand-maintained list — so a new encrypted column added anywhere in this
// service silently narrows a gate that keeps reporting success.
//
// The inventory below is the fix: every AAD context function used by this
// service must be declared either as swept by a registered column or as
// deliberately not swept, with a reason. Adding an encrypted column means
// editing this file, and editing this file is where someone decides whether
// dropping the previous key can still be called safe.
//
// It is checked in BOTH directions, because a one-way check rots. A listed
// function that no longer exists fails, a registered column no entry claims
// fails, and an entry claiming a column the registry does not have fails.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sweptAADContexts maps an AAD context function to the registered column whose
// rows RekeySecrets re-encrypts through it. One entry per column.
var sweptAADContexts = map[string]string{
	"TargetContext":                          "notification_channels.encrypted_target",
	"StorageConfigAzureAccountKeyContext":    "storage_config.azure_account_key_encrypted",
	"StorageConfigS3AccessKeyIDContext":      "storage_config.s3_access_key_id_encrypted",
	"StorageConfigS3SecretAccessKeyContext":  "storage_config.s3_secret_access_key_encrypted",
	"StorageConfigGCSCredentialsJSONContext": "storage_config.gcs_credentials_json_encrypted",
	"OIDCConfigClientSecretContext":          "oidc_config.client_secret_encrypted",
	"ProviderClientSecretContext":            "scm_providers.client_secret_encrypted",
	"ProviderAppPrivateKeyContext":           "scm_providers.encrypted_app_private_key",
	"SystemSettingsSMTPPasswordContext":      "system_settings.notifications_config:smtp.smtp_password_encrypted",
	"SystemSettingsLDAPBindPasswordContext":  "system_settings.ldap_config:bind_password_enc",
}

// unsweptAADContexts are the encrypted columns no sweep touches, and why.
//
// These are NOT covered by the rekey gate. Both tables hold credentials that the
// service can obtain again without an administrator: the shared app token is a
// cache with an expiry that is re-minted, and a user OAuth token is restored by
// that user re-linking their account. That is a real difference in blast radius
// from an OIDC client secret or a cloud storage key, which only a human can
// re-enter — but it is not "nothing", and docs/secrets-rotation.md says so
// rather than letting the gate imply a coverage it does not have.
//
// They are also not reachable from the registry as it stands: column.context
// takes one row-id string, and both scm_oauth_tokens contexts are derived from
// a user id AND a provider id (see internal/scm/aad.go). Widening the registry
// to carry composite keys is a change to the binding sweep as much as to this
// one, and belongs to its own issue rather than being smuggled in behind a
// rotation fix.
var unsweptAADContexts = map[string]string{
	"ProviderTokenContext": "scm_provider_tokens.access_token_encrypted is a cache with an expiry; " +
		"entries are re-minted from the identity provider, so the table converts itself",
	"UserTokenContext": "scm_oauth_tokens.access_token_encrypted is keyed by user AND provider, " +
		"which the single-row-id registry cannot express; a lost token is restored by the user re-linking",
	"UserRefreshTokenContext": "scm_oauth_tokens.refresh_token_encrypted, as above",
}

// findAADContextFuncs returns every exported *Context function this service
// passes as the additional-authenticated-data argument of a seal or open.
//
// Matched on the argument position of a *WithContext* call rather than on where
// the function is declared: what matters is that a ciphertext somewhere is bound
// by it, not which package it lives in. The bare name "Context" is excluded —
// that is ctx plumbing, not an AAD.
func findAADContextFuncs(t *testing.T) map[string]string {
	t.Helper()
	root := moduleRoot(t)
	found := map[string]string{}

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
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !strings.Contains(sel.Sel.Name, "WithContext") {
				return true
			}
			for _, arg := range call.Args {
				inner, ok := arg.(*ast.CallExpr)
				if !ok {
					continue
				}
				var name string
				switch fn := inner.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if name == "Context" || !strings.HasSuffix(name, "Context") {
					continue
				}
				if r := name[0]; r < 'A' || r > 'Z' {
					continue // col.context(...), not an exported AAD derivation
				}
				if _, seen := found[name]; !seen {
					found[name] = rel
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return found
}

func TestRekeyCoverage_EveryAADContextIsDeclaredSweptOrNot(t *testing.T) {
	found := findAADContextFuncs(t)
	if len(found) == 0 {
		t.Fatal("the scan found no AAD context functions at all; it has stopped matching " +
			"and would certify any registry as complete")
	}

	for name, where := range found {
		_, swept := sweptAADContexts[name]
		_, unswept := unsweptAADContexts[name]
		switch {
		case swept && unswept:
			t.Errorf("%s is listed as both swept and unswept", name)
		case !swept && !unswept:
			t.Errorf("%s binds a secret (first seen in %s) and is in neither inventory.\n"+
				"Either register a column for it in bindsecrets.go and add it to sweptAADContexts, "+
				"or add it to unsweptAADContexts with why a rotation does not need to reach it — "+
				"and say so in docs/secrets-rotation.md, because `rekey-secrets verify` returning "+
				"zero is what an operator deletes ENCRYPTION_KEY_PREVIOUS on.", name, where)
		}
	}

	for name := range sweptAADContexts {
		if _, ok := found[name]; !ok {
			t.Errorf("sweptAADContexts lists %s but nothing seals with it any more. "+
				"Remove the entry — a stale inventory is worse than none.", name)
		}
	}
	for name := range unsweptAADContexts {
		if _, ok := found[name]; !ok {
			t.Errorf("unsweptAADContexts lists %s but nothing seals with it any more. "+
				"Remove the entry — a stale inventory is worse than none.", name)
		}
	}
}

// The other direction: the swept inventory and the registry must describe the
// same set of columns. Without this, a column could be dropped from the registry
// — narrowing the gate — while the inventory above still claimed it was covered.
func TestRekeyCoverage_SweptInventoryMatchesTheRegistry(t *testing.T) {
	registered := map[string]bool{}
	for _, col := range columns {
		registered[col.name] = true
	}

	claimed := map[string]string{}
	for fn, colName := range sweptAADContexts {
		if !registered[colName] {
			t.Errorf("sweptAADContexts says %s covers %q, which is not a registered column", fn, colName)
			continue
		}
		if other, dup := claimed[colName]; dup {
			t.Errorf("%s and %s both claim to cover %q; one column, one entry", other, fn, colName)
			continue
		}
		claimed[colName] = fn
	}

	for _, col := range columns {
		if _, ok := claimed[col.name]; !ok {
			t.Errorf("column %q is registered but no sweptAADContexts entry claims it.\n"+
				"Every registered column is re-encrypted by RekeySecrets, so it belongs in the "+
				"inventory the rotation gate's scope is read from.", col.name)
		}
	}
}

// moduleRoot walks up to the module root so the test runs from its own package
// directory.
func moduleRoot(t *testing.T) string {
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
