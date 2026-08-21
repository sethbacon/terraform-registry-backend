package api

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

// Issue #739 — every consumer of identity data must be constructed on
// identityDB, not the domain connection.
//
// identityDB resolves users / organizations / organization_members against the
// configured identity schema when TFR_IDENTITY_SCHEMA_ENABLED is set, and
// equals db otherwise. A handler holding db therefore reads and writes a
// DIFFERENT set of tables than AuthMiddleware and the org-scope middleware do,
// but only under the cutover — so this is invisible in a default deployment and
// in every test that does not enable it.
//
// scim.NewHandlers was handed d.db. It builds its own UserRepository and
// OrganizationRepository over whatever connection it receives, so under the
// cutover SCIM-created users did not exist for login and — the
// security-relevant direction — RemoveAllMembershipsForUser on deactivation
// deleted rows in public.organization_members while authorization kept reading
// the identity schema. IdP-driven offboarding returned 204 with the user's
// access entirely intact.
//
// admin.NewDevHandlers had the same shape and is fixed with it.
//
// A behavioural test cannot see this: it is a wiring mistake that only diverges
// when two schemas exist, so the check has to be structural.

// identityRepoConstructors are the repository constructors that resolve
// identity tables. A function that calls one of these on a *sql.DB parameter is
// an identity consumer, whatever it is named.
var identityRepoConstructors = map[string]bool{
	"NewUserRepository":         true,
	"NewOrganizationRepository": true,
	"NewAPIKeyRepository":       true,
	"NewTokenRepository":        true,
	"NewAuditRepository":        true,
}

// identityBackedArgs are the expressions that carry an identity-backed
// connection.
var identityBackedArgs = map[string]bool{
	"identityDB":     true,
	"d.identityDB":   true,
	"identitySqlxDB": true,
	"d.identitySqlx": true,
}

// mustUseIdentityDB are the constructors whose identity data IS the product:
// they create, modify or deprovision users, memberships, API keys and audit
// records, and authentication/authorization reads what they write. If one of
// these is handed the domain connection, it operates on a different set of
// tables than AuthMiddleware does the moment the identity schema is enabled.
var mustUseIdentityDB = map[string]string{
	"scim.NewHandlers":              "provisions and deprovisions users and memberships (issue #739)",
	"admin.NewDevHandlers":          "creates users and switches sessions",
	"admin.NewAuthHandlers":         "login, group-mapping reconciliation, membership writes",
	"admin.NewAPIKeyHandlers":       "issues and revokes credentials",
	"admin.NewUserHandlers":         "user lifecycle",
	"admin.NewOrganizationHandlers": "organization and membership lifecycle",
	"admin.NewAuditLogHandlers":     "reads the audit trail",
}

// domainDBIsCorrect are the constructors that legitimately take the domain
// connection even though they build an organization repository.
//
// They resolve a namespace to an organization as part of a query over DOMAIN
// tables — modules, providers, versions — and join across the two. Handing them
// identityDB would split a single join across two connections, which is a
// different bug from the one #739 describes. Their org lookups are reads used
// for namespace ownership, not the identity records that authentication
// consumes.
//
// This list is not a blessing; it is a record that each was considered.
var domainDBIsCorrect = map[string]string{
	"admin.GetModuleScanHandler":     "scan records joined to modules",
	"admin.NewModuleAdminHandlers":   "module administration over domain tables",
	"admin.NewProviderAdminHandlers": "provider administration over domain tables",
	"mirror.IndexHandler":            "mirror index over domain tables",
	"mirror.PlatformIndexHandler":    "mirror index over domain tables",
	"modules.SearchHandler":          "namespace -> org resolution joined to modules",
	"modules.ServeFileHandler":       "namespace -> org resolution joined to modules",
	"modules.UploadHandler":          "namespace -> org resolution joined to modules",
	"oci.NewHandler":                 "OCI blobs joined to modules",
	"providers.DownloadHandler":      "namespace -> org resolution joined to providers",
	"providers.ListVersionsHandler":  "namespace -> org resolution joined to providers",
	"providers.SearchHandler":        "namespace -> org resolution joined to providers",
	"providers.UploadHandler":        "namespace -> org resolution joined to providers",
	"..NewRouter":                    "the router itself; it receives both connections",
}

func parseGoFile(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, f
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	}
	return ""
}

// discoverIdentityConsumers walks internal/api/** and returns the names of
// exported constructors that build an identity repository from a *sql.DB
// parameter.
//
// Derived from the source rather than hand-listed: a hand-list is exactly how
// scim.NewHandlers stayed wrong while every other identity consumer was
// correct.
func discoverIdentityConsumers(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}

	root := "."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		_, file := parseGoFile(t, path)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			// Parameter names of type *sql.DB.
			dbParams := map[string]bool{}
			for _, p := range fn.Type.Params.List {
				star, ok := p.Type.(*ast.StarExpr)
				if !ok || exprString(star.X) != "sql.DB" {
					continue
				}
				for _, n := range p.Names {
					dbParams[n.Name] = true
				}
			}
			if len(dbParams) == 0 {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !identityRepoConstructors[sel.Sel.Name] {
					return true
				}
				for _, arg := range call.Args {
					if id, ok := arg.(*ast.Ident); ok && dbParams[id.Name] {
						found[filepath.Base(filepath.Dir(path))+"."+fn.Name.Name] = path
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return found
}

func TestIdentityConsumers_AreClassifiedAndCorrectlyWired(t *testing.T) {
	consumers := discoverIdentityConsumers(t)
	if len(consumers) == 0 {
		t.Fatal("discovered no identity-consuming constructors under internal/api — " +
			"the discovery walk is broken, so this guard is vacuous")
	}

	// 1. Every discovered consumer must be classified. This is the half that
	//    catches the NEXT one: a new constructor that builds identity
	//    repositories forces a decision instead of silently defaulting to
	//    whatever connection was nearest at the call site, which is how
	//    scim.NewHandlers stayed wrong while every sibling was right.
	var unclassified []string
	for name := range consumers {
		if mustUseIdentityDB[name] == "" && domainDBIsCorrect[name] == "" {
			unclassified = append(unclassified, name)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("unclassified identity-consuming constructor(s): %s\n"+
			"Each builds an identity repository from a *sql.DB parameter. Decide "+
			"which connection is correct and add it to mustUseIdentityDB (with the "+
			"identity data it owns) or domainDBIsCorrect (with why the domain "+
			"connection is right).", strings.Join(unclassified, ", "))
	}

	// 2. Stale entries. An allowlist nobody re-examines is how a fix rots.
	for name := range mustUseIdentityDB {
		if consumers[name] == "" {
			t.Errorf("mustUseIdentityDB lists %q, which no longer builds an identity "+
				"repository from a *sql.DB parameter — drop the entry", name)
		}
	}
	for name := range domainDBIsCorrect {
		if consumers[name] == "" {
			t.Errorf("domainDBIsCorrect lists %q, which no longer builds an identity "+
				"repository from a *sql.DB parameter — drop the entry", name)
		}
	}

	// 3. The must-use set has to actually receive an identity connection.
	var checked int
	for _, wiring := range []string{"router.go", "router_routes.go"} {
		fset, file := parseGoFile(t, wiring)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			key := exprString(sel.X) + "." + sel.Sel.Name
			owns := mustUseIdentityDB[key]
			if owns == "" {
				return true
			}
			checked++

			var sawIdentity bool
			for _, arg := range call.Args {
				s := exprString(arg)
				if identityBackedArgs[s] {
					sawIdentity = true
				}
				if s == "db" || s == "d.db" {
					t.Errorf("%s: %s is passed %s, the DOMAIN connection. It %s, so under "+
						"TFR_IDENTITY_SCHEMA_ENABLED it reads and writes different tables "+
						"than AuthMiddleware does — SCIM offboarding returned 204 with the "+
						"user's access fully intact this way (issue #739). Pass identityDB.",
						fset.Position(call.Pos()), key, s, owns)
				}
			}
			if !sawIdentity {
				t.Errorf("%s: %s receives no identity-backed connection (%v). It %s.",
					fset.Position(call.Pos()), key, identityBackedArgs, owns)
			}
			return true
		})
	}

	if checked == 0 {
		t.Fatal("matched no mustUseIdentityDB call sites in the router wiring — " +
			"the guard is vacuous")
	}
	t.Logf("classified %d consumer(s); verified %d identity-owning call site(s)",
		len(consumers), checked)
}

// TestIdentityBackedArgVocabulary_IsStillAccurate keeps the "what counts as
// identity-backed" list honest: if NewRouter's identity parameter is renamed,
// the list above silently stops recognising it and the guard starts passing for
// the wrong reason.
func TestIdentityBackedArgVocabulary_IsStillAccurate(t *testing.T) {
	_, file := parseGoFile(t, "router.go")

	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewRouter" {
			return true
		}
		for _, p := range fn.Type.Params.List {
			for _, name := range p.Names {
				if identityBackedArgs[name.Name] {
					found = true
				}
			}
		}
		return false
	})

	if !found {
		t.Errorf("NewRouter has no parameter named in identityBackedArgs (%v). If the "+
			"identity connection was renamed, update that list — otherwise the wiring "+
			"guard no longer recognises a correctly-wired call.", identityBackedArgs)
	}
}
