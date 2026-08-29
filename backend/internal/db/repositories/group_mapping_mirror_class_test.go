package repositories

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Class guard for the group-mapping dual-write
// (sethbacon/terraform-suite-identity#206 phase 2, migration 000059).
//
// The property: EVERY path that can change the group-mapping list stored in
// oidc_config.extra_config also makes registry's own group_mappings table
// equal the new list. Nothing reads registry's table yet, so no behavioural
// test can observe a path that forgets -- the divergence would surface at the
// read cutover, after the rows are already wrong.
//
// This is the same guard family as member_role_mirror_class_test.go (whose
// helpers -- identityStoreDir, methodsOn, bodyText, calledMethodNames,
// moduleRoot, sortedNames -- it reuses), with one structural difference: the
// registry wrapper (repositories.OIDCConfigRepository) does NOT embed the
// shared store, it delegates through a named field. So a store writer the
// wrapper does not declare is unreachable through the wrapper, and the bypass
// shapes are:
//
//  1. The pinned module's store grows or changes an oidc_config writer and the
//     wrapper's delegation set silently no longer matches the store's writer
//     set. (On an embedding wrapper this is method promotion; here it is a
//     drifted delegation list -- either way the guard derives the writer set
//     from the module source, so a bump that changes it fails HERE, on the
//     bump, when it is still cheap.)
//  2. A wrapper delegation that forgets the mirror call.
//  3. Somebody builds identitystore.NewOIDCConfigRepository directly and
//     writes configs through a repository that has no mirror at all.
//  4. Somebody writes oidc_config SQL by hand.
//
// Every test here fails on an empty universe.
//
// # The blind axis this file was written against
//
// The store's INSERT lives in a PACKAGE-LEVEL CONST (createOIDCConfigInsertQuery),
// not in the method body -- so a matcher that only reads body string literals
// (which is what bodyText does, and what the member-role guard needs) derives
// a universe that is missing CreateOIDCConfig and certifies less than it
// claims. storeOIDCWriterSQLText therefore folds in the values of package-level
// string constants the body references, and
// TestGroupMappingMirrorClass_UniverseSeesTheConstCarriedInsert pins the fact
// that the const-carried writer is seen -- if const resolution breaks, that
// test fails rather than this file going quietly blind.

// groupMappingMirrorCallNames are the accepted ways a wrapper method reaches
// registry's own group_mappings table.
var groupMappingMirrorCallNames = map[string]bool{
	"ReplaceForConfig": true,
	"ClearConfig":      true,
}

// storeOIDCWriteSQL matches a statement that creates, updates or removes an
// oidc_config row. Any of them can change which group-mapping list exists;
// whether the CHANGE must be mirrored is classified per method below.
var storeOIDCWriteSQL = regexp.MustCompile(`(?i)(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+oidc_config\b`)

// oidcWritersThatCannotChangeMappingContent classifies store writers whose
// statements cannot alter any config's group-mapping LIST, with the reason.
// Checked in both directions: an entry naming a method that is no longer a
// derived writer, or that the wrapper no longer declares, fails the test.
var oidcWritersThatCannotChangeMappingContent = map[string]string{
	"ActivateOIDCConfig": "flips is_active only; the mirror is keyed per config and mirrors every config's " +
		"list, so which config is EFFECTIVE stays oidc_config's own fact until the read cutover",
	"DeactivateAllOIDCConfigs": "flips is_active only; same reasoning as ActivateOIDCConfig",
}

// packageStringValues collects every package-level string constant and
// variable declared in dir's non-test files, keyed by name. Concatenations of
// string literals ("a" + "b") are folded, because that is how the store spells
// its long column lists.
func packageStringValues(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]string{}
	var foldString func(e ast.Expr) (string, bool)
	foldString = func(e ast.Expr) (string, bool) {
		switch v := e.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				return v.Value, true
			}
		case *ast.BinaryExpr:
			if v.Op == token.ADD {
				l, lok := foldString(v.X)
				r, rok := foldString(v.Y)
				if lok && rok {
					return l + r, true
				}
			}
		case *ast.ParenExpr:
			return foldString(v.X)
		}
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if s, ok := foldString(vs.Values[i]); ok {
						out[name.Name] = s
					}
				}
			}
		}
	}
	return out
}

// storeOIDCWriterSQLText renders everything SQL-shaped a function can reach
// lexically: its body's string literals PLUS the values of package-level
// string constants/vars its body references by name. The second half is the
// point -- see the header on the blind axis.
func storeOIDCWriterSQLText(t *testing.T, fn *ast.FuncDecl, pkgStrings map[string]string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(bodyText(t, fn))
	seen := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || seen[id.Name] {
			return true
		}
		if v, ok := pkgStrings[id.Name]; ok {
			seen[id.Name] = true
			sb.WriteString(v)
			sb.WriteString("\n")
		}
		return true
	})
	return sb.String()
}

// packageFuncsIn returns every package-level function (no receiver) declared
// in dir's non-test files, keyed by name -- deactivateAllOIDCConfigsTx is one,
// and it is where two writers' UPDATE actually lives.
func packageFuncsIn(t *testing.T, dir string) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			out[fn.Name.Name] = fn
		}
	}
	return out
}

// storeOIDCConfigWriters derives, from the pinned module's own source, every
// method on the shared store's OIDCConfigRepository that writes oidc_config --
// in its own reachable SQL text, or by calling a package function or method
// that does.
func storeOIDCConfigWriters(t *testing.T) map[string]bool {
	t.Helper()
	return deriveOIDCConfigWritersIn(t, identityStoreDir(t), "OIDCConfigRepository")
}

// deriveOIDCConfigWritersIn is the derivation itself, parameterised by
// directory and receiver type so that
// TestGroupMappingMirrorClass_DerivationSeesEveryCarrierRoute can run it over
// a synthetic universe where each carrier route exists in ISOLATION -- the
// real module's shapes overlap (CreateOIDCConfig is reachable both through
// its const and through the package function it calls), so only a synthetic
// universe can prove that each route is load-bearing on its own.
func deriveOIDCConfigWritersIn(t *testing.T, dir, typeName string) map[string]bool {
	t.Helper()
	methods := methodsOn(t, dir, typeName)
	if len(methods) == 0 {
		t.Fatalf("found no methods on %s under %s — "+
			"the layout changed and this guard has no universe", typeName, dir)
	}
	funcs := packageFuncsIn(t, dir)
	pkgStrings := packageStringValues(t, dir)

	// One name space for the closure: methods and package functions together.
	all := map[string]*ast.FuncDecl{}
	for name, fn := range funcs {
		all[name] = fn
	}
	for name, fn := range methods {
		all[name] = fn
	}

	writers := map[string]bool{}
	for name, fn := range all {
		if storeOIDCWriteSQL.MatchString(storeOIDCWriterSQLText(t, fn, pkgStrings)) {
			writers[name] = true
		}
	}
	if len(writers) == 0 {
		t.Fatal("found no oidc_config write statements in the shared store — either the SQL moved " +
			"or storeOIDCWriteSQL is stale. Refusing to certify the dual-write against an empty universe")
	}

	// Closure: anything calling a writer is a writer.
	for changed := true; changed; {
		changed = false
		for name, fn := range all {
			if writers[name] {
				continue
			}
			for called := range calledMethodNames(fn) {
				if writers[called] {
					writers[name] = true
					changed = true
					break
				}
			}
		}
	}

	// Only methods on the repository type are the wrapper's universe; the
	// package functions existed solely to carry SQL into the closure.
	out := map[string]bool{}
	for name := range writers {
		if _, isMethod := methods[name]; isMethod {
			out[name] = true
		}
	}
	return out
}

// TestGroupMappingMirrorClass_DerivationSeesEveryCarrierRoute proves each of
// the three routes SQL can reach a method through is load-bearing ON ITS OWN,
// over a synthetic universe where the routes do not overlap. The real module
// cannot prove this: its const-carried writer (CreateOIDCConfig) also calls a
// package function that writes, so blinding the const route there changes
// nothing -- which is exactly how this file's first mutation test failed to
// fail, and why this test exists.
func TestGroupMappingMirrorClass_DerivationSeesEveryCarrierRoute(t *testing.T) {
	dir := t.TempDir()
	src := `package fakestore

const constCarried = ` + "`" + `INSERT INTO oidc_config (id) VALUES ($1)` + "`" + `

func helperWrite() { _ = ` + "`" + `UPDATE oidc_config SET is_active = false` + "`" + ` }

type FakeRepo struct{}

func (r *FakeRepo) ConstCarried()  { _ = constCarried }
func (r *FakeRepo) ViaHelper()     { helperWrite() }
func (r *FakeRepo) BodyLiteral()   { _ = ` + "`" + `DELETE FROM oidc_config WHERE id = $1` + "`" + ` }
func (r *FakeRepo) ReadOnly()      { _ = ` + "`" + `SELECT id FROM oidc_config` + "`" + ` }
`
	if err := os.WriteFile(filepath.Join(dir, "store.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write synthetic store: %v", err)
	}

	writers := deriveOIDCConfigWritersIn(t, dir, "FakeRepo")
	for _, route := range []struct{ method, carrier string }{
		{"ConstCarried", "a package-level string const its body references"},
		{"ViaHelper", "a package function it calls"},
		{"BodyLiteral", "a string literal in its own body"},
	} {
		if !writers[route.method] {
			t.Errorf("the derivation missed %s, whose write SQL is carried by %s. That carrier route "+
				"has gone blind, and a store writer spelled that way would silently escape every other "+
				"test in this file.", route.method, route.carrier)
		}
	}
	if writers["ReadOnly"] {
		t.Error("the derivation classified ReadOnly (a SELECT) as a writer — the SQL matcher is " +
			"over-broad, and the wrapper tests would demand mirrors on reads")
	}
}

// TestGroupMappingMirrorClass_UniverseSeesTheConstCarriedInsert pins the three
// derivation routes a writer can hide behind, one witness each:
//
//   - CreateOIDCConfig: its INSERT lives in a package-level const AND its
//     active-create path only writes through deactivateAllOIDCConfigsTx, a
//     package FUNCTION -- the two routes bodyText alone cannot see.
//   - UpdateOIDCConfigExtraConfig: a plain body-literal UPDATE, the route the
//     member-role guard already handles.
//   - DeleteOIDCConfig: a body-literal DELETE, because the dual-write cares
//     about deletes as much as writes.
//
// If any of the three stops being derived, the derivation has gone blind on
// that route, and every green result from the tests below means less than it
// claims. (A module bump that genuinely removes one of these methods also
// lands here first; reclassify deliberately in the same commit.)
func TestGroupMappingMirrorClass_UniverseSeesTheConstCarriedInsert(t *testing.T) {
	writers := storeOIDCConfigWriters(t)
	for _, witness := range []string{"CreateOIDCConfig", "UpdateOIDCConfigExtraConfig", "DeleteOIDCConfig"} {
		if !writers[witness] {
			t.Errorf("the derivation no longer sees %s as an oidc_config writer. Either the pinned module "+
				"genuinely dropped it (then update this witness list deliberately), or the derivation has "+
				"gone blind on one of its routes — body literals, package-level string consts, or the "+
				"closure through package functions — and every other test in this file now certifies "+
				"less than it claims.", witness)
		}
	}
	t.Logf("derived store oidc_config writers: %v", sortedNames(writers))
}

// TestGroupMappingMirrorClass_EveryStoreOIDCWriterIsWrapped is bypasses 1
// and 2.
//
// Every store writer must be re-declared on the registry wrapper (the wrapper
// does not embed, so this is what "reachable through the wrapper" means), and
// each of those wrapper methods must either reach a mirror call or be
// classified in oidcWritersThatCannotChangeMappingContent with a reason.
func TestGroupMappingMirrorClass_EveryStoreOIDCWriterIsWrapped(t *testing.T) {
	writers := storeOIDCConfigWriters(t)
	wrapper := methodsOn(t, ".", "OIDCConfigRepository")
	if len(wrapper) == 0 {
		t.Fatal("repositories.OIDCConfigRepository declares no methods — the type was renamed or moved, " +
			"and nothing is mirrored")
	}

	var checked int
	for _, name := range sortedNames(writers) {
		fn := wrapper[name]
		if fn == nil {
			t.Errorf("the shared identity store's OIDCConfigRepository.%s writes oidc_config, but "+
				"repositories.OIDCConfigRepository does not declare it. The wrapper's delegation set has "+
				"drifted from the store's writer set — add a delegation that mirrors (or classify it in "+
				"oidcWritersThatCannotChangeMappingContent), so the group-mapping dual-write "+
				"(terraform-suite-identity#206, migration 000059) keeps covering every write site.", name)
			continue
		}
		if reason := oidcWritersThatCannotChangeMappingContent[name]; reason != "" {
			checked++
			continue
		}
		checked++
		var reaches bool
		for called := range calledMethodNames(fn) {
			if groupMappingMirrorCallNames[called] {
				reaches = true
				break
			}
		}
		if !reaches {
			t.Errorf("repositories.OIDCConfigRepository.%s delegates a store oidc_config writer but "+
				"reaches none of the mirror calls %v. The change lands in oidc_config.extra_config and "+
				"never in registry's own group_mappings, which is exactly the half-a-dual-write this "+
				"guard exists to prevent (terraform-suite-identity#206). Mirror it, or classify it in "+
				"oidcWritersThatCannotChangeMappingContent with the reason.",
				name, sortedNames(groupMappingMirrorCallNames))
		}
	}
	if checked == 0 {
		t.Fatal("no wrapper method matched a store oidc_config writer — the two derivations have " +
			"drifted apart and this guard is vacuous")
	}

	for name := range oidcWritersThatCannotChangeMappingContent {
		if !writers[name] {
			t.Errorf("oidcWritersThatCannotChangeMappingContent names %q, which is no longer a derived "+
				"oidc_config writer in the pinned module — drop the entry", name)
		}
		if wrapper[name] == nil {
			t.Errorf("oidcWritersThatCannotChangeMappingContent names %q, which the wrapper no longer "+
				"declares — drop the entry", name)
		}
	}
	t.Logf("checked %d store oidc_config writer(s) against the wrapper", checked)
}

// oidcStoreConstructorExemptions are the files permitted to build the shared
// store's OIDC-config repository directly. Exactly one: the wrapper, which
// must build the thing it wraps.
var oidcStoreConstructorExemptions = map[string]string{
	"internal/db/repositories/oidc_config_repository.go": "the wrapper itself; it delegates to what it constructs",
}

// TestGroupMappingMirrorClass_NoDirectStoreConstruction is bypass 3, the same
// shape (and the same any-REFERENCE-not-just-a-call reasoning) as
// TestMemberRoleMirrorClass_NoDirectStoreConstruction.
func TestGroupMappingMirrorClass_NoDirectStoreConstruction(t *testing.T) {
	root := moduleRoot(t)

	var offenders []string
	var scanned int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewOIDCConfigRepository" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "identitystore" {
				return true
			}
			if _, exempt := oidcStoreConstructorExemptions[rel]; exempt {
				return true
			}
			offenders = append(offenders, fset.Position(sel.Pos()).String())
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned == 0 {
		t.Fatal("scanned no Go files — the walk is broken and this guard is vacuous")
	}

	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s — builds identitystore.NewOIDCConfigRepository directly. That repository has no "+
			"group-mapping mirror, so every config written through it bypasses the dual-write and "+
			"registry's own group_mappings silently diverges (terraform-suite-identity#206). Use "+
			"repositories.NewOIDCConfigRepository, which returns the mirroring wrapper.", o)
	}
	t.Logf("scanned %d Go file(s) for a direct store construction", scanned)
}

// rawOIDCConfigWriteAllowlist names the registry files that write oidc_config
// by hand, with the reason each cannot change a group-mapping list. Checked in
// both directions: a file here with no raw write is a stale entry, and a raw
// write in a file that is not here fails outright.
var rawOIDCConfigWriteAllowlist = map[string]string{
	"internal/maintenance/bindsecrets.go": "re-encrypts client_secret_encrypted in place during secret " +
		"rebinding; the statement names only that column and cannot reach extra_config",
}

// TestGroupMappingMirrorClass_RawOIDCConfigWritesCannotTouchMappings is
// bypass 4. A hand-written oidc_config statement bypasses the wrapper
// entirely; the ones that exist are enumerated and each must be incapable of
// changing extra_config — which is asserted on the file's source, not taken
// from the allowlist's word for it.
func TestGroupMappingMirrorClass_RawOIDCConfigWritesCannotTouchMappings(t *testing.T) {
	root := moduleRoot(t)

	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if !storeOIDCWriteSQL.Match(src) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		found[rel] = true
		if _, known := rawOIDCConfigWriteAllowlist[rel]; !known {
			t.Errorf("%s writes oidc_config by hand and is not listed in rawOIDCConfigWriteAllowlist. "+
				"A hand-written statement bypasses the group-mapping dual-write in "+
				"repositories.OIDCConfigRepository entirely (terraform-suite-identity#206). Either write "+
				"it through the repository, or — if it cannot change extra_config — add it here with the "+
				"reason.", rel)
			return nil
		}
		if strings.Contains(string(src), "extra_config") {
			t.Errorf("%s is allowlisted as unable to change extra_config, but its source now mentions "+
				"extra_config. Re-examine it: if it writes the column, its group-mapping changes bypass "+
				"the dual-write and must be mirrored in the same file.", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	if len(found) == 0 {
		t.Fatal("found no hand-written oidc_config statements anywhere — either every raw write moved " +
			"behind the repository (in which case delete this test and its list) or storeOIDCWriteSQL " +
			"is stale. It must not pass by matching nothing")
	}
	for rel := range rawOIDCConfigWriteAllowlist {
		if !found[rel] {
			t.Errorf("rawOIDCConfigWriteAllowlist lists %q, which no longer writes oidc_config by hand "+
				"— drop the entry", rel)
		}
	}
}
