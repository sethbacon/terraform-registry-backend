package schemaguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Issue #864 — application SQL must not depend on schema the running
// configuration will not have.
//
// THE DEFECT
//
// The identity store writes identity.audit_logs.actor_email unconditionally.
// That column is added by identity migration 000007, and the whole identity
// migration stream is gated behind TFR_IDENTITY_MIGRATIONS_ENABLED, default
// off. Separately, TFR_IDENTITY_SCHEMA_ENABLED (also default off) is what puts
// the identity schema on the connection's search_path — with it off,
// identityDB is the plain app pool and every unqualified identity write
// resolves against public. public.audit_logs comes from this repository's own
// 000001_initial_schema and has never had actor_email. So in the DEFAULT
// configuration every audited request dies on
//
//	pq: column "actor_email" of relation "audit_logs" does not exist (42703)
//
// Two flags are involved, not one, and that is the part the issue's own triage
// got wrong. Removing the TFR_IDENTITY_MIGRATIONS_ENABLED gate does not fix the
// default topology: migration 000007 is schema-qualified (ALTER TABLE
// identity.audit_logs), so running the identity chain adds the column to a
// table the default configuration never writes to. Reproduced on postgres:16 in
// #864's comments — the 42703 is identical before and after the identity chain
// is applied. This guard models the resolution, not the flag, which is why it
// stays red under that "fix" instead of certifying it.
//
// THE CLASS
//
// A gated capability became load-bearing without anything failing at build or
// start time. PR #438's safety premise was written down explicitly — "the
// identity schema is created but unused" — and expired silently when the audit
// path started depending on the gated schema. Nothing in the compiler, the
// startup sequence or the test suite could notice, because no single artefact
// holds both halves: the SQL lives in a Go module, the schema lives in .sql
// files, and the configuration that decides which of them apply lives in
// environment variables read at runtime.
//
// This guard holds all three at once. It replays the migrations the DEFAULT
// configuration actually applies, extracts every column application SQL
// actually writes (this repository's and the shared identity module's alike),
// resolves them through the search_path the default configuration actually
// uses, and fails on anything that cannot land.
//
// WHY THIS SHAPE
//
// A dynamic test against a real postgres would reproduce #864 more literally,
// and one is worth having, but it cannot run on every pull request here: PR CI
// runs no migrations at all today (only chaos.yml stands up a database), which
// is part of why this shipped. This guard is hermetic — no container, no
// network, no database — so it runs in the `go test ./...` that already gates
// every PR, which is the only place a guard against a silent default has any
// chance of being seen before release.
//
// It is also deliberately NOT a test of the audit path. Testing the audit path
// would have caught this instance and nothing else. The invariant here is
// schema-wide and library-wide: 230-odd writes across both codebases are
// checked, so the next capability to depend on gated schema fails here too.

// ---------------------------------------------------------------------------
// What this guard does NOT cover
// ---------------------------------------------------------------------------
//
// Stated plainly, because a guard whose limits are undocumented gets trusted
// past them.
//
//  1. READS. Only INSERT / UPDATE / DELETE are checked. A SELECT naming a
//     missing column fails just as hard at runtime, but resolving SELECT
//     projections means resolving aliases, joins, subqueries and CTEs. Out of
//     scope. #864's write happened to also RETURNING the same column.
//
//  2. TYPES, NULLABILITY, CONSTRAINTS AND DEFAULTS. Presence of a column is
//     all that is checked. A write of the wrong type, or omitting a NOT NULL
//     column with no default, passes here and fails at runtime.
//
//  3. SQL NOT PRESENT AS A CONTIGUOUS GO STRING LITERAL. Statements assembled
//     from fmt.Sprintf, a query builder, or a string variable contribute only
//     whatever literal text is adjacent. This can only miss a write, never
//     invent one. internal/db/repositories/querybuilder.go is largely invisible
//     to this guard for that reason.
//
//  4. TABLES CREATED BY APPLICATION CODE RATHER THAN BY A MIGRATION. Runtime
//     `CREATE TABLE IF NOT EXISTS` found in Go source is credited to the
//     universe, because a configuration that runs it really will have the
//     table. The guard does NOT verify the creating code is ever called.
//     internal/audit/legal_hold.go is exactly this case and its EnsureTable
//     currently has no non-test caller — the tables it credits are listed in
//     the test log so the credit is visible rather than implicit.
//
//  5. NON-DEFAULT CONFIGURATIONS. Only the shipped default is checked. The
//     cutover configurations documented in docs/identity-schema.md are not
//     modelled, on the ground that a broken default is what ships to everyone
//     who does not read the guide.
//
//  6. OTHER CONSUMERS OF THE SHARED LIBRARY. terraform-state-manager-backend
//     runs identity.RunMigrations unconditionally while this repository gates
//     it, and that divergence is arguably #864's root cause. Checking it needs
//     both checkouts, which no CI job here has. See the report accompanying
//     this guard for the cross-consumer recommendation.
//
//  7. WHETHER THE SERVER REFUSES TO START. This guard says the default
//     configuration cannot execute its own SQL. It cannot say whether that is
//     survivable, because it does not model startup preconditions. A
//     fail-fast check in cmd/server/main.go is complementary, not redundant.
//
//  8. WRITES CHOSEN AT RUNTIME. Code that probes the catalogue and picks a
//     narrower statement when a column is missing is safe, and the guard cannot
//     see that on its own — it reads both branches as unconditional demand. Such
//     writes need an explicit probedWrites entry, which the guard then re-derives
//     the justification for on every run (see below). Nothing here detects an
//     unregistered probe, so a correct fix that is not registered shows up as a
//     failure rather than being silently credited.

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

// knownGap is a violation that existed when this guard landed. The list can
// only shrink: an entry that stops matching FAILS the guard, so the fix for
// #864 also deletes the line that excuses it. Nothing may be added here
// without an issue number.
type knownGap struct {
	Table  string
	Column string
	Issue  string
	Why    string
}

// knownGaps is EMPTY, and #864 is why it can be.
//
// It held exactly one entry — audit_logs.actor_email — recording that the
// shared identity store wrote and read a column this repository's own chain
// never gave public.audit_logs, so every audited request and every read of
// /api/v1/admin/audit-logs answered 42703 in the DEFAULT configuration. The
// entry named three ways out and said to delete it when one landed.
//
// Migration 000058 is that landing: it adds the column here, additively, so a
// deployment that later completes the identity-schema cutover finds it already
// present on identity.audit_logs and this one goes inert.
//
// An entry here is a column the default configuration cannot supply — a 500
// waiting for the first request that reaches it. Empty is the finish line, and
// the set is empty; a new entry needs the same standard of proof the last one
// had, including which remedy will remove it.
var knownGaps = []knownGap{}

func (g knownGap) matches(v violation) bool {
	return strings.EqualFold(g.Table, v.Table) && strings.EqualFold(g.Column, v.Column)
}

// ---------------------------------------------------------------------------
// Probed writes
// ---------------------------------------------------------------------------

// probedWrite is a write this guard would otherwise flag, and must not,
// because the code asks the database whether the column is there before
// choosing the statement. That is not a gap to be excused — it is the correct
// fix shape for this defect class, so the guard has to recognise it or it
// punishes the behaviour it is trying to encourage.
//
// The entry is NOT taken on trust. Three things must hold or the guard fails:
//
//   - it must match a real violation (a stale entry is deleted, like knownGaps);
//   - the file must still contain Probe, the catalogue lookup that decides;
//   - the file must still contain a write to the same table that does NOT name
//     the column — the narrower statement the probe falls back to. Without a
//     fallback there is nothing to switch to and the probe is decoration.
//
// Delete the probe or the fallback and the suppression stops being justified
// on the next run.
type probedWrite struct {
	// FileSuffix identifies the source file by path suffix.
	FileSuffix string
	Table      string
	Column     string
	// Probe is text that must appear in the file for the suppression to hold.
	Probe string
	Why   string
}

// EMPTY since the outbox sink moved into the shared library
// (identity/auditoutbox, terraform-suite-identity#206). PR #865's sink was a
// two-branch statement — the ten-column insert when the destination carries
// actor_email, the nine-column one when it does not — and this entry existed to
// recognise the probe that chose between them. The library's sink asks the
// destination for its WHOLE column set and builds the insert from the
// intersection, so it names no column literally and this guard's scanner sees
// no write to attribute to it at all. There is nothing left here to suppress.
//
// The property that entry stood for did not go away; it moved to where the
// statement is, and identity/auditoutbox's own sink tests hold it.
var probedWrites = []probedWrite{}

func (p probedWrite) matches(v violation) bool {
	return strings.EqualFold(p.Table, v.Table) &&
		strings.EqualFold(p.Column, v.Column) &&
		strings.Contains(filepath.ToSlash(v.Pos), p.FileSuffix)
}

// verify re-derives the two facts that make the suppression sound, from the
// file itself, on every run.
func (p probedWrite) verify(t *testing.T, v violation) {
	t.Helper()
	path := filepath.ToSlash(v.Pos)
	if i := strings.Index(path, p.FileSuffix); i >= 0 {
		path = path[:i] + p.FileSuffix
	}
	src, err := os.ReadFile(path) // #nosec G304 -- test-only; path comes from a violation this guard produced
	if err != nil {
		t.Errorf("probedWrite %s %s.%s: cannot read %s: %v",
			p.FileSuffix, p.Table, p.Column, path, err)
		return
	}
	if !strings.Contains(string(src), p.Probe) {
		t.Errorf("probedWrite %s %s.%s: %q is gone from the file. The write is suppressed on the "+
			"grounds that the code checks the destination first; without that check the "+
			"suppression is unfounded and the write is a live #864.",
			p.FileSuffix, p.Table, p.Column, p.Probe)
	}
	if !hasFallbackWrite(t, path, p.Table, p.Column) {
		t.Errorf("probedWrite %s %s.%s: the file no longer contains a write to %s that omits %s. "+
			"A probe with nothing to fall back to does not make the write safe.",
			p.FileSuffix, p.Table, p.Column, p.Table, p.Column)
	}
}

// hasFallbackWrite reports whether the file contains a write to table that
// does not name column — the narrower statement a probe selects when the
// column is absent.
func hasFallbackWrite(t *testing.T, path, table, column string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Errorf("schemaguard: parse %s: %v", path, err)
		return false
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		text, pos, ok := stringLiteral(n, fset)
		if !ok {
			return true
		}
		for _, w := range extractWrites(text, pos) {
			if !strings.EqualFold(w.Table, table) {
				continue
			}
			names := false
			for _, c := range w.Columns {
				if strings.EqualFold(c, column) {
					names = true
					break
				}
			}
			if !names && len(w.Columns) > 0 {
				found = true
			}
		}
		return false
	})
	return found
}

// ---------------------------------------------------------------------------
// Deriving the default configuration from source
// ---------------------------------------------------------------------------

const (
	mainGoPath        = "../../cmd/server/main.go"
	appMigrationsDir  = "../db/migrations"
	backendSourceRoot = "../.."
	identityModule    = "github.com/sethbacon/terraform-suite-identity"

	schemaGateFunc      = "identitySchemaEnabled"
	schemaNameFunc      = "identitySchemaName"
	identityRunMigrCall = "identity.RunMigrations"
	appRunMigrCall      = "db.RunMigrations"
)

// envGate is a `func F() bool { return os.Getenv("E") == "true" }` style flag.
type envGate struct {
	Func      string
	Env       string
	DefaultOn bool
}

// defaultConfig is what the shipped defaults amount to.
type defaultConfig struct {
	SearchPath      []string
	IdentityApplied bool
	AppApplied      bool
	Gates           map[string]envGate
}

// readDefaultConfig derives the default configuration from cmd/server/main.go
// rather than restating it. That is the whole point: when #864 is fixed by
// changing a default or removing a gate, this guard follows the change instead
// of having to be re-taught. Anything it cannot recognise is fatal — a guard
// that silently guesses the configuration is worse than no guard.
func readDefaultConfig(t *testing.T) defaultConfig {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mainGoPath, nil, 0)
	if err != nil {
		t.Fatalf("schemaguard: parse %s: %v", mainGoPath, err)
	}

	gates := map[string]envGate{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if g, ok := envGateFromFunc(fn); ok {
			gates[g.Func] = g
		}
	}
	if len(gates) == 0 {
		t.Fatalf("schemaguard: found no `os.Getenv(...) == \"true\"` feature gates in %s. "+
			"Either the gating style changed or the file moved; refusing to certify against a "+
			"configuration this guard cannot read.", mainGoPath)
	}

	schemaGate, ok := gates[schemaGateFunc]
	if !ok {
		t.Fatalf("schemaguard: %s() not found in %s. It decides whether the identity schema is on "+
			"the connection search_path, and without it the guard cannot know which schema an "+
			"unqualified write resolves against.", schemaGateFunc, mainGoPath)
	}

	cfg := defaultConfig{Gates: gates}
	if schemaGate.DefaultOn {
		cfg.SearchPath = []string{identitySchemaDefaultName(t, f), "public"}
	} else {
		cfg.SearchPath = []string{"public"}
	}

	calls := runMigrationsCallSites(f)
	for _, want := range []string{identityRunMigrCall, appRunMigrCall} {
		if _, ok := calls[want]; !ok {
			t.Fatalf("schemaguard: no call to %s found in %s. The set of migration streams the "+
				"binary applies is the guard's schema universe; an empty one certifies nothing.",
				want, mainGoPath)
		}
	}
	cfg.IdentityApplied = allGatesDefaultOn(t, gates, calls[identityRunMigrCall])
	cfg.AppApplied = allGatesDefaultOn(t, gates, calls[appRunMigrCall])
	return cfg
}

// envGateFromFunc recognises the two shapes a boolean env gate takes:
//
//	return os.Getenv("X") == "true"   // default off
//	return os.Getenv("X") != "false"  // default on
func envGateFromFunc(fn *ast.FuncDecl) (envGate, bool) {
	if len(fn.Body.List) != 1 {
		return envGate{}, false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return envGate{}, false
	}
	bin, ok := ret.Results[0].(*ast.BinaryExpr)
	if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
		return envGate{}, false
	}
	call, ok := bin.X.(*ast.CallExpr)
	if !ok || exprName(call.Fun) != "os.Getenv" || len(call.Args) != 1 {
		return envGate{}, false
	}
	env, ok := stringLitValue(call.Args[0])
	if !ok {
		return envGate{}, false
	}
	want, ok := stringLitValue(bin.Y)
	if !ok {
		return envGate{}, false
	}
	switch {
	case bin.Op == token.EQL && want == "true":
		return envGate{Func: fn.Name.Name, Env: env, DefaultOn: false}, true
	case bin.Op == token.NEQ && want == "false":
		return envGate{Func: fn.Name.Name, Env: env, DefaultOn: true}, true
	}
	return envGate{}, false
}

// identitySchemaDefaultName reads the fallback literal out of
// identitySchemaName() so a renamed default schema is followed, not assumed.
func identitySchemaDefaultName(t *testing.T, f *ast.File) string {
	t.Helper()
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != schemaNameFunc || fn.Body == nil {
			continue
		}
		var last string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
				if s, ok := stringLitValue(ret.Results[0]); ok && s != "" {
					last = s
				}
			}
			return true
		})
		if last != "" {
			return last
		}
	}
	t.Fatalf("schemaguard: could not read the default schema name from %s() in %s",
		schemaNameFunc, mainGoPath)
	return ""
}

// runMigrationsCallSites maps "pkg.RunMigrations" to the set of gate functions
// whose enclosing `if` must be true for that call to run. An unguarded call
// yields an empty set, which is how "the gate was removed" is detected.
func runMigrationsCallSites(f *ast.File) map[string][]string {
	out := map[string][]string{}
	var stack []string
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if n == nil {
			return
		}
		switch v := n.(type) {
		case *ast.IfStmt:
			added := conditionGateNames(v.Cond)
			stack = append(stack, added...)
			walk(v.Body)
			stack = stack[:len(stack)-len(added)]
			// The else branch is NOT inside the condition.
			if v.Else != nil {
				walk(v.Else)
			}
			if v.Init != nil {
				walk(v.Init)
			}
			return
		case *ast.CallExpr:
			if name := exprName(v.Fun); strings.HasSuffix(name, ".RunMigrations") {
				if _, seen := out[name]; !seen || len(stack) < len(out[name]) {
					out[name] = append([]string(nil), stack...)
				}
			}
		}
		for _, child := range childNodes(n) {
			walk(child)
		}
	}
	for _, decl := range f.Decls {
		walk(decl)
	}
	return out
}

// conditionGateNames returns the gate functions a condition calls. Only plain
// `f()` and `f() && g()` are understood; anything else contributes no name,
// which makes the call look unguarded and can therefore only make the guard
// stricter, never laxer.
func conditionGateNames(cond ast.Expr) []string {
	switch v := cond.(type) {
	case *ast.CallExpr:
		if id, ok := v.Fun.(*ast.Ident); ok && len(v.Args) == 0 {
			return []string{id.Name}
		}
	case *ast.BinaryExpr:
		if v.Op == token.LAND {
			return append(conditionGateNames(v.X), conditionGateNames(v.Y)...)
		}
	case *ast.ParenExpr:
		return conditionGateNames(v.X)
	}
	return nil
}

func allGatesDefaultOn(t *testing.T, gates map[string]envGate, enclosing []string) bool {
	t.Helper()
	for _, name := range enclosing {
		g, ok := gates[name]
		if !ok {
			// An enclosing condition this guard cannot evaluate. Treat the
			// stream as not applied: understating the universe turns unchecked
			// writes into failures, which is the safe direction.
			t.Logf("schemaguard: enclosing condition %q is not a recognised env gate; "+
				"treating the guarded migration stream as NOT applied by default", name)
			return false
		}
		if !g.DefaultOn {
			return false
		}
	}
	return true
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if x := exprName(v.X); x != "" {
			return x + "." + v.Sel.Name
		}
		return v.Sel.Name
	}
	return ""
}

func stringLitValue(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// childNodes returns n's children. ast.Inspect cannot be used for the walk
// above because the enclosing-`if` stack has to be popped on the way out, and
// Inspect's post-order callback does not say which node it is leaving.
func childNodes(n ast.Node) []ast.Node {
	var out []ast.Node
	ast.Inspect(n, func(c ast.Node) bool {
		if c == nil || c == n {
			return c == n
		}
		out = append(out, c)
		return false
	})
	return out
}

// ---------------------------------------------------------------------------
// Locating the shared identity module
// ---------------------------------------------------------------------------

// identityModuleDir resolves the module's on-disk root through the go tool, so
// a `replace` directive or a version bump is followed automatically.
func identityModuleDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", identityModule).Output()
	if err != nil {
		t.Fatalf("schemaguard: go list -m %s: %v. The shared identity module holds both the SQL "+
			"that broke in #864 and the migrations that would have fixed it; without it this "+
			"guard inspects half the system and must not certify.", identityModule, err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatalf("schemaguard: go list -m %s returned no directory", identityModule)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity", "migrations")); err != nil {
		t.Fatalf("schemaguard: %s has no identity/migrations directory: %v", dir, err)
	}
	return dir
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

// runtimeDDLRoots are scanned for `CREATE TABLE IF NOT EXISTS` in Go string
// literals — tables the application creates for itself rather than through a
// numbered migration. See boundary 4.
var runtimeDDLRoots = []string{backendSourceRoot}

// ignoredTables are unqualified names owned by neither migration stream.
var ignoredTables = map[string]bool{
	// golang-migrate creates and owns its own version table.
	"schema_migrations": true,
}

var ignoredSchemas = map[string]bool{
	"pg_catalog":         true,
	"information_schema": true,
	"pg_temp":            true,
}

// analysis is everything the guard derived from the tree, kept as a value so
// the self-mutation test below can perturb it and re-resolve.
type analysis struct {
	Cfg    defaultConfig
	Model  *schemaModel
	Writes []sqlWrite
	Opts   resolveOpts
}

// buildAnalysis derives the default configuration, replays the migration
// streams that configuration applies, and collects every SQL write in this
// repository and in the shared identity module.
func buildAnalysis(t *testing.T) analysis {
	t.Helper()
	cfg := readDefaultConfig(t)
	idDir := identityModuleDir(t)
	t.Logf("default configuration: search_path=%v app_migrations_applied=%v identity_migrations_applied=%v",
		cfg.SearchPath, cfg.AppApplied, cfg.IdentityApplied)

	m := newSchemaModel()
	if cfg.AppApplied {
		if err := m.replay(migrationStream{Name: "app", Dir: appMigrationsDir, DefaultSchema: "public"}); err != nil {
			t.Fatalf("%v", err)
		}
	}
	if cfg.IdentityApplied {
		dir := filepath.Join(idDir, "identity", "migrations")
		if err := m.replay(migrationStream{Name: "identity", Dir: dir, DefaultSchema: "identity"}); err != nil {
			t.Fatalf("%v", err)
		}
	}
	migrationTables := m.tableCount()

	credited := creditRuntimeDDL(t, m, runtimeDDLRoots)
	if len(credited) > 0 {
		t.Logf("credited to application DDL rather than to a migration (boundary 4, unverified "+
			"that the creating code runs): %v", credited)
	}
	t.Logf("schema universe: %d tables (%d from migrations, %d created by application code)",
		m.tableCount(), migrationTables, len(credited))

	var writes []sqlWrite
	for _, root := range []string{backendSourceRoot, filepath.Join(idDir, "identity")} {
		w, err := scanWrites(root)
		if err != nil {
			t.Fatalf("schemaguard: scan %s: %v", root, err)
		}
		t.Logf("scanned %s: %d SQL writes", root, len(w))
		writes = append(writes, w...)
	}

	return analysis{
		Cfg:    cfg,
		Model:  m,
		Writes: writes,
		Opts: resolveOpts{
			SearchPath:    cfg.SearchPath,
			IgnoreSchemas: ignoredSchemas,
			IgnoreTables:  ignoredTables,
		},
	}
}

// TestDefaultConfigurationCanExecuteItsOwnSQL is the guard.
func TestDefaultConfigurationCanExecuteItsOwnSQL(t *testing.T) {
	a := buildAnalysis(t)
	cfg := a.Cfg

	// --- coherence -------------------------------------------------------
	//
	// A schema on the default search_path whose migration stream the default
	// configuration does not apply is the class in its purest form: the
	// capability is switched on while the thing it needs is switched off.
	// Today this passes trivially (search_path is public alone); it starts
	// biting the moment someone flips the cutover default without flipping the
	// migrations default, which is a two-line change away.
	streamsBySchema := map[string]bool{"public": cfg.AppApplied}
	if len(cfg.SearchPath) > 1 {
		streamsBySchema[cfg.SearchPath[0]] = cfg.IdentityApplied
	}
	for schema, applied := range streamsBySchema {
		if !applied {
			t.Errorf("schema %q is on the default search_path but the default configuration does "+
				"not apply its migrations. A gated migration stream that the default "+
				"configuration depends on is exactly the #864 defect class; either apply the "+
				"stream unconditionally or take the schema off the default search_path.", schema)
		}
	}

	// --- resolve ---------------------------------------------------------
	violations, checked, err := resolve(a.Model, a.Writes, a.Opts)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("checked %d writes against the default schema universe", checked)

	// --- verdict ---------------------------------------------------------
	matched := make([]bool, len(knownGaps))
	probed := make([]bool, len(probedWrites))
	for _, v := range violations {
		excused := false
		for i, p := range probedWrites {
			if p.matches(v) {
				probed[i] = true
				p.verify(t, v)
				excused = true
				break
			}
		}
		if excused {
			continue
		}
		for i, g := range knownGaps {
			if g.matches(v) {
				matched[i] = true
				excused = true
				break
			}
		}
		if excused {
			continue
		}
		t.Errorf("the DEFAULT configuration cannot execute this write: %s\n"+
			"    search_path is %v and only the migration streams above are applied, so this "+
			"statement fails at runtime with 42703/42P01 on every request that reaches it — "+
			"silently, per-request, with a clean startup log. Fix the schema, the write, or the "+
			"default configuration. If it is genuinely acceptable, add it to knownGaps with an "+
			"issue number.", v, cfg.SearchPath)
	}
	for i, g := range knownGaps {
		if !matched[i] {
			t.Errorf("knownGaps entry %s.%s (%s) no longer matches any violation. "+
				"The gap it excused is fixed — delete the entry. This list may only shrink; "+
				"leaving stale entries in it is how an allow-list stops guarding anything.",
				g.Table, g.Column, g.Issue)
		}
	}
	for i, p := range probedWrites {
		if !probed[i] {
			t.Errorf("probedWrites entry %s %s.%s no longer matches any violation. Either the "+
				"write moved, or the column is now in the default schema and the suppression is "+
				"pointless — delete the entry either way.", p.FileSuffix, p.Table, p.Column)
		}
	}
}

// TestGuardFiresWhenTheDefaultSchemaLosesAColumn is the guard's own mutation
// test, run on the real tree on every invocation.
//
// The failure mode this defends against is the one that has bitten this estate
// repeatedly: a guard that is green because it is inspecting nothing. The empty
// universe checks in the analyzer cover being handed nothing at all; this
// covers the subtler case where the migration replay, the write extraction and
// the resolver all run over the real tree but no longer connect — a regex that
// stopped matching, a source root that moved, a schema name that changed. In
// any of those states this test reports the mutation as undetected and fails.
//
// The column is chosen from the live data rather than named, so the test
// cannot rot as the schema changes.
func TestGuardFiresWhenTheDefaultSchemaLosesAColumn(t *testing.T) {
	a := buildAnalysis(t)

	baseline, checked, err := resolve(a.Model, a.Writes, a.Opts)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if checked == 0 {
		t.Fatal("schemaguard: baseline checked zero writes")
	}

	// Pick a (table, column) that the default schema really has and that real
	// application SQL really writes. Sorted so the choice is deterministic.
	victim, ok := pickWrittenColumn(a)
	if !ok {
		t.Fatal("schemaguard: no write in the tree names a column the default schema has. " +
			"Either the schema replay or the write extraction has stopped working; the guard " +
			"cannot be certifying anything in that state.")
	}
	t.Logf("mutating the default schema: dropping %s.%s", victim.key, victim.column)

	delete(a.Model.columns[victim.key], victim.column)

	mutated, _, err := resolve(a.Model, a.Writes, a.Opts)
	if err != nil {
		t.Fatalf("schemaguard: resolve after mutation: %v", err)
	}

	want := victim.key.Table + "." + victim.column
	found := false
	for _, v := range mutated {
		if strings.EqualFold(v.Table, victim.key.Table) && strings.EqualFold(v.Column, victim.column) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dropping %s from the default schema produced no violation naming it.\n"+
			"    baseline violations: %d, after mutation: %d\n"+
			"    The guard is not connecting the schema it replays to the writes it extracts, "+
			"which means a green result from TestDefaultConfigurationCanExecuteItsOwnSQL proves "+
			"nothing.", want, len(baseline), len(mutated))
	}
	if len(mutated) <= len(baseline) {
		t.Errorf("violation count did not grow: baseline %d, mutated %d", len(baseline), len(mutated))
	}
}

type writtenColumn struct {
	key    tableKey
	column string
}

// pickWrittenColumn returns a deterministic (table, column) pair that both
// exists in the modelled default schema and is named by an extracted write.
func pickWrittenColumn(a analysis) (writtenColumn, bool) {
	type cand struct {
		writtenColumn
		sortKey string
	}
	var cands []cand
	for _, w := range a.Writes {
		name := strings.ToLower(w.Table)
		if strings.Contains(name, ".") || ignoredTables[name] {
			continue
		}
		for _, s := range a.Opts.SearchPath {
			k := tableKey{Schema: s, Table: name}
			cols, ok := a.Model.columns[k]
			if !ok {
				continue
			}
			for _, c := range w.Columns {
				if cols[c] {
					cands = append(cands, cand{writtenColumn{key: k, column: c}, k.String() + "." + c})
				}
			}
			break
		}
	}
	if len(cands) == 0 {
		return writtenColumn{}, false
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].sortKey < cands[j].sortKey })
	return cands[0].writtenColumn, true
}

// creditRuntimeDDL folds `CREATE TABLE` statements found in Go string literals
// into the model and returns the table names it added. Only creations are
// honoured — a DROP or RENAME in application source is not replayed, since
// crediting a removal could only ever hide a violation.
func creditRuntimeDDL(t *testing.T, m *schemaModel, roots []string) []string {
	t.Helper()
	before := map[tableKey]bool{}
	for k := range m.columns {
		before[k] = true
	}
	for k := range m.opaque {
		before[k] = true
	}
	for _, root := range roots {
		for _, sql := range scanCreateTableSQL(t, root) {
			for _, stmt := range splitStatements(stripComments(sql)) {
				s := normalize(stmt)
				if reCreateTable.MatchString(s) {
					m.applyCreateTable(s, "public")
				}
			}
		}
	}
	var added []string
	for k := range m.columns {
		if !before[k] {
			added = append(added, k.String())
		}
	}
	sort.Strings(added)
	return added
}

// scanCreateTableSQL returns every non-test Go string literal containing a
// CREATE TABLE.
func scanCreateTableSQL(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "node_modules", ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			return fmt.Errorf("parse %s: %w", path, pErr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			text, _, ok := stringLiteral(n, fset)
			if !ok {
				return true
			}
			if reCreateTableAnywhere.MatchString(text) {
				out = append(out, text)
			}
			return false
		})
		return nil
	})
	if err != nil {
		t.Fatalf("schemaguard: scan %s for runtime DDL: %v", root, err)
	}
	return out
}

// TestNoTableIsCreatedByApplicationCode closes boundary 4 rather than tolerating
// it (issues #864, #871, #872).
//
// creditRuntimeDDL exists because some tables were created by CREATE TABLE IF
// NOT EXISTS in Go rather than by a numbered migration. The guard credited them
// so its write-checking would not report false violations, and logged the credit
// because a credit is an admission: the model is trusting that a string literal
// somewhere is executed, on the right connection, before anything reads the
// table. It cannot verify any of those.
//
// legal_holds was the last one, and #872 moved it into migration 000057 — so
// the credited set is now EMPTY, and an empty set can be asserted where a
// non-empty one could only be logged. From here a new runtime-created table
// fails this test instead of quietly joining a list nobody re-reads.
//
// This is not a ban on CREATE TABLE in Go. It is a requirement that adding one
// is a decision someone writes down: put the table in a migration, or add it
// here with the reason its schema cannot be known at migration time.
func TestNoTableIsCreatedByApplicationCode(t *testing.T) {
	cfg := readDefaultConfig(t)
	idDir := identityModuleDir(t)

	m := newSchemaModel()
	if cfg.AppApplied {
		if err := m.replay(migrationStream{Name: "app", Dir: appMigrationsDir, DefaultSchema: "public"}); err != nil {
			t.Fatalf("%v", err)
		}
	}
	if cfg.IdentityApplied {
		dir := filepath.Join(idDir, "identity", "migrations")
		if err := m.replay(migrationStream{Name: "identity", Dir: dir, DefaultSchema: "identity"}); err != nil {
			t.Fatalf("%v", err)
		}
	}

	credited := creditRuntimeDDL(t, m, runtimeDDLRoots)
	if len(credited) != 0 {
		t.Errorf("these tables are created by application code rather than by a migration: %v\n"+
			"A table outside the migration chain is invisible to everything that reasons about the "+
			"schema from it, and this guard cannot verify that the code creating it runs, runs first, "+
			"or runs on the connection that reads the table \u2014 legal_holds was created at startup for "+
			"months while the sweep that needed it ran on a different connection (#872).\n"+
			"Add a numbered migration, or list the table here with the reason its schema is not "+
			"knowable at migration time.", credited)
	}
}
