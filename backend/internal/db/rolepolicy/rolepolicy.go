// Package rolepolicy derives, from the registry's own migration files, the
// role -> scope policy those migrations leave behind in `role_templates`.
//
// # Why this exists
//
// The registry states one policy TWICE. Once in SQL, as the seed in migration
// 000001 and every migration that has amended it since; once in Go, as
// models.PredefinedRoleTemplates(). Only ONE of the two is exercised in any
// given topology -- the migrations in the default one, the Go list in the
// identity-schema cutover -- so the pair can disagree for a long time without
// anything failing. Issue #891 is exactly that: migration 000018 granted
// `scanning:read` to `devops` and `auditor`, the Go list was never updated, and
// because the seed upserts with `scopes = EXCLUDED.scopes` it REMOVED the scope
// the migration had granted, on every boot, in the topology where it runs.
//
// So this package replays the migrations' role-template DML in memory and hands
// back what they leave. A test then diffs that against the Go list, in BOTH
// directions -- the drift that removes authority fails safe and the drift that
// grants it does not, and neither should be able to reach main.
//
// # Derived, not typed
//
// Nothing here enumerates a scope. The policy comes out of the migration files,
// so a migration that lands tomorrow is covered the moment it exists, without
// anybody remembering to extend a list. That is the difference between a guard
// for THIS defect and a guard for its class.
//
// # It fails closed, and that is the important property
//
// A statement that writes role-template scopes in a form the model does not
// understand is an ERROR, never a silent skip. A guard that quietly ignores what
// it cannot parse reports "clean" for exactly the migrations most likely to be
// doing something interesting, which is indistinguishable from a guard that is
// not running at all.
//
// The one deliberate exception is `identity.`-qualified statements: that table
// belongs to the shared identity module, is TEXT[] rather than JSONB there, and
// registry's migrations only mirror into it what they have already done to its
// own table. The Go list is compared against the copy registry OWNS.
//
// # What it does not model
//
// Only `scopes`. `display_name` and `description` drift is cosmetic -- it
// changes what the role picker reads, not what a principal may do -- and
// including it would make the guard fire on wording, which is how guards get
// switched off.
package rolepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The two role-template tables registry's OWN migrations write. `role_templates`
// is the one 000001 creates and seeds and is what the default topology
// authorizes against; `registry_role_templates` is registry's per-app copy from
// 000055, created empty and populated at runtime.
const (
	RoleTemplatesTable         = "role_templates"
	RegistryRoleTemplatesTable = "registry_role_templates"
)

// Template is one role template as the migrations leave it.
type Template struct {
	Name     string
	Scopes   []string // sorted, de-duplicated
	IsSystem bool
}

// Policy is one table's role templates, keyed by name.
type Policy map[string]Template

// SystemScopes returns name -> scopes for the system templates only, which is
// the surface models.PredefinedRoleTemplates() states.
func (p Policy) SystemScopes() map[string][]string {
	out := make(map[string][]string, len(p))
	for name, t := range p {
		if t.IsSystem {
			out[name] = append([]string(nil), t.Scopes...)
		}
	}
	return out
}

// UnmodelledError is returned when a migration writes role-template scopes in a
// form this package cannot evaluate. It is a request to teach the model, and it
// deliberately blocks rather than degrading to a pass.
type UnmodelledError struct {
	File   string
	Reason string
	Stmt   string
}

func (e *UnmodelledError) Error() string {
	stmt := strings.Join(strings.Fields(e.Stmt), " ")
	if len(stmt) > 400 {
		stmt = stmt[:400] + " ..."
	}
	return fmt.Sprintf(
		"%s writes role-template scopes in a form internal/db/rolepolicy cannot evaluate (%s). "+
			"This is not a pass: the derived policy would be wrong and the guard comparing it to "+
			"the Go list in models.PredefinedRoleTemplates would be answering about a migration "+
			"it never read. "+
			"Either write the statement in a form the model understands (INSERT ... VALUES, or "+
			"UPDATE ... SET scopes = <jsonb literal | scopes || <literal> | scopes - '<scope>'> "+
			"WHERE <name/is_system/scopes @> conjunction>), or extend rolepolicy to evaluate it. "+
			"Statement: %s", e.File, e.Reason, stmt)
}

// FromMigrations replays every *.up.sql in dir, in version order, and returns
// what they leave in each tracked role-template table.
func FromMigrations(dir string) (map[string]Policy, error) {
	files, err := UpMigrations(dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		// An empty universe is a broken guard, not a clean one.
		return nil, fmt.Errorf("no *.up.sql migrations found under %s", dir)
	}
	state := map[string]Policy{
		RoleTemplatesTable:         {},
		RegistryRoleTemplatesTable: {},
	}
	for _, f := range files {
		body, readErr := os.ReadFile(f.Path)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", f.Path, readErr)
		}
		if applyErr := applyFile(state, f.Name, string(body)); applyErr != nil {
			return nil, applyErr
		}
	}
	return state, nil
}

// Migration is one up-migration file.
type Migration struct {
	Version uint64
	Name    string
	Path    string
}

var migrationNameRe = regexp.MustCompile(`^(\d+)_.*\.up\.sql$`)

// UpMigrations lists dir's up-migrations in version order. Exported because the
// database-backed cross-check needs the head version and must derive it rather
// than carry a number that goes stale on the next migration.
func UpMigrations(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations directory %s: %w", dir, err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationNameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, convErr := strconv.ParseUint(m[1], 10, 64)
		if convErr != nil {
			return nil, fmt.Errorf("migration %s has a non-numeric version: %w", e.Name(), convErr)
		}
		out = append(out, Migration{Version: v, Name: e.Name(), Path: filepath.Join(dir, e.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// HeadVersion is the highest migration version in dir.
func HeadVersion(dir string) (uint64, error) {
	files, err := UpMigrations(dir)
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, fmt.Errorf("no *.up.sql migrations found under %s", dir)
	}
	return files[len(files)-1].Version, nil
}

func applyFile(state map[string]Policy, file, body string) error {
	for _, stmt := range splitStatements(body) {
		if err := applyStatement(state, file, stmt, nil); err != nil {
			return err
		}
	}
	return nil
}

var doBlockRe = regexp.MustCompile(`(?is)^\s*do\s+(\$[a-z0-9_]*\$)`)

func applyStatement(state map[string]Policy, file, stmt string, consts map[string][]string) error {
	// A DO block is a statement whose body is more statements. Recurse into it
	// rather than treating the whole thing as opaque -- migration 000054 does
	// its entire role-template edit inside one.
	if m := doBlockRe.FindStringSubmatch(stmt); m != nil {
		tag := m[1]
		start := strings.Index(stmt, tag) + len(tag)
		end := strings.LastIndex(stmt, tag)
		if end <= start {
			return &UnmodelledError{File: file, Reason: "unterminated DO block", Stmt: stmt}
		}
		inner := stmt[start:end]
		scoped := mergeConstants(consts, declaredJSONConstants(inner))
		for _, sub := range splitStatements(inner) {
			if err := applyStatement(state, file, sub, scoped); err != nil {
				return err
			}
		}
		return nil
	}

	if m := insertRe.FindStringSubmatchIndex(stmt); m != nil {
		schema, table := group(stmt, m, 1), strings.ToLower(group(stmt, m, 2))
		if skipSchema(schema) {
			return nil
		}
		return applyInsert(state[table], file, stmt, stmt[m[1]:])
	}
	if m := updateRe.FindStringSubmatchIndex(stmt); m != nil {
		schema, table := group(stmt, m, 1), strings.ToLower(group(stmt, m, 2))
		if skipSchema(schema) {
			return nil
		}
		return applyUpdate(state[table], file, stmt, stmt[m[1]:], consts)
	}
	if m := deleteRe.FindStringSubmatchIndex(stmt); m != nil {
		schema, table := group(stmt, m, 1), strings.ToLower(group(stmt, m, 2))
		if skipSchema(schema) {
			return nil
		}
		return applyDelete(state[table], file, stmt, stmt[m[1]:])
	}
	if m := truncateRe.FindStringSubmatchIndex(stmt); m != nil {
		schema, table := group(stmt, m, 1), strings.ToLower(group(stmt, m, 2))
		if skipSchema(schema) {
			return nil
		}
		for name := range state[table] {
			delete(state[table], name)
		}
		return nil
	}
	// An ALTER that rewrites the column (ALTER COLUMN scopes TYPE ... USING ...)
	// changes every row's scopes without being DML. Refuse rather than miss it.
	if alterScopesRe.MatchString(stmt) {
		return &UnmodelledError{File: file, Reason: "ALTER TABLE mentioning `scopes`", Stmt: stmt}
	}
	return nil
}

// group returns capture n of a FindStringSubmatchIndex result, or "" when the
// group did not participate -- an optional schema qualifier reports (-1, -1),
// and slicing on that panics.
func group(s string, m []int, n int) string {
	if 2*n+1 >= len(m) || m[2*n] < 0 {
		return ""
	}
	return s[m[2*n]:m[2*n+1]]
}

// skipSchema reports whether a qualified statement targets a table this package
// deliberately does not model. `identity.` is the shared identity module's, and
// registry's migrations only mirror there what they have already done here.
func skipSchema(schema string) bool {
	switch strings.ToLower(schema) {
	case "", "public":
		return false
	default:
		return true
	}
}

const tableAlt = `(role_templates|registry_role_templates)`

var (
	insertRe   = regexp.MustCompile(`(?is)\binsert\s+into\s+(?:([a-z_][a-z0-9_]*)\s*\.\s*)?` + tableAlt + `\b`)
	updateRe   = regexp.MustCompile(`(?is)\bupdate\s+(?:only\s+)?(?:([a-z_][a-z0-9_]*)\s*\.\s*)?` + tableAlt + `\b`)
	deleteRe   = regexp.MustCompile(`(?is)\bdelete\s+from\s+(?:only\s+)?(?:([a-z_][a-z0-9_]*)\s*\.\s*)?` + tableAlt + `\b`)
	truncateRe = regexp.MustCompile(`(?is)\btruncate\s+(?:table\s+)?(?:([a-z_][a-z0-9_]*)\s*\.\s*)?` + tableAlt + `\b`)

	alterScopesRe = regexp.MustCompile(`(?is)\balter\s+table\s+(?:only\s+)?(?:[a-z_][a-z0-9_]*\s*\.\s*)?` +
		tableAlt + `\b[^;]*\bscopes\b`)
)

// ---------------------------------------------------------------------------
// INSERT
// ---------------------------------------------------------------------------

func applyInsert(p Policy, file, stmt, rest string) error {
	cols, after, ok := parenGroup(rest)
	if !ok {
		return &UnmodelledError{File: file, Reason: "INSERT without an explicit column list", Stmt: stmt}
	}
	colNames := make([]string, 0, 8)
	for _, c := range splitTopLevel(cols, ',') {
		colNames = append(colNames, strings.ToLower(strings.TrimSpace(c)))
	}

	after = strings.TrimSpace(after)
	if !hasLeadingKeyword(after, "values") {
		return &UnmodelledError{File: file, Reason: "INSERT ... SELECT, or a VALUES clause this model cannot find", Stmt: stmt}
	}
	after = strings.TrimSpace(after[len("values"):])

	// ON CONFLICT changes what the statement means; only DO NOTHING is modelled,
	// because that is the only arm whose effect does not need an EXCLUDED row.
	tail := ""
	if idx := indexTopLevelKeyword(after, "on conflict"); idx >= 0 {
		tail = after[idx:]
		after = after[:idx]
	}
	if tail != "" && indexTopLevelKeyword(strings.ToLower(tail), "do nothing") < 0 {
		return &UnmodelledError{File: file, Reason: "ON CONFLICT DO UPDATE", Stmt: stmt}
	}
	if idx := indexTopLevelKeyword(after, "returning"); idx >= 0 {
		after = after[:idx]
	}

	for len(strings.TrimSpace(after)) > 0 {
		tuple, next, tOK := parenGroup(after)
		if !tOK {
			return &UnmodelledError{File: file, Reason: "malformed VALUES tuple", Stmt: stmt}
		}
		vals := splitTopLevel(tuple, ',')
		if len(vals) != len(colNames) {
			return &UnmodelledError{File: file, Reason: "VALUES tuple does not match the column list", Stmt: stmt}
		}
		t := Template{}
		for i, col := range colNames {
			raw := strings.TrimSpace(vals[i])
			switch col {
			case "name":
				s, sOK := stringLiteral(raw)
				if !sOK {
					return &UnmodelledError{File: file, Reason: "non-literal `name`", Stmt: stmt}
				}
				t.Name = s
			case "scopes":
				scopes, sOK := jsonArrayLiteral(raw)
				if !sOK {
					return &UnmodelledError{File: file, Reason: "non-literal `scopes`", Stmt: stmt}
				}
				t.Scopes = scopes
			case "is_system":
				b, bOK := boolLiteral(raw)
				if !bOK {
					return &UnmodelledError{File: file, Reason: "non-literal `is_system`", Stmt: stmt}
				}
				t.IsSystem = b
			}
		}
		if t.Name == "" {
			return &UnmodelledError{File: file, Reason: "INSERT does not set `name`", Stmt: stmt}
		}
		if _, exists := p[t.Name]; !exists || tail == "" {
			t.Scopes = normalize(t.Scopes)
			p[t.Name] = t
		}
		after = strings.TrimSpace(next)
		after = strings.TrimPrefix(after, ",")
	}
	return nil
}

// ---------------------------------------------------------------------------
// UPDATE
// ---------------------------------------------------------------------------

func applyUpdate(p Policy, file, stmt, rest string, consts map[string][]string) error {
	setIdx := indexTopLevelKeyword(rest, "set")
	if setIdx < 0 {
		return &UnmodelledError{File: file, Reason: "UPDATE with no SET this model can find", Stmt: stmt}
	}
	alias := strings.TrimSpace(rest[:setIdx])
	alias = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(alias), "as"))
	body := rest[setIdx+len("set"):]

	if fromIdx := indexTopLevelKeyword(body, "from"); fromIdx >= 0 {
		if whereIdx := indexTopLevelKeyword(body, "where"); whereIdx < 0 || fromIdx < whereIdx {
			return &UnmodelledError{File: file, Reason: "UPDATE ... FROM", Stmt: stmt}
		}
	}
	assignments := body
	where := ""
	if whereIdx := indexTopLevelKeyword(body, "where"); whereIdx >= 0 {
		assignments = body[:whereIdx]
		where = body[whereIdx+len("where"):]
	}
	if retIdx := indexTopLevelKeyword(where, "returning"); retIdx >= 0 {
		where = where[:retIdx]
	}

	var scopeExpr string
	found := false
	for _, a := range splitTopLevel(assignments, ',') {
		eq := indexTopLevelRune(a, '=')
		if eq < 0 {
			return &UnmodelledError{File: file, Reason: "SET item that is not `col = expr`", Stmt: stmt}
		}
		col := strings.ToLower(strings.TrimSpace(a[:eq]))
		col = strings.TrimPrefix(col, strings.ToLower(alias)+".")
		if col == "scopes" {
			scopeExpr = a[eq+1:]
			found = true
		}
	}
	// An UPDATE that never assigns `scopes` cannot move the policy, whatever
	// else it does, so it needs no model at all.
	if !found {
		return nil
	}

	names, ok := evalWhere(p, where)
	if !ok {
		return &UnmodelledError{File: file, Reason: "WHERE clause this model cannot evaluate", Stmt: stmt}
	}
	// A statement that selects nothing changes nothing, so its right-hand side
	// never has to be understood. That is what lets migration 000054's second,
	// jsonb_agg-shaped UPDATE be modelled exactly: by the time it runs, its own
	// `scopes @> '["admin"]'` predicate matches no template.
	if len(names) == 0 {
		return nil
	}
	for _, name := range names {
		t := p[name]
		next, err := evalScopeExpr(t.Scopes, scopeExpr, consts)
		if err != nil {
			return &UnmodelledError{File: file, Reason: "SET scopes = " + strings.Join(strings.Fields(scopeExpr), " "), Stmt: stmt}
		}
		t.Scopes = normalize(next)
		p[name] = t
	}
	return nil
}

func applyDelete(p Policy, file, stmt, rest string) error {
	where := ""
	if whereIdx := indexTopLevelKeyword(rest, "where"); whereIdx >= 0 {
		where = rest[whereIdx+len("where"):]
	}
	names, ok := evalWhere(p, where)
	if !ok {
		return &UnmodelledError{File: file, Reason: "DELETE with a WHERE clause this model cannot evaluate", Stmt: stmt}
	}
	for _, n := range names {
		delete(p, n)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Expression and predicate evaluation
// ---------------------------------------------------------------------------

var errUnmodelled = errors.New("unmodelled expression")

var (
	concatLeftRe   = regexp.MustCompile(`(?is)^\s*(?:[a-z_][a-z0-9_]*\s*\.\s*)?scopes\s*\|\|\s*(.+?)\s*$`)
	concatRightRe  = regexp.MustCompile(`(?is)^\s*(.+?)\s*\|\|\s*(?:[a-z_][a-z0-9_]*\s*\.\s*)?scopes\s*$`)
	minusRe        = regexp.MustCompile(`(?is)^\s*(?:[a-z_][a-z0-9_]*\s*\.\s*)?scopes\s*-\s*(.+?)\s*$`)
	identRe        = regexp.MustCompile(`(?is)^\s*([a-z_][a-z0-9_]*)\s*$`)
	arrayLiteralRe = regexp.MustCompile(`(?is)^array\s*\[(.*)\]$`)
	castedJSONBRe  = regexp.MustCompile(`(?is)::\s*jsonb\s*$`)
)

func evalScopeExpr(cur []string, expr string, consts map[string][]string) ([]string, error) {
	expr = strings.TrimSpace(expr)
	if lit, ok := jsonArrayLiteral(expr); ok {
		return lit, nil
	}
	if m := identRe.FindStringSubmatch(expr); m != nil {
		if v, ok := consts[strings.ToLower(m[1])]; ok {
			return append([]string(nil), v...), nil
		}
		return nil, errUnmodelled
	}
	if m := concatLeftRe.FindStringSubmatch(expr); m != nil {
		add, err := evalScopeOperand(m[1], consts)
		if err != nil {
			return nil, err
		}
		return append(append([]string(nil), cur...), add...), nil
	}
	if m := concatRightRe.FindStringSubmatch(expr); m != nil {
		add, err := evalScopeOperand(m[1], consts)
		if err != nil {
			return nil, err
		}
		return append(append([]string(nil), add...), cur...), nil
	}
	if m := minusRe.FindStringSubmatch(expr); m != nil {
		// `jsonb - text` removes one element, `jsonb - text[]` removes several.
		// There is no `jsonb - jsonb`, so a jsonb-cast operand is NOT a set of
		// keys to remove and must not be read as one -- reading it that way
		// silently removed nothing, which is the direction that leaves a scope
		// in the derived policy that the database does not have.
		drop, dErr := textOperandList(strings.TrimSpace(m[1]))
		if dErr != nil {
			return nil, dErr
		}
		out := make([]string, 0, len(cur))
		for _, s := range cur {
			if !contains(drop, s) {
				out = append(out, s)
			}
		}
		return out, nil
	}
	return nil, errUnmodelled
}

// textOperandList reads the right-hand side of `scopes - X`: a single text
// literal, or an ARRAY[...] of them. Anything else is refused.
func textOperandList(expr string) ([]string, error) {
	expr = strings.TrimSpace(expr)
	if m := arrayLiteralRe.FindStringSubmatch(expr); m != nil {
		var out []string
		for _, item := range splitTopLevel(m[1], ',') {
			s, ok := stringLiteral(strings.TrimSpace(item))
			if !ok {
				return nil, errUnmodelled
			}
			out = append(out, s)
		}
		return out, nil
	}
	// A jsonb-cast operand is not a key list; refuse rather than misread it.
	if castedJSONBRe.MatchString(expr) {
		return nil, errUnmodelled
	}
	if s, ok := stringLiteral(expr); ok {
		return []string{s}, nil
	}
	return nil, errUnmodelled
}

func evalScopeOperand(expr string, consts map[string][]string) ([]string, error) {
	if lit, ok := jsonArrayLiteral(expr); ok {
		return lit, nil
	}
	if m := identRe.FindStringSubmatch(expr); m != nil {
		if v, ok := consts[strings.ToLower(m[1])]; ok {
			return append([]string(nil), v...), nil
		}
	}
	return nil, errUnmodelled
}

var (
	predNameEqRe    = regexp.MustCompile(`(?is)^(?:[a-z_][a-z0-9_]*\s*\.\s*)?name\s*=\s*('(?:[^']|'')*')$`)
	predNameNeRe    = regexp.MustCompile(`(?is)^(?:[a-z_][a-z0-9_]*\s*\.\s*)?name\s*(?:<>|!=)\s*('(?:[^']|'')*')$`)
	predIsSystemRe  = regexp.MustCompile(`(?is)^(?:[a-z_][a-z0-9_]*\s*\.\s*)?is_system\s*=\s*(true|false)$`)
	predIsSystemBRe = regexp.MustCompile(`(?is)^(?:[a-z_][a-z0-9_]*\s*\.\s*)?is_system\s+is\s+(true|false)$`)
	predContainsRe  = regexp.MustCompile(`(?is)^(?:[a-z_][a-z0-9_]*\s*\.\s*)?scopes\s*@>\s*(.+)$`)
	predNameInRe    = regexp.MustCompile(`(?is)^(?:[a-z_][a-z0-9_]*\s*\.\s*)?name\s+in\s*\((.*)\)$`)
)

// evalWhere returns the template names the predicate selects. ok is false when
// any conjunct is not understood -- never "assume it matches nothing", which
// would turn an unreadable migration into a silent pass.
func evalWhere(p Policy, where string) (names []string, ok bool) {
	where = strings.TrimSpace(where)
	candidates := make([]string, 0, len(p))
	for name := range p {
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)
	if where == "" {
		return candidates, true
	}
	if indexTopLevelKeyword(where, "or") >= 0 {
		return nil, false
	}
	for _, conj := range splitTopLevelKeyword(where, "and") {
		conj = strings.TrimSpace(conj)
		for strings.HasPrefix(conj, "(") && strings.HasSuffix(conj, ")") {
			inner, rest, gOK := parenGroup(conj)
			if !gOK || strings.TrimSpace(rest) != "" {
				break
			}
			conj = strings.TrimSpace(inner)
		}
		pred, pOK := compilePredicate(conj)
		if !pOK {
			return nil, false
		}
		kept := candidates[:0:0]
		for _, name := range candidates {
			if pred(p[name]) {
				kept = append(kept, name)
			}
		}
		candidates = kept
	}
	return candidates, true
}

func compilePredicate(conj string) (func(Template) bool, bool) {
	if m := predNameEqRe.FindStringSubmatch(conj); m != nil {
		want, ok := stringLiteral(m[1])
		if !ok {
			return nil, false
		}
		return func(t Template) bool { return t.Name == want }, true
	}
	if m := predNameNeRe.FindStringSubmatch(conj); m != nil {
		want, ok := stringLiteral(m[1])
		if !ok {
			return nil, false
		}
		return func(t Template) bool { return t.Name != want }, true
	}
	if m := predIsSystemRe.FindStringSubmatch(conj); m != nil {
		want := strings.EqualFold(m[1], "true")
		return func(t Template) bool { return t.IsSystem == want }, true
	}
	if m := predIsSystemBRe.FindStringSubmatch(conj); m != nil {
		want := strings.EqualFold(m[1], "true")
		return func(t Template) bool { return t.IsSystem == want }, true
	}
	if m := predNameInRe.FindStringSubmatch(conj); m != nil {
		var want []string
		for _, item := range splitTopLevel(m[1], ',') {
			s, ok := stringLiteral(strings.TrimSpace(item))
			if !ok {
				return nil, false
			}
			want = append(want, s)
		}
		return func(t Template) bool { return contains(want, t.Name) }, true
	}
	if m := predContainsRe.FindStringSubmatch(conj); m != nil {
		want, ok := jsonArrayLiteral(m[1])
		if !ok {
			return nil, false
		}
		return func(t Template) bool {
			for _, w := range want {
				if !contains(t.Scopes, w) {
					return false
				}
			}
			return true
		}, true
	}
	return nil, false
}

// declaredJSONConstants picks up `<name> CONSTANT jsonb := '<literal>'::jsonb`
// from a plpgsql DECLARE section. CONSTANT only: a plain variable can be
// reassigned later in the block, and this package does not execute control flow.
var declaredConstRe = regexp.MustCompile(
	`(?is)\b([a-z_][a-z0-9_]*)\s+constant\s+jsonb\s*:=\s*('(?:[^']|'')*')\s*::\s*jsonb`)

func declaredJSONConstants(body string) map[string][]string {
	out := map[string][]string{}
	for _, m := range declaredConstRe.FindAllStringSubmatch(body, -1) {
		if arr, ok := jsonArrayLiteral(m[2]); ok {
			out[strings.ToLower(m[1])] = arr
		}
	}
	return out
}

func mergeConstants(outer, inner map[string][]string) map[string][]string {
	out := make(map[string][]string, len(outer)+len(inner))
	for k, v := range outer {
		out[k] = v
	}
	for k, v := range inner {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Literals
// ---------------------------------------------------------------------------

var castSuffixRe = regexp.MustCompile(`(?is)\s*::\s*[a-z_][a-z0-9_]*(\s*\[\s*\])?\s*$`)

func stripCasts(s string) string {
	s = strings.TrimSpace(s)
	for {
		next := castSuffixRe.ReplaceAllString(s, "")
		if next == s {
			return strings.TrimSpace(s)
		}
		s = strings.TrimSpace(next)
	}
}

func stringLiteral(raw string) (string, bool) {
	s := stripCasts(raw)
	if len(s) < 2 || s[0] != '\'' || s[len(s)-1] != '\'' {
		return "", false
	}
	inner := s[1 : len(s)-1]
	// A lone quote inside would mean this is two literals, not one.
	if strings.Contains(strings.ReplaceAll(inner, "''", ""), "'") {
		return "", false
	}
	return strings.ReplaceAll(inner, "''", "'"), true
}

func jsonArrayLiteral(raw string) ([]string, bool) {
	s, ok := stringLiteral(raw)
	if !ok {
		return nil, false
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil, false
	}
	return arr, true
}

func boolLiteral(raw string) (bool, bool) {
	switch strings.ToLower(stripCasts(raw)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// normalize sorts and de-duplicates. Postgres' `||` on jsonb arrays appends
// without de-duplicating, so a re-granted scope can appear twice in the real
// column; a repeated scope confers nothing extra, and comparing sets rather
// than sequences keeps the guard about authority instead of about ordering.
func normalize(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Normalize is normalize, for callers comparing a database's or the Go list's
// scopes against a derived policy on the same terms.
func Normalize(in []string) []string { return normalize(in) }
