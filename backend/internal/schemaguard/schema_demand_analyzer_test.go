package schemaguard

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file is the reusable half of the guard: a DDL replayer, a DML write
// extractor, and the resolver that decides whether a write can land. It has no
// opinion about this repository — schema_demand_guard_test.go supplies the
// migration streams, the search_path and the source roots.
//
// Keeping the two apart is deliberate. The analyzer is exercised below against
// hand-written fixtures whose expected answers are obvious, including the
// empty-universe falsification; the guard proper is exercised against the real
// tree. A single fused test would have had no way to prove the analyzer says
// anything at all when handed nothing.

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

var (
	// errNoDDL means a migration stream contributed no CREATE TABLE at all.
	// Certifying against an empty schema universe would pass every write
	// vacuously, so this is fatal rather than "zero violations found".
	errNoDDL = errors.New("schemaguard: migration stream produced no tables; refusing to certify against an empty schema universe")
	// errNoWrites means the source scan found no INSERT/UPDATE/DELETE at all.
	// Same reasoning in the other direction: a guard that inspected zero
	// writes has proved nothing.
	errNoWrites = errors.New("schemaguard: source scan found no SQL writes; refusing to certify with nothing to check")
	// errNoSearchPath means the resolver was handed an empty schema list, so
	// no unqualified name could ever resolve.
	errNoSearchPath = errors.New("schemaguard: empty search_path; refusing to certify")
)

// ---------------------------------------------------------------------------
// The schema model
// ---------------------------------------------------------------------------

// tableKey identifies a table by schema and name. Schema is always populated:
// unqualified DDL is resolved against the owning stream's default schema when
// it is replayed, not left ambiguous.
type tableKey struct {
	Schema string
	Table  string
}

func (k tableKey) String() string { return k.Schema + "." + k.Table }

// fkKey identifies a foreign key by the table and columns it constrains.
//
// Keyed on the CONSTRAINED side rather than on the constraint name, because the
// defect this exists to catch is one constraint being pointed at two different
// schemas in two topologies -- and in the migration that does it, the arms
// carry different names.
type fkKey struct {
	Table   tableKey
	Columns string // unquoted, sorted, comma-joined
}

func (k fkKey) String() string { return k.Table.String() + "(" + k.Columns + ")" }

// fkTarget is one possible referent of a foreign key.
//
// POSSIBLE, not actual. A migration that chooses its target inside a DO block
// contributes one target per arm, and this analyzer deliberately does not
// evaluate the branch -- see the fifth arm of applySQL. Unresolved marks a
// target this analyzer could not parse at all, which is a stronger signal than
// a competing pair: a migration computing its target at runtime cannot be
// checked by anything static.
type fkTarget struct {
	Schema     string
	Table      string
	Unresolved bool
	Certain    bool
	Origin     string // migration file, for the report
}

// migrationSearchPath is the schema an unqualified name in a MIGRATION resolves
// to, and it is "public" in every topology.
//
// Migrations always run on GetMigrationDSN(), which emits no search_path
// option, while the APPLICATION may resolve identity names at "identity". That
// split is the mechanical root of this whole defect class: a constraint written
// by a migration and a row written by the application can disagree about which
// schema they mean, and every column involved still exists.
const migrationSearchPath = "public"

// schemaModel is the state of the world after replaying a set of migrations.
type schemaModel struct {
	// columns holds the column set of every table whose shape is known.
	columns map[tableKey]map[string]bool
	// fks records, per constrained (table, columns), every target the
	// migration stream could have pointed it at. A singleton is the healthy
	// case; more than one distinct target SCHEMA is the #883 defect.
	fks map[fkKey][]fkTarget
	// fkNames maps a key to every constraint name it has been created under,
	// so a later DROP CONSTRAINT can find it. A key can carry several names
	// because the conditional arms of one DO block name their constraints
	// differently.
	fkNames map[fkKey]map[string]bool
	// opaque holds relations that exist but whose column set this analyzer
	// declines to model — views, CREATE TABLE AS SELECT. Writes to these are
	// checked for existence only. Modelling a view's columns would mean
	// resolving its SELECT list, which is out of scope (see the boundary
	// section of schema_demand_guard_test.go).
	opaque map[tableKey]bool
}

func newSchemaModel() *schemaModel {
	return &schemaModel{
		columns: map[tableKey]map[string]bool{},
		opaque:  map[tableKey]bool{},
		fks:     map[fkKey][]fkTarget{},
		fkNames: map[fkKey]map[string]bool{},
	}
}

func (m *schemaModel) tableCount() int { return len(m.columns) + len(m.opaque) }

func (m *schemaModel) has(k tableKey) bool {
	if _, ok := m.columns[k]; ok {
		return true
	}
	return m.opaque[k]
}

// ---------------------------------------------------------------------------
// SQL lexing helpers
// ---------------------------------------------------------------------------

var (
	lineComment  = regexp.MustCompile(`--[^\n]*`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	wsRun        = regexp.MustCompile(`\s+`)
)

// stripComments removes SQL comments. Dollar-quoted bodies are left alone by
// splitStatements, so a `--` inside a DO $$ block is not a concern here: the
// whole block is one statement and the DDL matchers below do not fire on it.
func stripComments(s string) string {
	s = blockComment.ReplaceAllString(s, " ")
	return lineComment.ReplaceAllString(s, " ")
}

// splitStatements splits SQL on top-level semicolons, honouring single-quoted
// strings and dollar-quoted bodies ($$ ... $$ and $tag$ ... $tag$). A naive
// strings.Split(";") would shred every DO block in this repository's
// migrations, and five of them contain semicolons.
func splitStatements(sql string) []string {
	var out []string
	var cur strings.Builder
	i := 0
	for i < len(sql) {
		switch sql[i] {
		case '\'':
			j := i + 1
			for j < len(sql) {
				if sql[j] == '\'' {
					if j+1 < len(sql) && sql[j+1] == '\'' { // escaped ''
						j += 2
						continue
					}
					break
				}
				j++
			}
			if j >= len(sql) {
				j = len(sql) - 1
			}
			cur.WriteString(sql[i : j+1])
			i = j + 1
		case '$':
			if tag, ok := dollarTag(sql, i); ok {
				end := strings.Index(sql[i+len(tag):], tag)
				if end < 0 {
					cur.WriteString(sql[i:])
					i = len(sql)
					continue
				}
				stop := i + len(tag) + end + len(tag)
				cur.WriteString(sql[i:stop])
				i = stop
				continue
			}
			cur.WriteByte(sql[i])
			i++
		case ';':
			out = append(out, cur.String())
			cur.Reset()
			i++
		default:
			cur.WriteByte(sql[i])
			i++
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

// dollarTag reports the dollar-quote tag starting at i, e.g. "$$" or "$fn$".
func dollarTag(s string, i int) (string, bool) {
	if s[i] != '$' {
		return "", false
	}
	j := i + 1
	for j < len(s) && (s[j] == '_' || isIdentByte(s[j])) {
		j++
	}
	if j < len(s) && s[j] == '$' {
		return s[i : j+1], true
	}
	return "", false
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// normalize collapses whitespace so the statement matchers can be written
// against single-spaced text.
func normalize(s string) string { return strings.TrimSpace(wsRun.ReplaceAllString(s, " ")) }

// splitTopLevel splits on commas that are not inside parentheses.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// parenBody returns the contents of the parenthesised group that starts at the
// first '(' in s, balanced.
func parenBody(s string) (string, bool) {
	open := strings.Index(s, "(")
	if open < 0 {
		return "", false
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], true
			}
		}
	}
	return "", false
}

// unquoteIdent lowercases a bare identifier and strips SQL double quotes.
// Postgres folds unquoted identifiers to lower case; this repository quotes
// exactly one column ("references" in 000032), so the two paths must agree.
func unquoteIdent(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return strings.ToLower(s)
}

// parseName splits an optionally schema-qualified relation name, applying
// defaultSchema when the name carries none.
func parseName(raw, defaultSchema string) tableKey {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, "(")
	parts := strings.Split(raw, ".")
	if len(parts) >= 2 {
		return tableKey{Schema: unquoteIdent(parts[len(parts)-2]), Table: unquoteIdent(parts[len(parts)-1])}
	}
	return tableKey{Schema: defaultSchema, Table: unquoteIdent(raw)}
}

// ---------------------------------------------------------------------------
// DDL replay
// ---------------------------------------------------------------------------

var (
	reCreateTable = regexp.MustCompile(`(?i)^CREATE\s+(?:UNLOGGED\s+|TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w".]+)`)
	// reCreateTableAnywhere is the cheap pre-filter used to pick Go string
	// literals worth parsing as DDL.
	reCreateTableAnywhere = regexp.MustCompile(`(?i)\bCREATE\s+(?:UNLOGGED\s+|TEMP\s+|TEMPORARY\s+)?TABLE\b`)
	reCreateView          = regexp.MustCompile(`(?i)^CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w".]+)`)
	reDropTable           = regexp.MustCompile(`(?i)^DROP\s+(?:MATERIALIZED\s+)?(?:TABLE|VIEW)\s+(?:IF\s+EXISTS\s+)?(.+?)(?:\s+CASCADE|\s+RESTRICT)?$`)
	// reDoOpen matches the opening of a dollar-quoted DO block.
	//
	// Only the OPENING. Go's regexp is RE2 and has NO BACKREFERENCES, so the
	// natural `(\$[A-Za-z_]*\$)(.*)\1` does not compile -- it panics at
	// MustCompile. The closing tag is found by string search instead, which is
	// what a dollar-quote is anyway.
	reDoOpen = regexp.MustCompile(`(?is)^DO\s+(\$[A-Za-z_]*\$)`)
	// reAddConstraintFK matches ADD CONSTRAINT <name> FOREIGN KEY (<cols>)
	// TARGET-AGNOSTICALLY: the REFERENCES clause is parsed separately so a
	// target this analyzer cannot read becomes Unresolved rather than being
	// dropped on the floor. A migration that computes its FK target is the same
	// defect wearing a different hat, and silently skipping it would hide
	// exactly that.
	reAddConstraintFK = regexp.MustCompile(`(?is)^ADD\s+CONSTRAINT\s+([\w".]+)\s+FOREIGN\s+KEY\s*\(([^)]*)\)\s*(.*)$`)
	reReferences      = regexp.MustCompile(`(?is)\bREFERENCES\s+([\w".]+)\s*(?:\(|$|\s)`)
	reDropConstraint  = regexp.MustCompile(`(?is)^DROP\s+CONSTRAINT\s+(?:IF\s+EXISTS\s+)?([\w".]+)`)
	// reDDLLeader finds where the DDL actually starts inside a PL/pgSQL
	// statement.
	//
	// WHY THIS IS NEEDED, and it is not cosmetic. splitStatements splits on
	// ";", and PL/pgSQL control flow carries no semicolon of its own -- so the
	// FIRST statement after THEN or ELSE arrives glued to its prefix:
	//
	//	"BEGIN IF EXISTS (...) THEN ALTER TABLE ... ADD CONSTRAINT ..."
	//	"ELSE ALTER TABLE ... ADD CONSTRAINT ..."
	//
	// Neither matches ^ALTER TABLE, so the first constraint in each arm was
	// invisible while every subsequent one was seen. Against the real migration
	// stream that lost exactly namespace_claims(organization_id) -- the
	// constraint issue #883 is ABOUT -- while still reporting 23 others, which
	// is the most dangerous possible failure: a guard that looks like it works.
	reDDLLeader  = regexp.MustCompile(`(?is)\b(ALTER\s+TABLE|CREATE\s+TABLE|DROP\s+TABLE)\b`)
	reAlterTable = regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w".]+)\s+(.*)$`)

	reRenameColumn = regexp.MustCompile(`(?i)^RENAME\s+COLUMN\s+([\w"]+)\s+TO\s+([\w"]+)`)
	reRenameTable  = regexp.MustCompile(`(?i)^RENAME\s+TO\s+([\w"]+)`)
	reAddColumn    = regexp.MustCompile(`(?i)^ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([\w"]+)`)
	reDropColumn   = regexp.MustCompile(`(?i)^DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?([\w"]+)`)
)

// tableConstraintLeaders are the words that start a table-level constraint in a
// CREATE TABLE body or an ALTER TABLE ADD action. Anything led by one of these
// is not a column.
var tableConstraintLeaders = map[string]bool{
	"constraint": true, "primary": true, "unique": true, "foreign": true,
	"check": true, "exclude": true, "like": true, "generated": true,
}

// migrationStream is one ordered set of .up.sql files that some configuration
// may or may not apply.
type migrationStream struct {
	// Name is how the stream is reported in failures.
	Name string
	// Dir holds the *.up.sql files.
	Dir string
	// DefaultSchema qualifies unqualified DDL in this stream.
	DefaultSchema string
}

// replay applies every *.up.sql in the stream, in filename order, onto m.
// Filename order is migration order: golang-migrate requires the zero-padded
// numeric prefix, so a lexical sort is the applied sequence.
func (m *schemaModel) replay(stream migrationStream) error {
	entries, err := os.ReadDir(stream.Dir)
	if err != nil {
		return fmt.Errorf("schemaguard: read migration dir %s: %w", stream.Dir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("%w (stream %q, dir %s)", errNoDDL, stream.Name, stream.Dir)
	}
	sort.Strings(files)
	for _, name := range files {
		b, rErr := os.ReadFile(filepath.Join(stream.Dir, name)) // #nosec G304 -- test-only; path is a repo-relative migration directory
		if rErr != nil {
			return fmt.Errorf("schemaguard: read %s: %w", name, rErr)
		}
		m.applyStatements(splitStatements(stripComments(string(b))), stream.DefaultSchema, true, name)
	}
	return nil
}

// applySQL replays the DDL in one SQL blob.
func (m *schemaModel) applySQL(sql, defaultSchema string) {
	m.applyStatements(splitStatements(stripComments(sql)), defaultSchema, true, "")
}

// applyStatements replays statements, tracking whether their effects are
// CERTAIN (top level) or merely POSSIBLE (inside a conditional DO block).
//
// THE EXISTENCE MODEL ONLY ACCEPTS CERTAIN EFFECTS. Crediting a conditional
// CREATE TABLE into m.columns could only ever HIDE a write violation -- the
// same reasoning as creditRuntimeDDL's creations-only rule. The FK ledger is
// the opposite: it wants every possible target, because a target that exists in
// only one topology is precisely what it is looking for.
func (m *schemaModel) applyStatements(stmts []string, defaultSchema string, certain bool, origin string) {
	for _, raw := range stmts {
		stmt := normalize(raw)
		if stmt == "" {
			continue
		}
		// A DO block: descend, marking everything inside as possible.
		//
		// NO ARM TRACKING, deliberately. Every statement in the body is
		// "possible", which over-approximates -- and that is both cheaper and
		// strictly more robust than splitting IF/ELSIF/ELSE: it covers the
		// EXCEPTION-handler shape and the CASE shape for free, and it produces
		// no false positives, because a block that points one constraint at one
		// schema still yields a singleton set.
		if mm := reDoOpen.FindStringSubmatch(stmt); mm != nil {
			tag := mm[1]
			rest := stmt[len(mm[0]):]
			if end := strings.LastIndex(rest, tag); end >= 0 {
				m.applyStatements(splitStatements(rest[:end]), defaultSchema, false, origin)
			}
			continue
		}
		if !certain {
			// Inside a conditional: the ledger still wants ALTER TABLE effects,
			// but nothing may touch the existence model.
			//
			// Re-anchored past the PL/pgSQL control-flow prefix first -- see
			// reDDLLeader for why the first statement in each arm arrives
			// carrying its BEGIN/IF/ELSE.
			body := reAnchorDDL(stmt)
			if reAlterTable.MatchString(body) {
				am := reAlterTable.FindStringSubmatch(body)
				m.applyAlterTableFKs(parseName(am[1], defaultSchema), am[2], false, origin)
			}
			continue
		}
		switch {
		case reCreateTable.MatchString(stmt):
			m.applyCreateTable(stmt, defaultSchema, origin)
		case reCreateView.MatchString(stmt):
			key := parseName(reCreateView.FindStringSubmatch(stmt)[1], defaultSchema)
			delete(m.columns, key)
			m.opaque[key] = true
		case reDropTable.MatchString(stmt):
			for _, n := range splitTopLevel(reDropTable.FindStringSubmatch(stmt)[1]) {
				key := parseName(n, defaultSchema)
				delete(m.columns, key)
				delete(m.opaque, key)
			}
		case reAlterTable.MatchString(stmt):
			mm := reAlterTable.FindStringSubmatch(stmt)
			key := parseName(mm[1], defaultSchema)
			m.applyAlterTable(key, mm[2])
			m.applyAlterTableFKs(key, mm[2], true, origin)
		}
	}
}

func (m *schemaModel) applyCreateTable(stmt, defaultSchema, origin string) {
	key := parseName(reCreateTable.FindStringSubmatch(stmt)[1], defaultSchema)
	body, ok := parenBody(stmt)
	if !ok {
		// CREATE TABLE ... AS SELECT, or PARTITION OF: shape not modelled.
		m.opaque[key] = true
		return
	}
	cols := map[string]bool{}
	for _, item := range splitTopLevel(body) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		first := strings.ToLower(strings.Trim(strings.Fields(item)[0], `"`))
		if tableConstraintLeaders[first] {
			// A table-level constraint. Not a column -- but it may be a
			// FOREIGN KEY, which the ledger wants. This arm used to discard
			// the item entirely.
			m.recordCreateTableFK(key, item, origin)
			continue
		}
		name := unquoteIdent(strings.Fields(item)[0])
		cols[name] = true
		// An inline column REFERENCES is a single-column foreign key. It
		// carries no explicit name, so the implicit one PostgreSQL would
		// generate is synthesized -- that is what a later DROP CONSTRAINT
		// names, and 000056 drops several of these.
		if reReferences.MatchString(item) {
			fk := fkKey{Table: key, Columns: name}
			m.recordFK(fk, key.Table+"_"+name+"_fkey", parseFKTarget(item, origin, true), true)
		}
	}
	delete(m.opaque, key)
	m.columns[key] = cols
}

// applyAlterTableFKs records foreign-key effects into the ledger.
//
// Separate from applyAlterTable because the two answer different questions and
// obey opposite rules about certainty: the existence model takes only certain
// effects, the ledger wants every possible one.
// reAnchorDDL returns stmt from its first DDL leader onward, or stmt unchanged
// when it contains none.
//
// Only used on statements from inside a DO body: at top level a statement
// already starts with its own verb, and re-anchoring there would let a stray
// "ALTER TABLE" in some other construct be read as one.
func reAnchorDDL(stmt string) string {
	if loc := reDDLLeader.FindStringIndex(stmt); loc != nil {
		return stmt[loc[0]:]
	}
	return stmt
}

// recordCreateTableFK captures a table-level FOREIGN KEY inside CREATE TABLE.
//
// Named constraints ("CONSTRAINT x FOREIGN KEY (...)") and unnamed ones
// ("FOREIGN KEY (...)") both land here; the unnamed form gets the implicit name
// PostgreSQL would generate, so a later DROP CONSTRAINT can find it.
func (m *schemaModel) recordCreateTableFK(key tableKey, item, origin string) {
	fields := strings.Fields(item)
	lower := strings.ToLower(item)
	if !strings.Contains(lower, "foreign key") {
		return
	}
	name := ""
	if strings.EqualFold(fields[0], "constraint") && len(fields) > 1 {
		name = unquoteIdent(fields[1])
	}
	cols, ok := parenBody(item)
	if !ok {
		return
	}
	fk := fkKey{Table: key, Columns: normalizeFKColumns(cols)}
	if name == "" {
		name = key.Table + "_" + strings.ReplaceAll(fk.Columns, ",", "_") + "_fkey"
	}
	// The REFERENCES clause is whatever follows the constrained column list.
	rest := item
	if i := strings.Index(lower, "references"); i >= 0 {
		rest = item[i:]
	}
	m.recordFK(fk, name, parseFKTarget(rest, origin, true), true)
}

func (m *schemaModel) applyAlterTableFKs(key tableKey, actions string, certain bool, origin string) {
	for _, action := range splitTopLevel(actions) {
		action = strings.TrimSpace(action)
		switch {
		case reAddConstraintFK.MatchString(action):
			mm := reAddConstraintFK.FindStringSubmatch(action)
			name := unquoteIdent(mm[1])
			fk := fkKey{Table: key, Columns: normalizeFKColumns(mm[2])}
			m.recordFK(fk, name, parseFKTarget(mm[3], origin, certain), certain)

		case reDropConstraint.MatchString(action):
			// A POSSIBLE drop is a NO-OP, and this is the rule that makes the
			// whole ledger work.
			//
			// Dropping a constraint in one arm of a conditional leaves it alive
			// in the complementary arm, so the target it pointed at is still
			// possible. Treating a possible drop as a real one would let a
			// migration that repoints a constraint under a condition look like
			// a migration that simply moved it -- which is exactly the shape of
			// 000038, and exactly the defect being hunted.
			if !certain {
				continue
			}
			m.dropFKByName(unquoteIdent(reDropConstraint.FindStringSubmatch(action)[1]))
		}
	}
}

// recordFK adds a target. A CERTAIN add replaces the possibility set: the
// migration has stated, unconditionally, what this constraint now points at. A
// POSSIBLE add appends, because it is one of several worlds.
func (m *schemaModel) recordFK(fk fkKey, name string, tgt fkTarget, certain bool) {
	if certain {
		m.fks[fk] = []fkTarget{tgt}
	} else {
		m.fks[fk] = append(m.fks[fk], tgt)
	}
	if m.fkNames[fk] == nil {
		m.fkNames[fk] = map[string]bool{}
	}
	if name != "" {
		m.fkNames[fk][name] = true
	}
}

// dropFKByName removes every ledger entry created under this constraint name.
func (m *schemaModel) dropFKByName(name string) {
	for fk, names := range m.fkNames {
		if names[name] {
			delete(m.fks, fk)
			delete(m.fkNames, fk)
		}
	}
}

// normalizeFKColumns folds a column list to a canonical form so the same
// constraint written two ways lands on one key.
func normalizeFKColumns(list string) string {
	var out []string
	for _, c := range splitTopLevel(list) {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		out = append(out, unquoteIdent(strings.Fields(c)[0]))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// parseFKTarget reads the REFERENCES clause.
//
// A clause this cannot parse yields Unresolved rather than nothing. A migration
// that builds its FK target with format('%I', …) or string concatenation is
// making the same runtime decision the ledger exists to catch, and dropping the
// statement would make the loudest case the silent one.
func parseFKTarget(clause, origin string, certain bool) fkTarget {
	mm := reReferences.FindStringSubmatch(clause)
	if mm == nil {
		return fkTarget{Unresolved: true, Certain: certain, Origin: origin}
	}
	name := strings.TrimSpace(mm[1])
	// A target assembled at runtime does not look like an identifier.
	if strings.ContainsAny(name, "|'()") {
		return fkTarget{Unresolved: true, Certain: certain, Origin: origin}
	}
	k := parseName(name, migrationSearchPath)
	return fkTarget{Schema: k.Schema, Table: k.Table, Certain: certain, Origin: origin}
}

func (m *schemaModel) applyAlterTable(key tableKey, actions string) {
	// RENAME is never comma-listed with other actions.
	if mm := reRenameColumn.FindStringSubmatch(actions); mm != nil {
		if cols, ok := m.columns[key]; ok {
			delete(cols, unquoteIdent(mm[1]))
			cols[unquoteIdent(mm[2])] = true
		}
		return
	}
	if mm := reRenameTable.FindStringSubmatch(actions); mm != nil {
		newKey := tableKey{Schema: key.Schema, Table: unquoteIdent(mm[1])}
		if cols, ok := m.columns[key]; ok {
			m.columns[newKey] = cols
			delete(m.columns, key)
		}
		if m.opaque[key] {
			m.opaque[newKey] = true
			delete(m.opaque, key)
		}
		return
	}
	for _, action := range splitTopLevel(actions) {
		action = strings.TrimSpace(action)
		switch {
		case reAddColumn.MatchString(action):
			name := reAddColumn.FindStringSubmatch(action)[1]
			if tableConstraintLeaders[strings.ToLower(strings.Trim(name, `"`))] {
				continue
			}
			if cols, ok := m.columns[key]; ok {
				cols[unquoteIdent(name)] = true
			}
		case reDropColumn.MatchString(action):
			name := reDropColumn.FindStringSubmatch(action)[1]
			if tableConstraintLeaders[strings.ToLower(strings.Trim(name, `"`))] {
				continue
			}
			if cols, ok := m.columns[key]; ok {
				delete(cols, unquoteIdent(name))
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Write extraction from Go source
// ---------------------------------------------------------------------------

// sqlWrite is one INSERT/UPDATE/DELETE found in a Go string literal.
type sqlWrite struct {
	// Table is exactly as it appeared, so "identity.audit_logs" keeps its
	// qualifier and "audit_logs" stays unqualified for search_path resolution.
	Table string
	// Columns are the columns the statement names on Table. Empty for a plain
	// DELETE, which demands only that the table exist.
	Columns []string
	// Pos is file:line of the literal, for the failure message.
	Pos string
}

var (
	reInsert       = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+([\w.]+)\s*\(([^()]*)\)`)
	reInsertNoCols = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+([\w.]+)\s+(?:SELECT|VALUES|DEFAULT)\b`)
	reUpdate       = regexp.MustCompile(`(?is)\bUPDATE\s+(?:ONLY\s+)?([\w.]+)\s+SET\s+(.*?)(?:\s+FROM\s+|\s+WHERE\s+|\s+RETURNING\s+|$)`)
	reDelete       = regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+(?:ONLY\s+)?([\w.]+)`)
	reReturning    = regexp.MustCompile(`(?is)\bRETURNING\s+(.*?)(?:\s*$)`)
	reConflictSet  = regexp.MustCompile(`(?is)\bON\s+CONFLICT\b.*?\bDO\s+UPDATE\s+SET\s+(.*?)(?:\s+WHERE\s+|\s+RETURNING\s+|$)`)
	reIdent        = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	// reRelation accepts a bare or once-qualified all-lowercase relation name.
	// Case matters here even though SQL does not: every table in both migration
	// streams is lower case, so a capitalised token after "DELETE FROM" is
	// English, not SQL. Without this, `fmt.Errorf("failed to delete from S3")`
	// is reported as a write to a missing table named S3 — three such prose
	// matches showed up on the first run.
	reRelation = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$`)
)

// nonColumnWords are tokens that appear where a column name would and are not
// column names. EXCLUDED is the ON CONFLICT pseudo-table; the rest are
// projections a RETURNING clause may carry.
var nonColumnWords = map[string]bool{
	"excluded": true, "true": true, "false": true, "null": true,
	"default": true, "now": true, "current_timestamp": true,
}

// extractWrites pulls every DML write out of one SQL string.
func extractWrites(sql, pos string) []sqlWrite {
	var out []sqlWrite
	table := ""
	record := func(name string, cols []string) {
		if !reRelation.MatchString(name) {
			return
		}
		table = name
		out = append(out, sqlWrite{Table: name, Columns: cols, Pos: pos})
	}
	for _, mm := range reInsert.FindAllStringSubmatch(sql, -1) {
		record(mm[1], identList(mm[2]))
	}
	for _, mm := range reInsertNoCols.FindAllStringSubmatch(sql, -1) {
		record(mm[1], nil)
	}
	for _, mm := range reUpdate.FindAllStringSubmatch(sql, -1) {
		record(mm[1], assignedColumns(mm[2]))
	}
	for _, mm := range reDelete.FindAllStringSubmatch(sql, -1) {
		record(mm[1], nil)
	}
	if table == "" {
		return out
	}
	// RETURNING and ON CONFLICT DO UPDATE SET attach to the last write's table.
	// Every statement in this codebase is a single write, so "last" is "the
	// one"; a literal holding two writes with a RETURNING on the first would
	// mis-attribute, which is a stated boundary of the guard.
	if mm := reConflictSet.FindStringSubmatch(sql); mm != nil {
		out = append(out, sqlWrite{Table: table, Columns: assignedColumns(mm[1]), Pos: pos})
	}
	if mm := reReturning.FindStringSubmatch(sql); mm != nil {
		if cols := identList(mm[1]); len(cols) > 0 {
			out = append(out, sqlWrite{Table: table, Columns: cols, Pos: pos})
		}
	}
	return out
}

// identList turns a comma-separated projection into bare column names,
// dropping anything that is not a plain identifier (expressions, functions,
// `*`, literals). Dropping is a false-negative, never a false-positive.
func identList(s string) []string {
	var out []string
	for _, part := range splitTopLevel(s) {
		name := bareColumn(part)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// assignedColumns pulls the left-hand sides out of a SET clause.
func assignedColumns(s string) []string {
	var out []string
	for _, part := range splitTopLevel(s) {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		if name := bareColumn(part[:eq]); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// bareColumn reduces "al.actor_email" to "actor_email" and rejects anything
// that is not a simple identifier.
func bareColumn(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	if s == "" || strings.ContainsAny(s, "()'* \t\n") {
		return ""
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	s = strings.ToLower(s)
	if !reIdent.MatchString(s) || nonColumnWords[s] {
		return ""
	}
	return s
}

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

// scanWrites walks root for non-test .go files and returns every DML write in
// their string literals. Test files are excluded: a write that only ever runs
// under sqlmock proves nothing about the shipped schema, and fixture SQL in
// tests would otherwise dominate the demand set.
func scanWrites(root string) ([]sqlWrite, error) {
	var out []sqlWrite
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "node_modules", ".git", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, pErr := parser.ParseFile(fset, path, nil, 0)
		if pErr != nil {
			return fmt.Errorf("schemaguard: parse %s: %w", path, pErr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			text, pos, ok := stringLiteral(n, fset)
			if !ok {
				return true
			}
			out = append(out, extractWrites(text, pos)...)
			// A folded BinaryExpr's children are literals already covered.
			return false
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// stringLiteral folds a string literal or a `+` chain of them into one text,
// so SQL assembled as "INSERT INTO t (" + cols + ")" still yields whatever
// contiguous literal text there is. Non-literal operands contribute nothing,
// which can only lose a write, never invent one.
func stringLiteral(n ast.Node, fset *token.FileSet) (string, string, bool) {
	switch v := n.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", "", false
		}
		return s, fset.Position(v.Pos()).String(), true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", "", false
		}
		l, _, lok := stringLiteral(v.X, fset)
		r, _, rok := stringLiteral(v.Y, fset)
		if !lok && !rok {
			return "", "", false
		}
		return l + " " + r, fset.Position(v.Pos()).String(), true
	}
	return "", "", false
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// violation is one write the configured schema cannot accept.
type violation struct {
	Table  string // as written, qualified or not
	Column string // "" when the table itself is missing
	Pos    string
}

func (v violation) String() string {
	if v.Column == "" {
		return fmt.Sprintf("table %s does not exist (%s)", v.Table, v.Pos)
	}
	return fmt.Sprintf("%s.%s does not exist (%s)", v.Table, v.Column, v.Pos)
}

// resolveOpts controls how writes are matched against the model.
type resolveOpts struct {
	// SearchPath is the schema resolution order for unqualified names, exactly
	// as Postgres would apply it.
	SearchPath []string
	// IgnoreSchemas are never checked (pg_catalog, information_schema).
	IgnoreSchemas map[string]bool
	// IgnoreTables are unqualified names owned by something other than the
	// migration streams — golang-migrate's own bookkeeping, for instance.
	IgnoreTables map[string]bool
}

// resolve returns every write the model cannot accept, plus the number of
// writes actually examined.
func resolve(m *schemaModel, writes []sqlWrite, opts resolveOpts) ([]violation, int, error) {
	if len(opts.SearchPath) == 0 {
		return nil, 0, errNoSearchPath
	}
	if m.tableCount() == 0 {
		return nil, 0, errNoDDL
	}
	if len(writes) == 0 {
		return nil, 0, errNoWrites
	}

	var out []violation
	checked := 0
	for _, w := range writes {
		name := strings.ToLower(w.Table)
		schema, bare := "", name
		if i := strings.LastIndex(name, "."); i >= 0 {
			schema, bare = name[:i], name[i+1:]
		}
		if opts.IgnoreSchemas[schema] || opts.IgnoreTables[bare] {
			continue
		}
		checked++

		var found *tableKey
		if schema != "" {
			k := tableKey{Schema: schema, Table: bare}
			if m.has(k) {
				found = &k
			}
		} else {
			for _, s := range opts.SearchPath {
				k := tableKey{Schema: s, Table: bare}
				if m.has(k) {
					found = &k
					break
				}
			}
		}
		if found == nil {
			out = append(out, violation{Table: w.Table, Pos: w.Pos})
			continue
		}
		cols, modelled := m.columns[*found]
		if !modelled { // opaque relation: existence only
			continue
		}
		for _, c := range w.Columns {
			if !cols[c] {
				out = append(out, violation{Table: w.Table, Column: c, Pos: w.Pos})
			}
		}
	}
	if checked == 0 {
		return nil, 0, errNoWrites
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, checked, nil
}

// ===========================================================================
// Unit tests for the analyzer itself
// ===========================================================================

func modelFromSQL(t *testing.T, schema, sql string) *schemaModel {
	t.Helper()
	m := newSchemaModel()
	m.applySQL(sql, schema)
	return m
}

func TestDDLReplayTracksColumns(t *testing.T) {
	m := modelFromSQL(t, "public", `
		CREATE TABLE audit_logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id),
			metadata JSONB,
			PRIMARY KEY (id),
			CONSTRAINT ck CHECK (id IS NOT NULL)
		);
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_email VARCHAR(255);
		ALTER TABLE audit_logs DROP COLUMN metadata;
		ALTER TABLE audit_logs RENAME COLUMN user_id TO actor_id;
	`)
	cols := m.columns[tableKey{Schema: "public", Table: "audit_logs"}]
	if cols == nil {
		t.Fatal("public.audit_logs not modelled")
	}
	for _, want := range []string{"id", "actor_email", "actor_id"} {
		if !cols[want] {
			t.Errorf("column %q missing; got %v", want, sortedKeys(cols))
		}
	}
	for _, gone := range []string{"metadata", "user_id", "primary", "constraint", "ck"} {
		if cols[gone] {
			t.Errorf("column %q should not be present; got %v", gone, sortedKeys(cols))
		}
	}
}

func TestDDLReplayHandlesDropRenameAndViews(t *testing.T) {
	m := modelFromSQL(t, "public", `
		CREATE TABLE old_name (a INT);
		ALTER TABLE old_name RENAME TO new_name;
		CREATE TABLE doomed (b INT);
		DROP TABLE IF EXISTS doomed CASCADE;
		CREATE OR REPLACE VIEW v_stats AS SELECT 1 AS n;
	`)
	if !m.has(tableKey{Schema: "public", Table: "new_name"}) {
		t.Error("rename did not carry the table to new_name")
	}
	if m.has(tableKey{Schema: "public", Table: "old_name"}) {
		t.Error("old_name survived the rename")
	}
	if m.has(tableKey{Schema: "public", Table: "doomed"}) {
		t.Error("doomed survived DROP TABLE")
	}
	if !m.opaque[tableKey{Schema: "public", Table: "v_stats"}] {
		t.Error("view was not recorded as an opaque relation")
	}
}

func TestSplitStatementsSurvivesDollarQuoting(t *testing.T) {
	stmts := splitStatements(`CREATE TABLE t (a INT); DO $$ BEGIN INSERT INTO t VALUES (1); END $$; DROP TABLE t;`)
	if len(stmts) != 3 {
		t.Fatalf("got %d statements, want 3: %q", len(stmts), stmts)
	}
	if !strings.Contains(stmts[1], "END $$") {
		t.Errorf("DO block was split; got %q", stmts[1])
	}
}

func TestExtractWritesFindsColumns(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		wantTable string
		wantCols  []string
	}{
		{
			name:      "insert with returning (the #864 shape)",
			sql:       "INSERT INTO audit_logs (id, user_id, actor_email) VALUES ($1,$2,COALESCE($3,(SELECT email FROM users))) RETURNING actor_email",
			wantTable: "audit_logs",
			wantCols:  []string{"id", "user_id", "actor_email", "actor_email"},
		},
		{
			name:      "update set",
			sql:       "UPDATE identity.users SET name = $1, updated_at = NOW() WHERE id = $2",
			wantTable: "identity.users",
			wantCols:  []string{"name", "updated_at"},
		},
		{
			name:      "upsert",
			sql:       "INSERT INTO t (a) VALUES ($1) ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b",
			wantTable: "t",
			wantCols:  []string{"a", "b"},
		},
		{
			name:      "delete demands only the table",
			sql:       "DELETE FROM api_keys WHERE id = $1",
			wantTable: "api_keys",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writes := extractWrites(tc.sql, "fixture:1")
			if len(writes) == 0 {
				t.Fatal("no writes extracted")
			}
			var gotCols []string
			for _, w := range writes {
				if w.Table != tc.wantTable {
					t.Errorf("table = %q, want %q", w.Table, tc.wantTable)
				}
				gotCols = append(gotCols, w.Columns...)
			}
			if strings.Join(gotCols, ",") != strings.Join(tc.wantCols, ",") {
				t.Errorf("columns = %v, want %v", gotCols, tc.wantCols)
			}
		})
	}
}

// TestResolveModelsSearchPathOrder is the mechanism behind #864 in miniature:
// the identity schema holds actor_email, but it is not on the search_path, so
// the unqualified write lands on public and fails.
func TestResolveModelsSearchPathOrder(t *testing.T) {
	m := newSchemaModel()
	m.applySQL(`CREATE TABLE public.audit_logs (id UUID, user_id UUID);`, "public")
	m.applySQL(`CREATE TABLE identity.audit_logs (id UUID, user_id UUID, actor_email VARCHAR(255));`, "identity")
	writes := extractWrites("INSERT INTO audit_logs (id, actor_email) VALUES ($1,$2)", "fixture:1")

	got, checked, err := resolve(m, writes, resolveOpts{SearchPath: []string{"public"}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if checked != 1 {
		t.Fatalf("checked = %d, want 1", checked)
	}
	if len(got) != 1 || got[0].Column != "actor_email" || got[0].Table != "audit_logs" {
		t.Fatalf("violations = %v, want exactly audit_logs.actor_email", got)
	}

	got, _, err = resolve(m, writes, resolveOpts{SearchPath: []string{"identity", "public"}})
	if err != nil {
		t.Fatalf("resolve with identity on the path: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("violations = %v, want none once identity is on the search_path", got)
	}
}

// TestResolveRefusesEmptyUniverse is the falsification required of this guard:
// pointed at nothing, it must refuse to certify rather than report success.
func TestResolveRefusesEmptyUniverse(t *testing.T) {
	populated := newSchemaModel()
	populated.applySQL(`CREATE TABLE public.t (a INT);`, "public")
	someWrites := extractWrites("INSERT INTO t (a) VALUES ($1)", "fixture:1")

	cases := []struct {
		name    string
		model   *schemaModel
		writes  []sqlWrite
		opts    resolveOpts
		wantErr error
	}{
		{
			name:    "no schema at all",
			model:   newSchemaModel(),
			writes:  someWrites,
			opts:    resolveOpts{SearchPath: []string{"public"}},
			wantErr: errNoDDL,
		},
		{
			name:    "no writes at all",
			model:   populated,
			writes:  nil,
			opts:    resolveOpts{SearchPath: []string{"public"}},
			wantErr: errNoWrites,
		},
		{
			name:    "every write filtered away leaves nothing checked",
			model:   populated,
			writes:  someWrites,
			opts:    resolveOpts{SearchPath: []string{"public"}, IgnoreTables: map[string]bool{"t": true}},
			wantErr: errNoWrites,
		},
		{
			name:    "no search_path",
			model:   populated,
			writes:  someWrites,
			opts:    resolveOpts{},
			wantErr: errNoSearchPath,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, checked, err := resolve(tc.model, tc.writes, tc.opts)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != nil || checked != 0 {
				t.Fatalf("refusal must not also report results: violations=%v checked=%d", got, checked)
			}
		})
	}
}

// TestReplayRefusesEmptyStream falsifies the other empty universe: a migration
// directory that contributes no DDL.
func TestReplayRefusesEmptyStream(t *testing.T) {
	dir := t.TempDir()
	m := newSchemaModel()
	if err := m.replay(migrationStream{Name: "empty", Dir: dir, DefaultSchema: "public"}); !errors.Is(err, errNoDDL) {
		t.Fatalf("replay of an empty dir: err = %v, want %v", err, errNoDDL)
	}
	if err := m.replay(migrationStream{Name: "gone", Dir: filepath.Join(dir, "nope"), DefaultSchema: "public"}); err == nil {
		t.Fatal("replay of a missing dir returned nil error")
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
