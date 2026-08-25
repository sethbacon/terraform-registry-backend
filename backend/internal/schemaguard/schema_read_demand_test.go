package schemaguard

// Reads demand a schema too.
//
// The write scanner has always asked "does the table this statement INSERTs
// into have the columns it names?". Nothing asked the same of a SELECT, and
// that gap cost a production incident: the audit-log page answered 500 for
// every deployment in the default configuration, because
//
//	SELECT al.id, ..., al.actor_email FROM audit_logs al LEFT JOIN users u ...
//
// resolves `audit_logs` through the search_path to PUBLIC.audit_logs — created
// by registry migration 000001 with no actor_email — while the column exists
// only on identity.audit_logs, added by identity migration 000007 and reachable
// only after the TFR_IDENTITY_SCHEMA_ENABLED cutover, which is off by default.
//
// Every piece was already modelled here: both migration streams, the default
// search_path, and the column sets. The guard simply never looked at what a
// SELECT reads. It had been broken since identity v0.25.0 and nothing said so.
//
// # What this scanner does and does not claim
//
// It reads ALIAS-QUALIFIED column references only — `al.actor_email` where `al`
// is bound by `FROM audit_logs al` or a JOIN. That is deliberately a subset:
//
//   - a qualified reference is UNAMBIGUOUS. It names one relation, so a demand
//     derived from it cannot be attributed to the wrong table, which is the
//     failure mode that would make this guard noisy enough to be switched off.
//   - a bare `SELECT name, email FROM users` is not scanned. Resolving those
//     needs to know which relation in scope owns each name, and getting it
//     wrong in the multi-table case invents demands nobody made.
//   - `SELECT *` demands nothing beyond the table existing, and is not scanned.
//
// CTE names and subquery aliases are collected and excluded: they are relations
// the statement itself defines, and the model has no rows for them.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	// FROM/JOIN <relation> [AS] [alias]. The relation may be schema-qualified.
	reFromJoin = regexp.MustCompile(`(?is)\b(?:FROM|JOIN)\s+(?:ONLY\s+)?([a-z_][\w.]*)(?:\s+(?:AS\s+)?([a-z_]\w*))?`)
	// A qualified column reference: alias.column.
	reQualifiedCol = regexp.MustCompile(`\b([a-z_]\w*)\.([a-z_]\w*)\b`)
	// WITH <name> AS ( — a relation the statement defines for itself.
	reCTE = regexp.MustCompile(`(?is)\b(?:WITH|,)\s+([a-z_]\w*)\s+AS\s*\(`)
	// Keywords that can follow FROM/JOIN and are not relations.
	reSelectStmt = regexp.MustCompile(`(?is)\bSELECT\b`)
)

// sqlKeywordsAfterFrom are tokens the FROM/JOIN regex can capture that name no
// relation. LATERAL and the set-returning functions appear in this codebase's
// queries; the rest are cheap insurance.
var sqlKeywordsAfterFrom = map[string]bool{
	"lateral": true, "unnest": true, "generate_series": true, "jsonb_each": true,
	"jsonb_each_text": true, "json_each": true, "select": true, "values": true,
}

// scanReadsSQL extracts read demands from one SQL string.
//
// Exported shape is sqlWrite because the demand is identical — this table must
// have these columns — and resolve() already answers exactly that question
// against the modelled search_path. Reusing it means reads and writes cannot
// drift in how they are resolved.
func scanReadsSQL(sql, pos string) []sqlWrite {
	if !reSelectStmt.MatchString(sql) {
		return nil
	}

	// Relations the statement defines for itself are not in the model.
	selfDefined := map[string]bool{}
	for _, m := range reCTE.FindAllStringSubmatch(sql, -1) {
		selfDefined[strings.ToLower(m[1])] = true
	}

	// alias -> relation(s). An unaliased `FROM audit_logs` also binds the bare
	// name, so `audit_logs.id` resolves.
	//
	// A SET of relations per alias, not one, because an alias is scoped to its
	// query block and this scanner is not a parser. A UNION reuses `h` for a
	// different table in each half:
	//
	//	SELECT ... h.versions_synced FROM terraform_sync_history h
	//	UNION ALL
	//	SELECT ... h.providers_synced FROM mirror_sync_history h
	//
	// A last-write-wins map attributes the first half's columns to the second
	// half's table and reports four columns missing that are not missing. That
	// was this scanner's first draft, and it is the failure mode that gets a
	// guard switched off — so an alias bound to more than one relation is
	// AMBIGUOUS and contributes nothing. A dropped demand is a check not made,
	// which is the status quo; a wrong demand is a red build nobody trusts.
	aliasTo := map[string]map[string]bool{}
	bind := func(alias, rel string) {
		if aliasTo[alias] == nil {
			aliasTo[alias] = map[string]bool{}
		}
		aliasTo[alias][rel] = true
	}
	for _, m := range reFromJoin.FindAllStringSubmatch(sql, -1) {
		rel, alias := strings.ToLower(m[1]), strings.ToLower(m[2])
		if sqlKeywordsAfterFrom[rel] || selfDefined[rel] || !reRelation.MatchString(rel) {
			continue
		}
		bare := rel
		if i := strings.LastIndex(rel, "."); i >= 0 {
			bare = rel[i+1:]
		}
		bind(bare, rel)
		if alias != "" && !sqlKeywordsAfterFrom[alias] {
			bind(alias, rel)
		}
	}
	if len(aliasTo) == 0 {
		return nil
	}

	byTable := map[string]map[string]bool{}
	for _, m := range reQualifiedCol.FindAllStringSubmatch(sql, -1) {
		alias, col := strings.ToLower(m[1]), strings.ToLower(m[2])
		rels, bound := aliasTo[alias]
		if !bound || selfDefined[alias] || len(rels) != 1 {
			continue // unbound, self-defined, or ambiguous across query blocks
		}
		var rel string
		for r := range rels {
			rel = r
		}
		// `identity.audit_logs` is a qualified RELATION, not alias.column, and
		// is excluded because `identity` was never bound as an alias.
		if _, alsoRelation := aliasTo[col]; alsoRelation && strings.Contains(sql, alias+"."+col+" ") {
			continue
		}
		if !reIdent.MatchString(col) {
			continue
		}
		if byTable[rel] == nil {
			byTable[rel] = map[string]bool{}
		}
		byTable[rel][col] = true
	}

	out := make([]sqlWrite, 0, len(byTable))
	for rel, cols := range byTable {
		names := make([]string, 0, len(cols))
		for c := range cols {
			names = append(names, c)
		}
		sort.Strings(names)
		out = append(out, sqlWrite{Table: rel, Columns: names, Pos: pos})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out
}

// scanReads walks a source tree and returns every read demand in it.
func scanReads(root string) ([]sqlWrite, error) {
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
			if text, pos, ok := stringLiteral(n, fset); ok {
				out = append(out, scanReadsSQL(text, pos)...)
			}
			return true
		})
		return nil
	})
	return out, err
}

// knownReadGaps records read demands the default configuration genuinely cannot
// satisfy, each with the reason and the remedy.
//
// EMPTY IS THE FINISH LINE. An entry here is a column a query selects that the
// default schema does not have — which is a 500 waiting for the first request
// that reaches it, not a style problem.
var knownReadGaps = map[string]string{}

// TestDefaultConfigurationCanReadItsOwnSQL is TestDefaultConfigurationCanExecuteItsOwnSQL
// for the read side.
//
// The write guard asked whether an INSERT's columns exist. Nothing asked it of a
// SELECT, and the audit-log page answered 500 in every default deployment
// because `SELECT al.actor_email FROM audit_logs al` resolves through the
// search_path to public.audit_logs, which has no such column — it lives on
// identity.audit_logs, behind a cutover that is off by default. Both streams,
// the search_path and the column sets were already modelled here; only the
// question was missing.
//
// COLUMNS ONLY, deliberately. A read demand whose TABLE is unknown is dropped
// rather than reported: alias-qualified parsing over concatenated DDL templates
// can invent a relation name (`o` from an outbox template did exactly that), and
// table existence is already the write guard's job — anything the application
// writes to, it checks there.
func TestDefaultConfigurationCanReadItsOwnSQL(t *testing.T) {
	a := buildAnalysis(t)

	reads, err := scanReads(backendSourceRoot)
	if err != nil {
		t.Fatalf("%v", err)
	}
	idReads, err := scanReads(filepath.Join(identityModuleDir(t), "identity"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	reads = append(reads, idReads...)

	// A scanner that found nothing would pass silently while checking nothing.
	if len(reads) < 50 {
		t.Fatalf("only %d read demands scanned across both trees. That is not a codebase with "+
			"few SELECTs, it is a scanner that stopped matching — fix scanReadsSQL before "+
			"trusting this test's green.", len(reads))
	}

	violations, checked, err := resolve(a.Model, reads, a.Opts)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("checked %d read demands against the default schema universe", checked)

	seen := map[string]bool{}
	for _, v := range violations {
		if v.Column == "" {
			continue // table existence is the write guard's question
		}
		key := v.Table + "." + v.Column
		if seen[key] {
			continue
		}
		seen[key] = true
		if reason, known := knownReadGaps[key]; known {
			t.Logf("known read gap: %s — %s", key, reason)
			continue
		}
		t.Errorf("%s\n"+
			"A query SELECTs this column and the schema the DEFAULT configuration produces does "+
			"not have it, so every request reaching that query answers 500. This is how "+
			"/api/v1/admin/audit-logs was broken in every default deployment from identity "+
			"v0.25.0 onward: the column exists, on the OTHER schema, behind a cutover that is "+
			"off by default.\n"+
			"Fix the schema, or make the query's schema a documented precondition and record it "+
			"in knownReadGaps with the remedy.", v.String())
	}
}
