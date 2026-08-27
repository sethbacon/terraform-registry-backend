package schemaguard

// schema_constraint_test.go widens schemaguard past column existence, to the
// class of defect where every column exists and the write still fails (#898).
//
// WHAT #883 WAS. Migrations 000038 and 000045 chose each foreign key's target
// SCHEMA at migration time:
//
//	IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
//	  ... REFERENCES identity.organizations(id)
//	ELSE
//	  ... REFERENCES public.organizations(id)
//
// Where the identity schema exists but the application still reads and writes
// public -- a documented rollout step, not an exotic configuration -- the
// constraint resolved at identity while every row carried a public id. POST
// /api/v1/modules returned 500 on every attempt.
//
// The existing guard could not have caught it and said so in its own
// boundaries: every column involved EXISTED. Its answer, "this write can land",
// was correct about columns and wrong about the write.
//
// WHAT THIS GUARD DOES INSTEAD. It records each foreign key's target as the SET
// of values the migration stream could have given it, and never evaluates the
// branch predicate. A constraint whose possible targets span more than one
// schema is chosen by the deployment's topology rather than by the migration,
// and that is reportable without modelling any topology at all.
//
// That formulation is deliberately blind to spelling. It never reads the
// condition, so `to_regclass`, `'identity'::regnamespace`, a
// `has_schema_privilege` call, an EXCEPTION handler and a CASE all land in the
// same place. The text-level lint in internal/db/migrations_test.go catches one
// spelling of the mistake; this catches the mistake.
//
// WHAT IT DOES NOT COVER, stated rather than left to be discovered:
//
//   - .down.sql files. The replay is forward-only.
//   - DML that branches on schema existence. Several migrations do this to
//     decide where to COPY rows from; it is reported below as a fact, never
//     failed on, because a data move is not a constraint.
//   - Anything about which topology is CORRECT. The guard's claim is only that
//     no single arm can be right in every topology -- converge the artifact,
//     do not pick an arm.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// minLedgerEntries is the empty-universe floor.
//
// Every assertion here iterates m.fks. If the ledger were empty they would all
// pass while checking nothing -- and an empty ledger is exactly what a broken
// parser produces, which is how this guard would fail silently rather than
// loudly. The tree carried 47 entries when this was written.
const minLedgerEntries = 30

// checkLedgerNotVacuous is the empty-universe guard, factored out as a pure
// function so it can be falsified DIRECTLY -- the same treatment
// checkNotVacuous gets in schema_demand_guard_test.go, and for the same reason.
//
// A floor cannot be falsified by lowering it: the tree is healthy, so nothing
// else fails and the mutation looks harmless. Handing the checker an empty
// ledger is the only way to prove it would object.
func checkLedgerNotVacuous(m *schemaModel) error {
	if len(m.fks) < minLedgerEntries {
		return fmt.Errorf("the foreign-key ledger holds only %d entries (floor %d): the migration "+
			"replay is not extracting constraints, so every assertion over it is vacuous",
			len(m.fks), minLedgerEntries)
	}
	return nil
}

func TestNoForeignKeyTargetDependsOnTheEnvironment(t *testing.T) {
	a := buildAnalysis(t)
	m := a.Model

	if err := checkLedgerNotVacuous(m); err != nil {
		t.Fatalf("%v", err)
	}

	keys := make([]fkKey, 0, len(m.fks))
	for k := range m.fks {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })

	// --- the fact report, on every run -------------------------------------
	//
	// #898 observes that merely REPORTING each constraint's target schema would
	// have made #883 visible in the test log even without a rule that fails on
	// it. This is that report, and it is what makes the assertions below
	// auditable rather than oracular.
	var report []string
	for _, k := range keys {
		report = append(report, "  "+k.String()+" -> "+describeTargets(m.fks[k]))
	}
	t.Logf("foreign-key ledger (%d constraints):\n%s", len(keys), strings.Join(report, "\n"))

	for _, k := range keys {
		targets := m.fks[k]

		// --- V3: a target this analyzer could not read ----------------------
		//
		// Checked before V1, because a migration that computes its FK target at
		// runtime is the same defect wearing a different hat, and reporting it
		// as "only one schema seen" would be actively misleading.
		for _, tgt := range targets {
			if tgt.Unresolved {
				t.Errorf("%s has a foreign-key target this analyzer cannot resolve statically (%s).\n"+
					"A migration that computes its FOREIGN KEY target -- with format('%%I', …), string "+
					"concatenation, or a variable -- decides at run time what the schema should have "+
					"decided, which is the defect this file exists for. Write the target literally.",
					k, tgt.Origin)
			}
		}

		// --- V1: the #883 catcher ------------------------------------------
		schemas := map[string]bool{}
		for _, tgt := range targets {
			if !tgt.Unresolved {
				schemas[tgt.Schema] = true
			}
		}
		if len(schemas) > 1 {
			names := make([]string, 0, len(schemas))
			for s := range schemas {
				names = append(names, s)
			}
			sort.Strings(names)
			t.Errorf("the target SCHEMA of %s is chosen by the deployment's topology, not by the "+
				"migration: it can resolve at %s (%s).\n\n"+
				"Under one topology this constraint points at one schema and under another at a "+
				"different one, while the application writes ids from whichever schema its own "+
				"search_path selects -- so every column exists and the write still fails. That was "+
				"#883.\n\n"+
				"NO ARM IS CORRECT IN EVERY TOPOLOGY, so do not pick an arm: converge the artifact. "+
				"Migration 000056 converged the previous 24 of these by dropping them and holding "+
				"the invariant in the application instead. See #883 and #898.",
				k, strings.Join(names, " or "), describeTargets(targets))
			continue
		}

		// --- V2: reported, never failed ------------------------------------
		//
		// A singleton target this replay does not model is usually a table in a
		// stream the default configuration does not apply -- which is a fact
		// about the configuration, not a defect in the migration. Failing here
		// would make the guard configuration-relative, and V1's whole value is
		// that it is not.
		for s := range schemas {
			if len(targets) > 0 && !m.has(tableKey{Schema: s, Table: targets[0].Table}) {
				t.Logf("note: %s targets %s.%s, which the default configuration's replay does not "+
					"model (reported, not failed -- see V2 in this file)", k, s, targets[0].Table)
			}
		}
	}
}

// describeTargets renders a possibility set for a message.
func describeTargets(targets []fkTarget) string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		var d string
		switch {
		case t.Unresolved:
			d = fmt.Sprintf("<unresolved> from %s", t.Origin)
		case t.Certain:
			d = fmt.Sprintf("%s.%s from %s", t.Schema, t.Table, t.Origin)
		default:
			d = fmt.Sprintf("%s.%s possible, from %s", t.Schema, t.Table, t.Origin)
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

// ---------------------------------------------------------------------------
// Hermetic ledger tests
//
// The guard above runs against the real migration stream, which is CLEAN --
// migration 000056 converged the 24 constraints that made #883. That is a
// problem for falsification: breaking the extractor on a clean tree makes the
// ledger find nothing, and finding nothing is the correct answer there, so the
// guard still passes.
//
// Four separate mutations proved exactly that, and were inert until these
// tests existed: treating a possible DROP as certain, not descending into DO
// blocks at all, removing the PL/pgSQL re-anchor, and removing the
// empty-universe floor. Each is invisible against clean input and fatal against
// dirty input.
//
// So these feed the analyzer SQL that CONTAINS the defect and require it to be
// reported.
// ---------------------------------------------------------------------------

// ledgerFor replays sql and returns the resulting model.
func ledgerFor(t *testing.T, sql string) *schemaModel {
	t.Helper()
	m := newSchemaModel()
	m.applyStatements(splitStatements(stripComments(sql)), "public", true, "test.sql")
	return m
}

// schemasFor returns the distinct target schemas recorded for one constraint.
func schemasFor(t *testing.T, m *schemaModel, table, cols string) []string {
	t.Helper()
	k := fkKey{Table: tableKey{Schema: "public", Table: table}, Columns: cols}
	targets, ok := m.fks[k]
	if !ok {
		t.Fatalf("no ledger entry for %s(%s). Recorded: %v", table, cols, ledgerKeys(m))
	}
	seen := map[string]bool{}
	var out []string
	for _, tg := range targets {
		if tg.Unresolved {
			out = append(out, "<unresolved>")
			continue
		}
		if !seen[tg.Schema] {
			seen[tg.Schema] = true
			out = append(out, tg.Schema)
		}
	}
	sort.Strings(out)
	return out
}

func ledgerKeys(m *schemaModel) []string {
	var out []string
	for k := range m.fks {
		out = append(out, k.String())
	}
	sort.Strings(out)
	return out
}

// TestLedgerSeesBothArmsOfASchemaBranch is the #883 shape, reduced.
func TestLedgerSeesBothArmsOfASchemaBranch(t *testing.T) {
	m := ledgerFor(t, `
CREATE TABLE claims (namespace TEXT, organization_id UUID);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.claims ADD CONSTRAINT claims_org_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id);
  ELSE
    ALTER TABLE public.claims ADD CONSTRAINT claims_org_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
  END IF;
END $$;`)

	got := schemasFor(t, m, "claims", "organization_id")
	if len(got) != 2 {
		t.Fatalf("target schemas = %v, want both identity and public. A constraint whose schema is "+
			"chosen by a branch must record BOTH arms, or the guard cannot see the choice.", got)
	}
}

// TestLedgerSeesTheFirstStatementInEachArm is the subtle one, and the reason
// this test exists as its own case.
//
// splitStatements splits on ";", and PL/pgSQL control flow carries no semicolon
// -- so the first statement after THEN and after ELSE arrives glued to its
// prefix ("BEGIN IF EXISTS (...) THEN ALTER TABLE ..."). Without re-anchoring
// past that prefix, the FIRST constraint in each arm is invisible while every
// later one is seen.
//
// Against the real stream that lost exactly namespace_claims(organization_id) --
// the constraint #883 is about -- while still reporting 23 others. A guard that
// looks like it works is worse than one that obviously does not.
func TestLedgerSeesTheFirstStatementInEachArm(t *testing.T) {
	m := ledgerFor(t, `
CREATE TABLE claims (organization_id UUID, claimed_by UUID);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.claims ADD CONSTRAINT claims_org_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id);
    ALTER TABLE public.claims ADD CONSTRAINT claims_by_fkey FOREIGN KEY (claimed_by) REFERENCES identity.users(id);
  ELSE
    ALTER TABLE public.claims ADD CONSTRAINT claims_org_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
    ALTER TABLE public.claims ADD CONSTRAINT claims_by_fkey FOREIGN KEY (claimed_by) REFERENCES public.users(id);
  END IF;
END $$;`)

	// The SECOND constraint in each arm is the easy one; it is the FIRST that
	// used to vanish.
	if got := schemasFor(t, m, "claims", "organization_id"); len(got) != 2 {
		t.Errorf("the FIRST constraint in each arm recorded %v, want two schemas. It arrives glued "+
			"to its BEGIN/IF/ELSE prefix and needs re-anchoring past it.", got)
	}
	if got := schemasFor(t, m, "claims", "claimed_by"); len(got) != 2 {
		t.Errorf("the second constraint in each arm recorded %v, want two schemas", got)
	}
}

// TestPossibleDropDoesNotHideAConditionalRepoint pins the load-bearing rule.
//
// 000038 repoints constraints created earlier against public, and has no ELSE.
// Treating its conditional DROP as a real one would leave a single target and
// make the repoint look like a plain move -- which is precisely the defect.
func TestPossibleDropDoesNotHideAConditionalRepoint(t *testing.T) {
	m := ledgerFor(t, `
CREATE TABLE modules (organization_id UUID);
ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.modules DROP CONSTRAINT modules_org_fkey;
    ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id);
  END IF;
END $$;`)

	got := schemasFor(t, m, "modules", "organization_id")
	if len(got) != 2 {
		t.Fatalf("target schemas = %v, want both. A DROP inside a conditional removes the "+
			"constraint in ONE world only; the original target is still live in the other, so a "+
			"possible drop must be a no-op.", got)
	}
}

// TestCertainDropRemovesTheEntry is the other half, and it is what makes the
// real tree green: 000056's 24 drops are unconditional and top-level.
func TestCertainDropRemovesTheEntry(t *testing.T) {
	m := ledgerFor(t, `
CREATE TABLE modules (organization_id UUID);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id);
  ELSE
    ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
  END IF;
END $$;
ALTER TABLE IF EXISTS public.modules DROP CONSTRAINT IF EXISTS modules_org_fkey;`)

	k := fkKey{Table: tableKey{Schema: "public", Table: "modules"}, Columns: "organization_id"}
	if _, ok := m.fks[k]; ok {
		t.Errorf("an unconditional DROP left the entry in the ledger: %v.\nConverging a constraint "+
			"by dropping it is how 000056 fixed #883, and a guard that still reported it afterwards "+
			"would be permanently red for a defect that had been fixed.", m.fks[k])
	}
}

// TestRuntimeComputedTargetIsUnresolved. A migration that builds its FK target
// with format('%I', …) decides at run time what the schema should decide, and
// reporting it as "one schema seen" would be actively misleading.
func TestRuntimeComputedTargetIsUnresolved(t *testing.T) {
	// The realistic shape: the DDL lives inside a string handed to EXECUTE, and
	// the schema arrives through a format placeholder. An earlier draft of this
	// test used `REFERENCES quote_ident(sch).organizations(id)` inline, which is
	// not valid SQL and which the parser happily resolved to `public.quote_ident`
	// -- a reminder that a hermetic fixture has to be something the database
	// would actually accept, or it tests the parser against a language nobody
	// writes.
	m := ledgerFor(t, `
CREATE TABLE modules (organization_id UUID);
DO $$
DECLARE sch text := 'identity';
BEGIN
  EXECUTE format('ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES %I.organizations(id)', sch);
END $$;`)

	got := schemasFor(t, m, "modules", "organization_id")
	if len(got) != 1 || got[0] != "<unresolved>" {
		t.Errorf("target = %v, want <unresolved>. A computed target must be reported as unreadable, "+
			"not silently resolved or dropped.", got)
	}
}

// TestInlineColumnReferencesIsRecorded covers the CREATE TABLE path: an inline
// REFERENCES is a single-column FK, and 000056 drops several of them by the
// implicit name PostgreSQL would have generated.
func TestInlineColumnReferencesIsRecorded(t *testing.T) {
	m := ledgerFor(t, `CREATE TABLE download_events (id UUID, user_id UUID REFERENCES users(id));`)

	got := schemasFor(t, m, "download_events", "user_id")
	if len(got) != 1 || got[0] != "public" {
		t.Fatalf("inline REFERENCES recorded %v, want [public] (unqualified names in a migration "+
			"resolve at public)", got)
	}
	k := fkKey{Table: tableKey{Schema: "public", Table: "download_events"}, Columns: "user_id"}
	if !m.fkNames[k]["download_events_user_id_fkey"] {
		t.Errorf("the implicit constraint name was not synthesized (names: %v). A later "+
			"DROP CONSTRAINT names it that way, and without it the drop cannot find the entry.",
			m.fkNames[k])
	}
}

// TestLedgerFloorRefusesAnEmptyUniverse falsifies the floor directly.
func TestLedgerFloorRefusesAnEmptyUniverse(t *testing.T) {
	if err := checkLedgerNotVacuous(newSchemaModel()); err == nil {
		t.Error("an empty ledger was accepted. Every assertion in this file iterates m.fks, so an " +
			"empty one passes them all while checking nothing -- which is exactly what a broken " +
			"extractor produces.")
	}
	// And a healthy one must be accepted, or the floor is simply always red.
	m := newSchemaModel()
	for i := 0; i < minLedgerEntries; i++ {
		k := fkKey{Table: tableKey{Schema: "public", Table: fmt.Sprintf("t%d", i)}, Columns: "c"}
		m.fks[k] = []fkTarget{{Schema: "public", Table: "u", Certain: true}}
	}
	if err := checkLedgerNotVacuous(m); err != nil {
		t.Errorf("a ledger at the floor was rejected: %v", err)
	}
}

// TestCertainAddReplacesThePossibilitySet.
//
// A migration that states, unconditionally, what a constraint now points at has
// SETTLED the question -- the earlier conditional arms are no longer possible.
// Appending instead would leave a stale target in the set forever, so a
// constraint converged by a later migration would keep failing the guard and
// the only way to quiet it would be to delete the guard.
func TestCertainAddReplacesThePossibilitySet(t *testing.T) {
	m := ledgerFor(t, `
CREATE TABLE modules (organization_id UUID);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id);
  ELSE
    ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);
  END IF;
END $$;
ALTER TABLE public.modules ADD CONSTRAINT modules_org_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);`)

	got := schemasFor(t, m, "modules", "organization_id")
	if len(got) != 1 || got[0] != "public" {
		t.Errorf("after an unconditional re-add the possibility set is %v, want [public] only.\n"+
			"A certain ADD settles the question; keeping the earlier arms would leave a converged "+
			"constraint failing forever.", got)
	}
}
