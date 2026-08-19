package rolepolicy

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The constructs below are not all used by a migration in this tree today. They
// are covered anyway, because the deriver's job is to be right about the
// migration that has not been written yet -- and an unexercised branch in a
// guard is a blind spot in the guard, not spare capacity.
func TestDeriverHandlesEachStatementForm(t *testing.T) {
	base := `INSERT INTO role_templates (name, display_name, scopes, is_system) VALUES
		('viewer',    'Viewer',    '["modules:read"]'::jsonb, true),
		('devops',    'DevOps',    '["modules:read", "scm:manage"]'::jsonb, true),
		('auditor',   'Auditor',   '["audit:read"]'::jsonb, true),
		('scratch',   'Scratch',   '["modules:read"]'::jsonb, false);`

	for _, tc := range []struct {
		name string
		sql  string
		want map[string][]string // nil entry means "template must be gone"
	}{
		{
			name: "DELETE with a name predicate",
			sql:  `DELETE FROM role_templates WHERE name = 'scratch';`,
			want: map[string][]string{"scratch": nil},
		},
		{
			name: "DELETE selecting on is_system",
			sql:  `DELETE FROM public.role_templates WHERE is_system = false;`,
			want: map[string][]string{"scratch": nil, "viewer": {"modules:read"}},
		},
		{
			name: "TRUNCATE empties the table",
			sql:  `TRUNCATE TABLE role_templates;`,
			want: map[string][]string{"viewer": nil, "devops": nil, "auditor": nil, "scratch": nil},
		},
		{
			name: "name IN (...)",
			sql: `UPDATE role_templates SET scopes = scopes || '["scanning:read"]'::jsonb
			      WHERE name IN ('devops', 'auditor');`,
			want: map[string][]string{
				"devops":  {"modules:read", "scanning:read", "scm:manage"},
				"auditor": {"audit:read", "scanning:read"},
				"viewer":  {"modules:read"},
			},
		},
		{
			name: "name <> excludes exactly one row",
			sql: `UPDATE role_templates SET scopes = '["only:this"]'::jsonb
			      WHERE name <> 'viewer' AND is_system = true;`,
			want: map[string][]string{
				"viewer":  {"modules:read"},
				"devops":  {"only:this"},
				"auditor": {"only:this"},
				"scratch": {"modules:read"},
			},
		},
		{
			name: "is_system IS true",
			sql: `UPDATE role_templates SET scopes = scopes || '["everywhere:read"]'::jsonb
			      WHERE is_system IS true;`,
			want: map[string][]string{
				"viewer":  {"everywhere:read", "modules:read"},
				"scratch": {"modules:read"},
			},
		},
		{
			name: "the literal is on the left of ||",
			sql: `UPDATE role_templates SET scopes = '["first:read"]'::jsonb || scopes
			      WHERE name = 'viewer';`,
			want: map[string][]string{"viewer": {"first:read", "modules:read"}},
		},
		{
			name: "subtracting a text ARRAY removes several",
			sql: `UPDATE role_templates SET scopes = scopes - ARRAY['modules:read', 'scm:manage']
			      WHERE name = 'devops';`,
			want: map[string][]string{"devops": {}},
		},
		{
			name: "subtracting one text literal removes one",
			sql:  `UPDATE role_templates SET scopes = scopes - 'scm:manage' WHERE name = 'devops';`,
			want: map[string][]string{"devops": {"modules:read"}},
		},
		{
			name: "no WHERE clause means every row",
			sql:  `UPDATE role_templates SET scopes = '["flat"]'::jsonb;`,
			want: map[string][]string{
				"viewer": {"flat"}, "devops": {"flat"}, "auditor": {"flat"}, "scratch": {"flat"},
			},
		},
		{
			name: "an UPDATE that never touches scopes needs no model",
			sql: `UPDATE role_templates SET display_name = initcap(display_name)
			      WHERE id IN (SELECT role_template_id FROM organization_members);`,
			want: map[string][]string{"viewer": {"modules:read"}},
		},
		{
			name: "reads of the table are not writes",
			sql: `INSERT INTO some_report (n) SELECT count(*) FROM role_templates rt
			      JOIN organization_members om ON om.role_template_id = rt.id
			      WHERE rt.scopes @> '["admin"]'::jsonb;`,
			want: map[string][]string{"viewer": {"modules:read"}},
		},
		{
			name: "INSERT ... ON CONFLICT DO NOTHING keeps the existing row",
			sql: `INSERT INTO role_templates (name, display_name, scopes, is_system)
			      VALUES ('viewer', 'Viewer', '["clobbered"]'::jsonb, true)
			      ON CONFLICT (name) DO NOTHING;`,
			want: map[string][]string{"viewer": {"modules:read"}},
		},
		{
			name: "a block comment and a dollar-quoted tag do not confuse the scanner",
			sql: `/* a /* nested */ comment mentioning role_templates and scopes */
			      DO $tag$
			      BEGIN
			        UPDATE role_templates SET scopes = '["from:tag"]'::jsonb WHERE name = 'viewer';
			      END
			      $tag$;`,
			want: map[string][]string{"viewer": {"from:tag"}},
		},
		{
			name: "a semicolon inside a string literal does not end the statement",
			sql: `UPDATE role_templates SET description = 'one; two', scopes = '["kept"]'::jsonb
			      WHERE name = 'viewer';`,
			want: map[string][]string{"viewer": {"kept"}},
		},
		{
			name: "identity's copy is deliberately not modelled",
			sql:  `UPDATE identity.role_templates SET scopes = ARRAY['ignored'] WHERE name = 'viewer';`,
			want: map[string][]string{"viewer": {"modules:read"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "000001_base.up.sql", base)
			write(t, dir, "000002_case.up.sql", tc.sql)

			policies, err := FromMigrations(dir)
			if err != nil {
				t.Fatalf("FromMigrations: %v", err)
			}
			got := policies[RoleTemplatesTable]
			for name, wantScopes := range tc.want {
				tmpl, present := got[name]
				if wantScopes == nil {
					if present {
						t.Errorf("template %q survived, scopes %v", name, tmpl.Scopes)
					}
					continue
				}
				if !present {
					t.Errorf("template %q is missing", name)
					continue
				}
				if len(tmpl.Scopes) == 0 && len(wantScopes) == 0 {
					continue
				}
				if !reflect.DeepEqual(tmpl.Scopes, wantScopes) {
					t.Errorf("template %q scopes = %v, want %v", name, tmpl.Scopes, wantScopes)
				}
			}
		})
	}
}

// TestUnmodelledErrorNamesTheFileAndTheStatement: the message is the whole
// remedy. A guard that fails without saying which migration it choked on gets
// worked around rather than taught.
func TestUnmodelledErrorNamesTheFileAndTheStatement(t *testing.T) {
	e := &UnmodelledError{
		File:   "000099_probe.up.sql",
		Reason: "SET scopes = mystery(scopes)",
		Stmt:   "UPDATE role_templates SET scopes = mystery(scopes)",
	}
	msg := e.Error()
	for _, want := range []string{"000099_probe.up.sql", "mystery(scopes)", "rolepolicy"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not mention %q:\n%s", want, msg)
		}
	}
	long := &UnmodelledError{File: "f", Reason: "r", Stmt: strings.Repeat("x ", 900)}
	if len(long.Error()) > 1500 {
		t.Errorf("an oversized statement is not truncated; message is %d bytes", len(long.Error()))
	}
}

// TestFromMigrationsRefusesAnEmptyDirectory: a deriver pointed at nothing
// reports a policy of nothing, which agrees with every Go list there is.
func TestFromMigrationsRefusesAnEmptyDirectory(t *testing.T) {
	if _, err := FromMigrations(t.TempDir()); err == nil {
		t.Fatal("FromMigrations accepted a directory with no migrations")
	}
	if _, err := FromMigrations(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("FromMigrations accepted a directory that does not exist")
	}
	if _, err := HeadVersion(t.TempDir()); err == nil {
		t.Fatal("HeadVersion accepted a directory with no migrations")
	}
}
