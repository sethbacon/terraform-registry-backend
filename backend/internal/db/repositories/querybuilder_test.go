package repositories

import (
	"testing"
)

func TestWhereBuilder_Empty(t *testing.T) {
	var wb whereBuilder
	clause, args := wb.clause()
	if clause != "" {
		t.Errorf("clause() with no conditions = %q, want empty string", clause)
	}
	if len(args) != 0 {
		t.Errorf("args with no conditions = %v, want empty", args)
	}
	if got := wb.nextPlaceholder(); got != 1 {
		t.Errorf("nextPlaceholder() with no conditions = %d, want 1", got)
	}
}

func TestWhereBuilder_SingleCondition(t *testing.T) {
	var wb whereBuilder
	wb.add("org_id = $%d", "org-1")
	clause, args := wb.clause()
	if clause != "WHERE org_id = $1" {
		t.Errorf("clause() = %q, want %q", clause, "WHERE org_id = $1")
	}
	if len(args) != 1 || args[0] != "org-1" {
		t.Errorf("args = %v, want [org-1]", args)
	}
	if got := wb.nextPlaceholder(); got != 2 {
		t.Errorf("nextPlaceholder() = %d, want 2", got)
	}
}

func TestWhereBuilder_MultipleConditionsAreAndJoinedAndNumberedInOrder(t *testing.T) {
	var wb whereBuilder
	wb.add("org_id = $%d", "org-1")
	wb.add("namespace = $%d", "acme")
	wb.add("system = $%d", "aws")
	clause, args := wb.clause()

	want := "WHERE org_id = $1 AND namespace = $2 AND system = $3"
	if clause != want {
		t.Errorf("clause() = %q, want %q", clause, want)
	}
	if len(args) != 3 || args[0] != "org-1" || args[1] != "acme" || args[2] != "aws" {
		t.Errorf("args = %v, want [org-1 acme aws] in that exact order", args)
	}
	if got := wb.nextPlaceholder(); got != 4 {
		t.Errorf("nextPlaceholder() = %d, want 4", got)
	}
}

// A condition that references one bound value across several columns (e.g. an
// ILIKE search over namespace/name/description) must format the SAME
// placeholder index into every %d and bind only a single argument -- this is
// the exact case the hand-rolled argCount pattern got right and that the
// builder must preserve, since getting it wrong would either misnumber later
// placeholders or bind the wrong number of args.
func TestWhereBuilder_RepeatedPlaceholderBindsSingleArg(t *testing.T) {
	var wb whereBuilder
	wb.add("org_id = $%d", "org-1")
	wb.add("(namespace ILIKE $%d OR name ILIKE $%d OR description ILIKE $%d)", "%foo%")
	wb.add("system = $%d", "aws")
	clause, args := wb.clause()

	want := "WHERE org_id = $1 AND (namespace ILIKE $2 OR name ILIKE $2 OR description ILIKE $2) AND system = $3"
	if clause != want {
		t.Errorf("clause() = %q, want %q", clause, want)
	}
	// Three conditions, but the middle one referenced $2 three times while
	// binding a single value, so there are exactly 3 args -- and the trailing
	// system filter is correctly $3, not $5.
	if len(args) != 3 {
		t.Fatalf("args = %v, want exactly 3 (repeated placeholder must not bind extra args)", args)
	}
	if args[0] != "org-1" || args[1] != "%foo%" || args[2] != "aws" {
		t.Errorf("args = %v, want [org-1 %%foo%% aws]", args)
	}
	if got := wb.nextPlaceholder(); got != 4 {
		t.Errorf("nextPlaceholder() = %d, want 4 (LIMIT/OFFSET would be $4/$5)", got)
	}
}
