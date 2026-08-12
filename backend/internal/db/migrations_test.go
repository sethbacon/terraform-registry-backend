package db_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestMigrationFilesAreConsistent(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	upCount := 0
	downCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			upCount++
		}
		if strings.HasSuffix(e.Name(), ".down.sql") {
			downCount++
		}
	}
	if upCount != downCount {
		t.Errorf("migration up/down count mismatch: %d up, %d down", upCount, downCount)
	}
}

// migrations/README.md is the rollback reference an operator reads during an
// incident, and it is maintained by hand. It has already drifted once: it sat
// at 46 rows while the directory held 49 migrations, so the four newest had no
// documented rollback behaviour at exactly the moment someone would need it,
// and nothing failed. Drift is invisible in review because the row and the file
// live in different diffs.
//
// The check is BIDIRECTIONAL by number and by name. Undocumented migrations are
// the reported failure, but a stale row (documenting a migration that no longer
// exists, or naming one that was renamed) is just as wrong and fails here too --
// a one-way check would let the table rot in the other direction.
func TestMigrationsAreDocumented(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]string{} // number -> name
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".up.sql")
		if !ok {
			continue
		}
		num, rest, ok := strings.Cut(name, "_")
		if !ok {
			t.Errorf("migration %q is not <number>_<name>.up.sql", e.Name())
			continue
		}
		onDisk[num] = rest
	}
	if len(onDisk) == 0 {
		// Guard the guard: a bad path or a changed filename convention would
		// make every assertion below vacuously true.
		t.Fatal("no .up.sql migrations found - this test would pass vacuously")
	}

	readme, err := os.ReadFile("migrations/README.md")
	if err != nil {
		t.Fatal(err)
	}
	// | 000001 | `initial_schema` | ...
	row := regexp.MustCompile("(?m)^\\|\\s*(\\d{6})\\s*\\|\\s*`([^`]+)`")
	documented := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(string(readme), -1) {
		documented[m[1]] = m[2]
	}

	for num, name := range onDisk {
		got, ok := documented[num]
		if !ok {
			t.Errorf("migration %s_%s is not documented in migrations/README.md - add a row with its rollback behaviour", num, name)
			continue
		}
		if got != name {
			t.Errorf("migrations/README.md documents %s as %q, but the migration on disk is %q", num, got, name)
		}
	}
	for num, name := range documented {
		if _, ok := onDisk[num]; !ok {
			t.Errorf("migrations/README.md documents %s (%q), which does not exist on disk - remove the stale row", num, name)
		}
	}
}
