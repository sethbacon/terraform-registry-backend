package db_test

import (
	"os"
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
