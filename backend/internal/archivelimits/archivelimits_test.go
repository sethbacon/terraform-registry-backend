package archivelimits

import "testing"

// TestLimitsAreSourceOfTruth pins the values both the upload-time validator
// (internal/validation) and the extraction guard (internal/archiver) rely on,
// so a change here is a deliberate, reviewed change to both guards rather
// than an accidental drift between two independently-defined constants.
func TestLimitsAreSourceOfTruth(t *testing.T) {
	if MaxBytes != 100<<20 {
		t.Errorf("MaxBytes = %d, want %d", MaxBytes, 100<<20)
	}
	if MaxEntries != 100000 {
		t.Errorf("MaxEntries = %d, want %d", MaxEntries, 100000)
	}
}
