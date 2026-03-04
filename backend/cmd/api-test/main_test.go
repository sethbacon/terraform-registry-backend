package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"
	"time"
)

// ── parseResp ────────────────────────────────────────────────────────────────

func TestParseResp_Empty(t *testing.T) {
	r := parseResp(200, []byte{}, time.Millisecond)
	if r.Code != 200 {
		t.Errorf("want Code=200, got %d", r.Code)
	}
	if r.IsArray || r.IsNull || r.Object != nil {
		t.Error("empty body should leave all flags false and Object nil")
	}
}

func TestParseResp_WhitespaceOnly(t *testing.T) {
	r := parseResp(200, []byte("   \n"), time.Millisecond)
	if r.IsArray || r.IsNull {
		t.Error("whitespace-only should be treated as empty")
	}
}

func TestParseResp_Null(t *testing.T) {
	r := parseResp(200, []byte("null"), time.Millisecond)
	if !r.IsNull {
		t.Error("want IsNull=true")
	}
	if r.IsArray {
		t.Error("want IsArray=false for null")
	}
}

func TestParseResp_Array(t *testing.T) {
	r := parseResp(200, []byte(`[{"a":1},{"b":2}]`), time.Millisecond)
	if !r.IsArray {
		t.Error("want IsArray=true")
	}
	if len(r.Array) != 2 {
		t.Errorf("want Array len=2, got %d", len(r.Array))
	}
}

func TestParseResp_Object(t *testing.T) {
	r := parseResp(200, []byte(`{"key":"value"}`), time.Millisecond)
	if r.IsArray {
		t.Error("want IsArray=false for object")
	}
	if r.Object == nil {
		t.Fatal("want Object non-nil")
	}
	if r.Object["key"] != "value" {
		t.Errorf("want Object[key]=value, got %v", r.Object["key"])
	}
}

func TestParseResp_StatusCodePreserved(t *testing.T) {
	r := parseResp(404, []byte(`{"error":"not found"}`), 5*time.Millisecond)
	if r.Code != 404 {
		t.Errorf("want Code=404, got %d", r.Code)
	}
	if r.Elapsed != 5*time.Millisecond {
		t.Errorf("want Elapsed=5ms, got %v", r.Elapsed)
	}
}

// ── checkFields ──────────────────────────────────────────────────────────────

func TestCheckFields_Nil(t *testing.T) {
	note := checkFields(nil, "id", "name")
	if note != "response object is nil" {
		t.Errorf("unexpected note: %q", note)
	}
}

func TestCheckFields_AllPresent(t *testing.T) {
	m := map[string]interface{}{"id": "1", "name": "foo"}
	if note := checkFields(m, "id", "name"); note != "" {
		t.Errorf("want empty note, got %q", note)
	}
}

func TestCheckFields_Missing(t *testing.T) {
	m := map[string]interface{}{"id": "1"}
	note := checkFields(m, "id", "name", "email")
	if note == "" {
		t.Error("want non-empty note for missing fields")
	}
	// should mention missing keys
	if !bytes.Contains([]byte(note), []byte("name")) {
		t.Errorf("note should mention 'name', got %q", note)
	}
}

func TestCheckFields_TitleCasedFallback(t *testing.T) {
	// checkFields accepts Title-cased variants (first letter capitalised): "id" → "Id", "name" → "Name"
	m := map[string]interface{}{"Id": "1", "Name": "foo"}
	if note := checkFields(m, "id", "name"); note != "" {
		t.Errorf("title-case fallback failed, got note %q", note)
	}
}

// ── str ──────────────────────────────────────────────────────────────────────

func TestStr_Nil(t *testing.T) {
	if got := str(nil, "key"); got != "" {
		t.Errorf("want empty string for nil map, got %q", got)
	}
}

func TestStr_Present(t *testing.T) {
	m := map[string]interface{}{"key": "value"}
	if got := str(m, "key"); got != "value" {
		t.Errorf("want 'value', got %q", got)
	}
}

func TestStr_TitleCaseFallback(t *testing.T) {
	m := map[string]interface{}{"Key": "value"}
	if got := str(m, "key"); got != "value" {
		t.Errorf("title-case fallback failed, want 'value', got %q", got)
	}
}

func TestStr_Missing(t *testing.T) {
	m := map[string]interface{}{"other": "x"}
	if got := str(m, "key"); got != "" {
		t.Errorf("want empty string for missing key, got %q", got)
	}
}

func TestStr_NonString(t *testing.T) {
	m := map[string]interface{}{"key": 42}
	if got := str(m, "key"); got != "" {
		t.Errorf("want empty string for non-string value, got %q", got)
	}
}

// ── nested ───────────────────────────────────────────────────────────────────

func TestNested_Nil(t *testing.T) {
	if got := nested(nil, "key"); got != nil {
		t.Errorf("want nil for nil map, got %v", got)
	}
}

func TestNested_Present(t *testing.T) {
	sub := map[string]interface{}{"x": 1}
	m := map[string]interface{}{"key": sub}
	got := nested(m, "key")
	if got == nil {
		t.Fatal("want non-nil nested map")
	}
	if got["x"] != 1 {
		t.Errorf("want x=1, got %v", got["x"])
	}
}

func TestNested_TitleCaseFallback(t *testing.T) {
	sub := map[string]interface{}{"x": 1}
	m := map[string]interface{}{"Key": sub}
	if got := nested(m, "key"); got == nil {
		t.Error("title-case fallback failed")
	}
}

func TestNested_Missing(t *testing.T) {
	m := map[string]interface{}{"other": "x"}
	if got := nested(m, "key"); got != nil {
		t.Errorf("want nil for missing key, got %v", got)
	}
}

func TestNested_NonMap(t *testing.T) {
	m := map[string]interface{}{"key": "string-not-map"}
	if got := nested(m, "key"); got != nil {
		t.Errorf("want nil when value is not a map, got %v", got)
	}
}

// ── fmtWant ──────────────────────────────────────────────────────────────────

func TestFmtWant_Single(t *testing.T) {
	if got := fmtWant([]int{200}); got != "200" {
		t.Errorf("want '200', got %q", got)
	}
}

func TestFmtWant_Multiple(t *testing.T) {
	if got := fmtWant([]int{200, 201}); got != "200 or 201" {
		t.Errorf("want '200 or 201', got %q", got)
	}
}

func TestFmtWant_Empty(t *testing.T) {
	if got := fmtWant(nil); got != "" {
		t.Errorf("want empty string for nil slice, got %q", got)
	}
}

// ── makeTarGz ────────────────────────────────────────────────────────────────

func TestMakeTarGz_ValidArchive(t *testing.T) {
	data := makeTarGz()
	if len(data) == 0 {
		t.Fatal("makeTarGz returned empty bytes")
	}

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("not valid gzip: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("no tar entry: %v", err)
	}
	if hdr.Name != "main.tf" {
		t.Errorf("want entry name 'main.tf', got %q", hdr.Name)
	}
	body, _ := io.ReadAll(tr)
	if !bytes.Contains(body, []byte("terraform")) {
		t.Errorf("expected terraform content in main.tf, got %q", body)
	}
}

// ── makeProviderZip ──────────────────────────────────────────────────────────

func TestMakeProviderZip_ValidArchive(t *testing.T) {
	data := makeProviderZip()
	if len(data) == 0 {
		t.Fatal("makeProviderZip returned empty bytes")
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not valid zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("want 1 file in zip, got %d", len(zr.File))
	}
	if zr.File[0].Name != "terraform-provider-testprovider_0.1.0_linux_amd64" {
		t.Errorf("unexpected file name: %q", zr.File[0].Name)
	}
}

// ── record / skipTest ────────────────────────────────────────────────────────

func TestRecord_Pass(t *testing.T) {
	// Save and restore global state.
	origPassed, origFailed, origSkipped := passed, failed, skipped
	origFailed2 := failedTests
	defer func() {
		passed, failed, skipped = origPassed, origFailed, origSkipped
		failedTests = origFailed2
	}()

	passed, failed, skipped = 0, 0, 0
	failedTests = nil

	ok := record("GET", "/test", 200, []int{200}, time.Millisecond, "")
	if !ok {
		t.Error("want true for matching status code")
	}
	if passed != 1 || failed != 0 {
		t.Errorf("want passed=1 failed=0, got passed=%d failed=%d", passed, failed)
	}
}

func TestRecord_Fail(t *testing.T) {
	origPassed, origFailed, origSkipped := passed, failed, skipped
	origFailed2 := failedTests
	defer func() {
		passed, failed, skipped = origPassed, origFailed, origSkipped
		failedTests = origFailed2
	}()

	passed, failed, skipped = 0, 0, 0
	failedTests = nil

	ok := record("GET", "/test", 500, []int{200}, time.Millisecond, "")
	if ok {
		t.Error("want false for non-matching status code")
	}
	if failed != 1 || passed != 0 {
		t.Errorf("want failed=1 passed=0, got failed=%d passed=%d", failed, passed)
	}
	if len(failedTests) != 1 {
		t.Errorf("want 1 entry in failedTests, got %d", len(failedTests))
	}
}

func TestRecord_WithNote(t *testing.T) {
	origPassed, origFailed, origSkipped := passed, failed, skipped
	origFailed2 := failedTests
	defer func() {
		passed, failed, skipped = origPassed, origFailed, origSkipped
		failedTests = origFailed2
	}()

	passed, failed, skipped = 0, 0, 0
	failedTests = nil

	ok := record("GET", "/test", 200, []int{200}, time.Millisecond, "some extra context")
	if !ok {
		t.Error("want true for matching status code")
	}
	if passed != 1 {
		t.Errorf("want passed=1, got %d", passed)
	}
}

func TestSkipTest(t *testing.T) {
	origPassed, origFailed, origSkipped := passed, failed, skipped
	defer func() { passed, failed, skipped = origPassed, origFailed, origSkipped }()

	passed, failed, skipped = 0, 0, 0
	skipTest("GET", "/test", "prerequisite failed")
	if skipped != 1 {
		t.Errorf("want skipped=1, got %d", skipped)
	}
}

// ── APIResp JSON roundtrip ────────────────────────────────────────────────────

func TestAPIResp_RawPreserved(t *testing.T) {
	raw := []byte(`{"status":"ok"}`)
	r := parseResp(200, raw, 0)
	if !bytes.Equal(r.Raw, raw) {
		t.Errorf("Raw bytes not preserved: got %q", r.Raw)
	}

	// Ensure the object is accessible via checkFields
	note := checkFields(r.Object, "status")
	if note != "" {
		t.Errorf("expected status field present, got note %q", note)
	}
}

func TestParseResp_ObjectJSON(t *testing.T) {
	payload := map[string]interface{}{
		"organizations": []interface{}{},
		"pagination":    map[string]interface{}{"total": float64(0)},
	}
	raw, _ := json.Marshal(payload)
	r := parseResp(200, raw, 0)
	if r.IsArray {
		t.Error("should not be array")
	}
	note := checkFields(r.Object, "organizations", "pagination")
	if note != "" {
		t.Errorf("field check failed: %s", note)
	}
}
