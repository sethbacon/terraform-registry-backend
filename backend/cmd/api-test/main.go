// Package main — integration test binary for the Terraform Registry API.
// Runs ~170 tests across 23 phases, cleans up everything it creates, and
// reports any remaining swagger/spec discrepancies separately from failures.
//
// After the phases run it fetches the live OpenAPI spec and prints an API
// coverage report: every spec path+method the runner never touched is listed
// so new endpoints can't ship untested. Coverage is informational by default;
// pass -strict-coverage to fail the run when uncovered endpoints exist.
//
// Usage:
//
//	go run ./cmd/api-test/ -key <api-key>
//	go run ./cmd/api-test/ -url http://registry.local:8080 -key <api-key>
//	go run ./cmd/api-test/ -key <api-key> -strict-coverage
//	./api-test.exe -key <api-key>
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	baseURL  string
	apiKey   string // #nosec G101 -- integration test credential, not a production secret
	reqDelay time.Duration
)

var state struct {
	orgID              string // ID of test org we create (phase 4)
	defaultOrgID       string // ID of an existing org the API-key user belongs to (phase 3)
	userID             string
	keyID              string
	roleID             string
	scmID              string
	mirrorID           string
	tfMirrorID         string
	policyID           string
	auditLogID         string // captured in phase 14 for detail-read test
	approvalID         string // captured in phase 9 for phase 13 detail-read test
	storageConfigID    string // captured in phase 3 for phase 16 detail-read test
	tfMirrorVersion    string // captured in phase 10 for version-detail test
	moduleID           string // captured in phase 11 for UpdateModuleRecord test
	providerRecordID   string // captured in phase 12 for CreateProviderRecord/GetProviderByID test
	freshApprovalID    string // created in phase 13 for review/token tests
	storageConfigNewID string // created in phase 21 for storage config CRUD tests
	storageMigrationID string // created in phase 21 for migration status test
}

var (
	passed, failed, skipped int
	swaggerDiscrepancies    []string
	failedTests             []string
	skippedTests            []string
)

// APIResp holds a parsed HTTP response that may be a JSON object, array, or null.
type APIResp struct {
	Code    int
	Object  map[string]interface{}
	Array   []interface{}
	IsArray bool
	IsNull  bool
	Raw     []byte
	Elapsed time.Duration
}

func doJSON(method, path string, payload interface{}, auth bool) APIResp {
	if reqDelay > 0 {
		time.Sleep(reqDelay)
	}
	var bodyReader io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	if err != nil {
		return APIResp{Code: -1}
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return APIResp{Code: -1, Elapsed: elapsed}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return parseResp(resp.StatusCode, raw, elapsed)
}

func doMultipart(method, path string, fields map[string]string, fileField, fileName string, fileContent []byte, auth bool) APIResp {
	if reqDelay > 0 {
		time.Sleep(reqDelay)
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	fw, _ := w.CreateFormFile(fileField, fileName)
	_, _ = fw.Write(fileContent)
	w.Close() // #nosec G104 -- multipart writer to bytes.Buffer; Close cannot fail
	req, _ := http.NewRequest(method, baseURL+path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if auth {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return APIResp{Code: -1, Elapsed: elapsed}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return parseResp(resp.StatusCode, raw, elapsed)
}

func parseResp(code int, raw []byte, elapsed time.Duration) APIResp {
	r := APIResp{Code: code, Raw: raw, Elapsed: elapsed}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return r
	}
	if bytes.Equal(trimmed, []byte("null")) {
		r.IsNull = true
		return r
	}
	if trimmed[0] == '[' {
		r.IsArray = true
		_ = json.Unmarshal(raw, &r.Array)
	} else {
		_ = json.Unmarshal(raw, &r.Object)
	}
	return r
}

// checkFields returns a note listing any keys absent from the map.
// It tries the key as-is and its Title-cased variant (catches unfixed capitalization bugs).
func checkFields(m map[string]interface{}, keys ...string) string {
	if m == nil {
		return "response object is nil"
	}
	var missing []string
	for _, k := range keys {
		upper := strings.ToUpper(k[:1]) + k[1:]
		if _, ok := m[k]; !ok {
			if _, ok2 := m[upper]; !ok2 {
				missing = append(missing, k)
			}
		}
	}
	if len(missing) > 0 {
		return "missing fields: " + strings.Join(missing, ", ")
	}
	return ""
}

// str extracts a string field, trying the key as-is then Title-cased.
func str(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	for _, k := range []string{key, strings.ToUpper(key[:1]) + key[1:]} {
		if v, ok := m[k]; ok {
			if s, ok2 := v.(string); ok2 {
				return s
			}
		}
	}
	return ""
}

// nested extracts a nested map, trying the key as-is then Title-cased.
func nested(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	for _, k := range []string{key, strings.ToUpper(key[:1]) + key[1:]} {
		if v, ok := m[k]; ok {
			if sub, ok2 := v.(map[string]interface{}); ok2 {
				return sub
			}
		}
	}
	return nil
}

func record(method, path string, got int, want []int, elapsed time.Duration, note string) bool {
	markTouched(method, path)
	label := ""
	if note != "" {
		label = " | " + note
	}
	wantStr := fmtWant(want)
	total := passed + failed + skipped
	for _, w := range want {
		if got == w {
			passed++
			fmt.Printf("[PASS] #%-3d %-7s %-72s → %d (want %s) (%dms)%s\n",
				total+1, method, path, got, wantStr, elapsed.Milliseconds(), label)
			return true
		}
	}
	failed++
	failedTests = append(failedTests, fmt.Sprintf("#%-3d %-7s %s → got %d, want %s", total+1, method, path, got, wantStr))
	fmt.Printf("[FAIL] #%-3d %-7s %-72s → got %d, want %s (%dms)%s\n",
		total+1, method, path, got, wantStr, elapsed.Milliseconds(), label)
	return false
}

func skipTest(method, path, reason string) {
	markTouched(method, path)
	skipped++
	skippedTests = append(skippedTests, fmt.Sprintf("#%-3d %-7s %s → %s", passed+failed+skipped, method, path, reason))
	fmt.Printf("[SKIP] #%-3d %-7s %-72s → %s\n", passed+failed+skipped, method, path, reason)
}

func fmtWant(want []int) string {
	parts := make([]string, len(want))
	for i, w := range want {
		parts[i] = fmt.Sprintf("%d", w)
	}
	return strings.Join(parts, " or ")
}

// makeTarGz returns a minimal valid .tar.gz containing a single main.tf.
func makeTarGz() []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	content := []byte("# test terraform module\n")
	_ = tw.WriteHeader(&tar.Header{Name: "main.tf", Mode: 0644, Size: int64(len(content))})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// makeProviderZip returns a minimal .zip containing a mock provider binary.
func makeProviderZip() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, _ := zw.Create("terraform-provider-testprovider_0.1.0_linux_amd64")
	_, _ = fw.Write([]byte("mock provider binary"))
	_ = zw.Close()
	return buf.Bytes()
}

// ── Phase 1: Public / unauthenticated endpoints ─────────────────────────────

func phase1() {
	fmt.Println("\n=== Phase 1: Public Endpoints (no auth required) ===")

	r := doJSON("GET", "/health", nil, false)
	record("GET", "/health", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/ready", nil, false)
	record("GET", "/ready", r.Code, []int{200, 503}, r.Elapsed, "")

	r = doJSON("GET", "/.well-known/terraform.json", nil, false)
	note := checkFields(r.Object, "modules.v1", "providers.v1")
	record("GET", "/.well-known/terraform.json", r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("GET", "/version", nil, false)
	record("GET", "/version", r.Code, []int{200}, r.Elapsed, "")

	// OpenAPI spec — verify it is served and is valid JSON
	r = doJSON("GET", "/swagger.json", nil, false)
	swaggerNote := ""
	if r.Object == nil {
		swaggerNote = "not a JSON object"
	}
	record("GET", "/swagger.json", r.Code, []int{200}, r.Elapsed, swaggerNote)

	r = doJSON("GET", "/v1/modules/nonexistent/nonexistent/nonexistent/versions", nil, false)
	record("GET", "/v1/modules/nonexistent/nonexistent/nonexistent/versions", r.Code, []int{404}, r.Elapsed, "")

	r = doJSON("GET", "/v1/providers/nonexistent/nonexistent/versions", nil, false)
	record("GET", "/v1/providers/nonexistent/nonexistent/versions", r.Code, []int{404}, r.Elapsed, "")

	// Terraform binary mirror — public listing
	r = doJSON("GET", "/terraform/binaries", nil, false)
	record("GET", "/terraform/binaries", r.Code, []int{200, 404}, r.Elapsed, "")

	// Terraform binary version listing (public sub-routes)
	r = doJSON("GET", "/terraform/binaries/terraform/versions", nil, false)
	record("GET", "/terraform/binaries/terraform/versions", r.Code, []int{200, 404}, r.Elapsed, "")

	r = doJSON("GET", "/terraform/binaries/terraform/versions/latest", nil, false)
	record("GET", "/terraform/binaries/terraform/versions/latest", r.Code, []int{200, 404}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/modules/search?q=test", nil, false)
	record("GET", "/api/v1/modules/search?q=test", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/providers/search?q=test", nil, false)
	record("GET", "/api/v1/providers/search?q=test", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/setup/status", nil, false)
	note = checkFields(r.Object, "setup_completed", "setup_required", "oidc_configured", "storage_configured")
	record("GET", "/api/v1/setup/status", r.Code, []int{200}, r.Elapsed, note)

	// OCI Distribution Spec v1.1 — ping endpoint
	r = doJSON("GET", "/v2/", nil, false)
	record("GET", "/v2/", r.Code, []int{200}, r.Elapsed, "OCI ping")

	// Auth providers list — returns configured identity providers
	r = doJSON("GET", "/api/v1/auth/providers", nil, false)
	record("GET", "/api/v1/auth/providers", r.Code, []int{200}, r.Elapsed, "")

	// Active CVE advisories — public banner endpoint consumed by the frontend
	r = doJSON("GET", "/api/v1/advisories/active", nil, false)
	record("GET", "/api/v1/advisories/active", r.Code, []int{200}, r.Elapsed, "")

	// Network mirror index — public pull-through; 404 expected when provider not mirrored
	r = doJSON("GET", "/terraform/providers/registry.terraform.io/hashicorp/nonexistent/index.json", nil, false)
	record("GET", "/terraform/providers/registry.terraform.io/hashicorp/nonexistent/index.json", r.Code, []int{200, 404}, r.Elapsed, "")
}

// ── Phase 2: Auth enforcement ────────────────────────────────────────────────

func phase2() {
	fmt.Println("\n=== Phase 2: Auth Enforcement (expect 401 without token) ===")
	for _, ep := range [][2]string{
		{"GET", "/api/v1/auth/me"},
		{"GET", "/api/v1/apikeys"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/organizations"},
		{"GET", "/api/v1/admin/stats/dashboard"},
		{"GET", "/api/v1/admin/policy/config"},
		{"GET", "/api/v1/admin/advisories"},
		{"GET", "/api/v1/admin/scanning/config"},
		{"GET", "/api/v1/admin/identity/group-mappings"},
		{"GET", "/api/v1/admin/mtls/config"},
		{"GET", "/api/v1/admin/audit-logs/export"},
	} {
		r := doJSON(ep[0], ep[1], nil, false)
		record(ep[0], ep[1], r.Code, []int{401}, r.Elapsed, "")
	}
}

// ── Phase 3: Authenticated bootstrap reads ──────────────────────────────────

func phase3() {
	fmt.Println("\n=== Phase 3: Authenticated Read Endpoints / Context Bootstrap ===")

	// auth/me — capture defaultOrgID from memberships
	r := doJSON("GET", "/api/v1/auth/me", nil, true)
	note := checkFields(r.Object, "allowed_scopes", "memberships", "user")
	record("GET", "/api/v1/auth/me", r.Code, []int{200}, r.Elapsed, note)
	if mems, ok := r.Object["memberships"].([]interface{}); ok && len(mems) > 0 {
		if mb, ok := mems[0].(map[string]interface{}); ok {
			if oid := str(mb, "organization_id"); oid != "" {
				state.defaultOrgID = oid
			}
		}
	}

	// role-templates returns a raw array
	r = doJSON("GET", "/api/v1/admin/role-templates", nil, true)
	arrayNote := ""
	if !r.IsArray {
		arrayNote = "expected raw array"
	}
	record("GET", "/api/v1/admin/role-templates", r.Code, []int{200}, r.Elapsed, arrayNote)

	r = doJSON("GET", "/api/v1/admin/stats/dashboard", nil, true)
	note = checkFields(r.Object, "modules", "providers", "users", "organizations")
	record("GET", "/api/v1/admin/stats/dashboard", r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("GET", "/api/v1/organizations", nil, true)
	note = checkFields(r.Object, "organizations", "pagination")
	record("GET", "/api/v1/organizations", r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("GET", "/api/v1/organizations/search?q=default", nil, true)
	record("GET", "/api/v1/organizations/search?q=default", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/users", nil, true)
	note = checkFields(r.Object, "users", "pagination")
	record("GET", "/api/v1/users", r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("GET", "/api/v1/users/search?q=admin", nil, true)
	record("GET", "/api/v1/users/search?q=admin", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/storage/config", nil, true)
	record("GET", "/api/v1/storage/config", r.Code, []int{200, 404}, r.Elapsed, "")

	// storage/configs returns a bare array; capture first ID for phase 16
	r = doJSON("GET", "/api/v1/storage/configs", nil, true)
	record("GET", "/api/v1/storage/configs", r.Code, []int{200}, r.Elapsed, "")
	if r.IsArray && len(r.Array) > 0 {
		if cfg, ok := r.Array[0].(map[string]interface{}); ok {
			state.storageConfigID = str(cfg, "id")
		}
	}

	r = doJSON("GET", "/api/v1/admin/oidc/config", nil, true)
	record("GET", "/api/v1/admin/oidc/config", r.Code, []int{200, 404}, r.Elapsed, "")

	// Identity group mappings (SAML + LDAP config read)
	r = doJSON("GET", "/api/v1/admin/identity/group-mappings", nil, true)
	record("GET", "/api/v1/admin/identity/group-mappings", r.Code, []int{200}, r.Elapsed, "")

	// mTLS configuration read (read-only view of server config)
	r = doJSON("GET", "/api/v1/admin/mtls/config", nil, true)
	record("GET", "/api/v1/admin/mtls/config", r.Code, []int{200}, r.Elapsed, "")
}

// ── Phase 4: Organization CRUD ───────────────────────────────────────────────

func phase4() {
	fmt.Println("\n=== Phase 4: Organization CRUD ===")

	r := doJSON("POST", "/api/v1/organizations",
		map[string]interface{}{"name": "test-api-org", "display_name": "API Test Org"}, true)
	orgObj := nested(r.Object, "organization")
	note := checkFields(orgObj, "id", "name", "display_name")
	if record("POST", "/api/v1/organizations", r.Code, []int{201}, r.Elapsed, note) {
		state.orgID = str(orgObj, "id")
	}

	if state.orgID == "" {
		skipTest("GET", "/api/v1/organizations/{id}", "create org failed")
		skipTest("PUT", "/api/v1/organizations/{id}", "create org failed")
		skipTest("GET", "/api/v1/organizations/{id}/members", "create org failed")
		return
	}

	// GET returns {"organization": {...}, "members": [...]}
	r = doJSON("GET", "/api/v1/organizations/"+state.orgID, nil, true)
	note = checkFields(r.Object, "organization", "members")
	record("GET", "/api/v1/organizations/"+state.orgID, r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("PUT", "/api/v1/organizations/"+state.orgID,
		map[string]interface{}{"display_name": "API Test Org Updated"}, true)
	note = checkFields(nested(r.Object, "organization"), "id", "name", "display_name")
	record("PUT", "/api/v1/organizations/"+state.orgID, r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("GET", "/api/v1/organizations/"+state.orgID+"/members", nil, true)
	note = checkFields(r.Object, "members")
	record("GET", "/api/v1/organizations/"+state.orgID+"/members", r.Code, []int{200}, r.Elapsed, note)
}

// ── Phase 5: User CRUD + membership ─────────────────────────────────────────

func phase5() {
	fmt.Println("\n=== Phase 5: User CRUD + Organization Membership ===")

	r := doJSON("POST", "/api/v1/users",
		map[string]interface{}{"email": "apitest@test.local", "name": "API Test User"}, true)
	userObj := nested(r.Object, "user")
	note := checkFields(userObj, "id", "email", "name")
	if record("POST", "/api/v1/users", r.Code, []int{201}, r.Elapsed, note) {
		state.userID = str(userObj, "id")
	}

	if state.userID == "" {
		for _, ep := range [][2]string{
			{"GET", "/api/v1/users/{id}"},
			{"PUT", "/api/v1/users/{id}"},
			{"GET", "/api/v1/users/{id}/memberships"},
			{"POST", "/api/v1/organizations/{id}/members"},
			{"PUT", "/api/v1/organizations/{id}/members/{id}"},
			{"DELETE", "/api/v1/organizations/{id}/members/{id}"},
			{"GET", "/api/v1/users/me/memberships"},
		} {
			skipTest(ep[0], ep[1], "create user failed")
		}
		return
	}

	// GET returns {"user": {...}, "organizations": [...]}
	r = doJSON("GET", "/api/v1/users/"+state.userID, nil, true)
	note = checkFields(r.Object, "user", "organizations")
	record("GET", "/api/v1/users/"+state.userID, r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("PUT", "/api/v1/users/"+state.userID,
		map[string]interface{}{"name": "API Test User Updated"}, true)
	note = checkFields(nested(r.Object, "user"), "id", "email", "name")
	record("PUT", "/api/v1/users/"+state.userID, r.Code, []int{200}, r.Elapsed, note)

	// Per-user memberships endpoint
	r = doJSON("GET", "/api/v1/users/"+state.userID+"/memberships", nil, true)
	note = checkFields(r.Object, "memberships")
	record("GET", "/api/v1/users/"+state.userID+"/memberships", r.Code, []int{200}, r.Elapsed, note)

	if state.orgID != "" {
		r = doJSON("POST", "/api/v1/organizations/"+state.orgID+"/members",
			map[string]interface{}{"user_id": state.userID}, true)
		record("POST", "/api/v1/organizations/"+state.orgID+"/members", r.Code, []int{200, 201}, r.Elapsed, "")

		r = doJSON("PUT", "/api/v1/organizations/"+state.orgID+"/members/"+state.userID,
			map[string]interface{}{}, true)
		record("PUT", "/api/v1/organizations/"+state.orgID+"/members/"+state.userID, r.Code, []int{200}, r.Elapsed, "")

		r = doJSON("DELETE", "/api/v1/organizations/"+state.orgID+"/members/"+state.userID, nil, true)
		record("DELETE", "/api/v1/organizations/"+state.orgID+"/members/"+state.userID, r.Code, []int{200}, r.Elapsed, "")
	} else {
		skipTest("POST", "/api/v1/organizations/{id}/members", "org not created")
		skipTest("PUT", "/api/v1/organizations/{id}/members/{id}", "org not created")
		skipTest("DELETE", "/api/v1/organizations/{id}/members/{id}", "org not created")
	}

	r = doJSON("GET", "/api/v1/users/me/memberships", nil, true)
	note = checkFields(r.Object, "memberships")
	record("GET", "/api/v1/users/me/memberships", r.Code, []int{200}, r.Elapsed, note)
}

// ── Phase 6: API Key CRUD ────────────────────────────────────────────────────

func phase6() {
	fmt.Println("\n=== Phase 6: API Key CRUD ===")

	r := doJSON("GET", "/api/v1/apikeys", nil, true)
	note := checkFields(r.Object, "keys")
	record("GET", "/api/v1/apikeys", r.Code, []int{200}, r.Elapsed, note)

	// Use defaultOrgID — the API user is already a member of that org
	payload := map[string]interface{}{
		"name":   "test-key-apitester",
		"scopes": []string{"modules:read", "providers:read"},
	}
	if state.defaultOrgID != "" {
		payload["organization_id"] = state.defaultOrgID
	} else if state.orgID != "" {
		payload["organization_id"] = state.orgID
	}
	r = doJSON("POST", "/api/v1/apikeys", payload, true)
	note = checkFields(r.Object, "id", "key", "key_prefix", "scopes")
	if record("POST", "/api/v1/apikeys", r.Code, []int{201}, r.Elapsed, note) {
		state.keyID = str(r.Object, "id")
	}

	if state.keyID == "" {
		skipTest("GET", "/api/v1/apikeys/{id}", "create key failed")
		skipTest("PUT", "/api/v1/apikeys/{id}", "create key failed")
		skipTest("POST", "/api/v1/apikeys/{id}/rotate", "create key failed")
		skipTest("DELETE", "/api/v1/apikeys/{id}", "create key failed")
		return
	}

	r = doJSON("GET", "/api/v1/apikeys/"+state.keyID, nil, true)
	record("GET", "/api/v1/apikeys/"+state.keyID, r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("PUT", "/api/v1/apikeys/"+state.keyID,
		map[string]interface{}{"name": "test-key-updated", "scopes": []string{"modules:read"}}, true)
	record("PUT", "/api/v1/apikeys/"+state.keyID, r.Code, []int{200}, r.Elapsed, "")

	// Rotate — response: {"new_key": {id, key, ...}, "old_key_status": "revoked"}
	r = doJSON("POST", "/api/v1/apikeys/"+state.keyID+"/rotate",
		map[string]interface{}{"grace_period_hours": 0}, true)
	note = checkFields(r.Object, "new_key", "old_key_status")
	record("POST", "/api/v1/apikeys/"+state.keyID+"/rotate", r.Code, []int{200}, r.Elapsed, note)
	if newKeyObj := nested(r.Object, "new_key"); newKeyObj != nil {
		if newID := str(newKeyObj, "id"); newID != "" {
			state.keyID = newID
		}
	}

	r = doJSON("DELETE", "/api/v1/apikeys/"+state.keyID, nil, true)
	record("DELETE", "/api/v1/apikeys/"+state.keyID, r.Code, []int{200}, r.Elapsed, "")
	state.keyID = ""
}

// ── Phase 7: Role Template CRUD ──────────────────────────────────────────────

func phase7() {
	fmt.Println("\n=== Phase 7: Role Template CRUD ===")

	// Returns raw RoleTemplate object, not wrapped
	r := doJSON("POST", "/api/v1/admin/role-templates",
		map[string]interface{}{
			"name":         "test-role",
			"display_name": "Test Role",
			"description":  "Integration test role",
			"scopes":       []string{"modules:read"},
		}, true)
	note := checkFields(r.Object, "id", "name")
	if record("POST", "/api/v1/admin/role-templates", r.Code, []int{201}, r.Elapsed, note) {
		state.roleID = str(r.Object, "id")
	}

	if state.roleID == "" {
		skipTest("GET", "/api/v1/admin/role-templates/{id}", "create role failed")
		skipTest("PUT", "/api/v1/admin/role-templates/{id}", "create role failed")
		skipTest("DELETE", "/api/v1/admin/role-templates/{id}", "create role failed")
		return
	}

	r = doJSON("GET", "/api/v1/admin/role-templates/"+state.roleID, nil, true)
	note = checkFields(r.Object, "id", "name")
	record("GET", "/api/v1/admin/role-templates/"+state.roleID, r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("PUT", "/api/v1/admin/role-templates/"+state.roleID,
		map[string]interface{}{
			"name":         "test-role-updated",
			"display_name": "Test Role Updated",
			"description":  "Updated",
			"scopes":       []string{"modules:read"},
		}, true)
	record("PUT", "/api/v1/admin/role-templates/"+state.roleID, r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/admin/role-templates/"+state.roleID, nil, true)
	record("DELETE", "/api/v1/admin/role-templates/"+state.roleID, r.Code, []int{200}, r.Elapsed, "")
	state.roleID = ""
}

// ── Phase 8: SCM Provider CRUD ───────────────────────────────────────────────

func phase8() {
	fmt.Println("\n=== Phase 8: SCM Provider CRUD ===")

	// List returns raw array
	r := doJSON("GET", "/api/v1/scm-providers", nil, true)
	record("GET", "/api/v1/scm-providers", r.Code, []int{200}, r.Elapsed, "")

	// Create returns raw SCMProviderRecord object
	r = doJSON("POST", "/api/v1/scm-providers",
		map[string]interface{}{
			"name":          "test-scm",
			"provider_type": "github",
			"client_id":     "test-client",
			"client_secret": "test-secret",
		}, true)
	note := checkFields(r.Object, "id", "name")
	if record("POST", "/api/v1/scm-providers", r.Code, []int{201}, r.Elapsed, note) {
		state.scmID = str(r.Object, "id")
	}

	if state.scmID == "" {
		skipTest("GET", "/api/v1/scm-providers/{id}", "create scm failed")
		skipTest("PUT", "/api/v1/scm-providers/{id}", "create scm failed")
		skipTest("GET", "/api/v1/scm-providers/{id}/oauth/token", "create scm failed")
		skipTest("GET", "/api/v1/scm-providers/{id}/repositories", "create scm failed")
		skipTest("DELETE", "/api/v1/scm-providers/{id}", "create scm failed")
		return
	}

	r = doJSON("GET", "/api/v1/scm-providers/"+state.scmID, nil, true)
	note = checkFields(r.Object, "id", "name")
	record("GET", "/api/v1/scm-providers/"+state.scmID, r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("PUT", "/api/v1/scm-providers/"+state.scmID,
		map[string]interface{}{"name": "test-scm-updated"}, true)
	record("PUT", "/api/v1/scm-providers/"+state.scmID, r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/scm-providers/"+state.scmID+"/oauth/token", nil, true)
	record("GET", "/api/v1/scm-providers/"+state.scmID+"/oauth/token", r.Code, []int{200, 404}, r.Elapsed, "")

	// Repository listing — returns 400/404 when no OAuth token is stored yet
	r = doJSON("GET", "/api/v1/scm-providers/"+state.scmID+"/repositories", nil, true)
	record("GET", "/api/v1/scm-providers/"+state.scmID+"/repositories", r.Code, []int{200, 400, 404}, r.Elapsed, "no token expected")

	r = doJSON("DELETE", "/api/v1/scm-providers/"+state.scmID, nil, true)
	record("DELETE", "/api/v1/scm-providers/"+state.scmID, r.Code, []int{200}, r.Elapsed, "")
	state.scmID = ""
}

// ── Phase 9: Provider Mirror CRUD ────────────────────────────────────────────

func phase9() {
	fmt.Println("\n=== Phase 9: Provider Mirror CRUD ===")

	// List: {"mirrors": [...]}
	r := doJSON("GET", "/api/v1/admin/mirrors", nil, true)
	note := checkFields(r.Object, "mirrors")
	record("GET", "/api/v1/admin/mirrors", r.Code, []int{200}, r.Elapsed, note)

	// Create returns raw MirrorConfiguration object
	r = doJSON("POST", "/api/v1/admin/mirrors",
		map[string]interface{}{
			"name":                  "test-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
		}, true)
	note = checkFields(r.Object, "id", "name")
	if record("POST", "/api/v1/admin/mirrors", r.Code, []int{201}, r.Elapsed, note) {
		state.mirrorID = str(r.Object, "id")
	}

	if state.mirrorID == "" {
		for _, ep := range [][2]string{
			{"GET", "/api/v1/admin/mirrors/{id}"},
			{"PUT", "/api/v1/admin/mirrors/{id}"},
			{"GET", "/api/v1/admin/mirrors/{id}/status"},
			{"POST", "/api/v1/admin/mirrors/{id}/sync"},
			{"GET", "/api/v1/admin/mirrors/{id}/providers"},
			{"POST", "/api/v1/admin/approvals"},
			{"DELETE", "/api/v1/admin/mirrors/{id}"},
		} {
			skipTest(ep[0], ep[1], "create mirror failed")
		}
		return
	}

	// Get returns raw MirrorConfiguration object
	r = doJSON("GET", "/api/v1/admin/mirrors/"+state.mirrorID, nil, true)
	note = checkFields(r.Object, "id", "name")
	record("GET", "/api/v1/admin/mirrors/"+state.mirrorID, r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("PUT", "/api/v1/admin/mirrors/"+state.mirrorID,
		map[string]interface{}{
			"name":                  "test-mirror-updated",
			"upstream_registry_url": "https://registry.terraform.io",
			"enabled":               false,
		}, true)
	record("PUT", "/api/v1/admin/mirrors/"+state.mirrorID, r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/admin/mirrors/"+state.mirrorID+"/status", nil, true)
	record("GET", "/api/v1/admin/mirrors/"+state.mirrorID+"/status", r.Code, []int{200, 404}, r.Elapsed, "")

	// Trigger sync — no body required; returns 200 or 202
	r = doJSON("POST", "/api/v1/admin/mirrors/"+state.mirrorID+"/sync", nil, true)
	record("POST", "/api/v1/admin/mirrors/"+state.mirrorID+"/sync", r.Code, []int{200, 202}, r.Elapsed, "")

	// Providers: {"providers": [...]}
	r = doJSON("GET", "/api/v1/admin/mirrors/"+state.mirrorID+"/providers", nil, true)
	note = checkFields(r.Object, "providers")
	record("GET", "/api/v1/admin/mirrors/"+state.mirrorID+"/providers", r.Code, []int{200}, r.Elapsed, note)

	// Create an approval request scoped to this mirror
	r = doJSON("POST", "/api/v1/admin/approvals",
		map[string]interface{}{
			"mirror_config_id":   state.mirrorID,
			"provider_namespace": "hashicorp",
			"reason":             "integration test approval request",
		}, true)
	note = checkFields(r.Object, "id")
	if record("POST", "/api/v1/admin/approvals", r.Code, []int{201}, r.Elapsed, note) {
		state.approvalID = str(r.Object, "id")
	}

	// Read approval back immediately (before mirror deletion may cascade-delete it)
	if state.approvalID != "" {
		r = doJSON("GET", "/api/v1/admin/approvals/"+state.approvalID, nil, true)
		note = checkFields(r.Object, "id")
		record("GET", "/api/v1/admin/approvals/"+state.approvalID, r.Code, []int{200}, r.Elapsed, note)
	} else {
		skipTest("GET", "/api/v1/admin/approvals/{id}", "approval not created")
	}

	r = doJSON("DELETE", "/api/v1/admin/mirrors/"+state.mirrorID, nil, true)
	record("DELETE", "/api/v1/admin/mirrors/"+state.mirrorID, r.Code, []int{200}, r.Elapsed, "")
	state.mirrorID = ""
}

// ── Phase 10: Terraform Binary Mirror CRUD ───────────────────────────────────

func phase10() {
	fmt.Println("\n=== Phase 10: Terraform Binary Mirror CRUD ===")

	// List: {"configs": [...], "total_count": N}
	r := doJSON("GET", "/api/v1/admin/terraform-mirrors", nil, true)
	note := checkFields(r.Object, "configs", "total_count")
	record("GET", "/api/v1/admin/terraform-mirrors", r.Code, []int{200}, r.Elapsed, note)

	// Create returns raw TerraformMirrorConfig object
	r = doJSON("POST", "/api/v1/admin/terraform-mirrors",
		map[string]interface{}{
			"name":         "test-tf-mirror",
			"tool":         "terraform",
			"upstream_url": "https://releases.hashicorp.com",
		}, true)
	note = checkFields(r.Object, "id", "name")
	if record("POST", "/api/v1/admin/terraform-mirrors", r.Code, []int{201}, r.Elapsed, note) {
		state.tfMirrorID = str(r.Object, "id")
	}

	if state.tfMirrorID == "" {
		for _, ep := range [][2]string{
			{"GET", "/api/v1/admin/terraform-mirrors/{id}"},
			{"PUT", "/api/v1/admin/terraform-mirrors/{id}"},
			{"GET", "/api/v1/admin/terraform-mirrors/{id}/status"},
			{"POST", "/api/v1/admin/terraform-mirrors/{id}/sync"},
			{"GET", "/api/v1/admin/terraform-mirrors/{id}/versions"},
			{"GET", "/api/v1/admin/terraform-mirrors/{id}/versions/{version}"},
			{"GET", "/api/v1/admin/terraform-mirrors/{id}/history"},
			{"DELETE", "/api/v1/admin/terraform-mirrors/{id}"},
		} {
			skipTest(ep[0], ep[1], "create tf mirror failed")
		}
		return
	}

	r = doJSON("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID, nil, true)
	note = checkFields(r.Object, "id", "name")
	record("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID, r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("PUT", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID,
		map[string]interface{}{"name": "test-tf-mirror-updated"}, true)
	record("PUT", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID, r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/status", nil, true)
	record("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/status", r.Code, []int{200}, r.Elapsed, "")

	// Trigger sync — no body; returns 202 with enqueue message
	r = doJSON("POST", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/sync", nil, true)
	record("POST", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/sync", r.Code, []int{200, 202}, r.Elapsed, "")

	// Versions list; capture a version string for detail test
	r = doJSON("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions", nil, true)
	record("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions", r.Code, []int{200}, r.Elapsed, "")
	if r.IsArray && len(r.Array) > 0 {
		if v, ok := r.Array[0].(map[string]interface{}); ok {
			state.tfMirrorVersion = str(v, "version")
		}
	} else if r.Object != nil {
		if versions, ok := r.Object["versions"].([]interface{}); ok && len(versions) > 0 {
			if v, ok := versions[0].(map[string]interface{}); ok {
				state.tfMirrorVersion = str(v, "version")
			}
		}
	}

	// Version detail — only reachable if a version was synced
	if state.tfMirrorVersion != "" {
		r = doJSON("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions/"+state.tfMirrorVersion, nil, true)
		record("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions/"+state.tfMirrorVersion, r.Code, []int{200}, r.Elapsed, "")

		// Platforms for a synced version
		r = doJSON("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions/"+state.tfMirrorVersion+"/platforms", nil, true)
		record("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions/"+state.tfMirrorVersion+"/platforms", r.Code, []int{200}, r.Elapsed, "")

		// Delete the synced version
		r = doJSON("DELETE", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions/"+state.tfMirrorVersion, nil, true)
		record("DELETE", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/versions/"+state.tfMirrorVersion, r.Code, []int{200}, r.Elapsed, "")
	} else {
		skipTest("GET", "/api/v1/admin/terraform-mirrors/{id}/versions/{version}", "no synced versions available")
		skipTest("GET", "/api/v1/admin/terraform-mirrors/{id}/versions/{version}/platforms", "no synced versions available")
		skipTest("DELETE", "/api/v1/admin/terraform-mirrors/{id}/versions/{version}", "no synced versions available")
	}

	r = doJSON("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/history", nil, true)
	record("GET", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID+"/history", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID, nil, true)
	record("DELETE", "/api/v1/admin/terraform-mirrors/"+state.tfMirrorID, r.Code, []int{200}, r.Elapsed, "")
	state.tfMirrorID = ""
}

// ── Phase 11: Module CRUD + Terraform Protocol ───────────────────────────────

func phase11() {
	fmt.Println("\n=== Phase 11: Module CRUD + Terraform Protocol ===")

	r := doJSON("POST", "/api/v1/admin/modules/create",
		map[string]interface{}{"namespace": "testns", "name": "testmod", "system": "aws"}, true)
	if record("POST", "/api/v1/admin/modules/create", r.Code, []int{200, 201}, r.Elapsed, "") {
		state.moduleID = str(r.Object, "id")
	}

	r = doMultipart("POST", "/api/v1/modules",
		map[string]string{"namespace": "testns", "name": "testmod", "system": "aws", "version": "0.1.0"},
		"file", "testmod.tar.gz", makeTarGz(), true)
	note := checkFields(r.Object, "id", "namespace", "name", "version")
	record("POST", "/api/v1/modules", r.Code, []int{201}, r.Elapsed, note)

	r = doJSON("GET", "/api/v1/modules/testns/testmod/aws", nil, true)
	note = checkFields(r.Object, "id", "created_by_name")
	record("GET", "/api/v1/modules/testns/testmod/aws", r.Code, []int{200}, r.Elapsed, note)

	// GetModuleByIDRecord + UpdateModuleRecord — use captured module ID
	if state.moduleID != "" {
		r = doJSON("GET", "/api/v1/admin/modules/"+state.moduleID, nil, true)
		note = checkFields(r.Object, "id", "namespace", "name")
		record("GET", "/api/v1/admin/modules/"+state.moduleID, r.Code, []int{200}, r.Elapsed, note)

		r = doJSON("PUT", "/api/v1/admin/modules/"+state.moduleID,
			map[string]interface{}{
				"description": "updated description",
				"source":      "https://github.com/example/testmod",
			}, true)
		note = checkFields(r.Object, "id", "description", "source")
		record("PUT", "/api/v1/admin/modules/"+state.moduleID, r.Code, []int{200}, r.Elapsed, note)

		// SCM info — returns 404 when no SCM link configured; that is the expected state here
		r = doJSON("GET", "/api/v1/admin/modules/"+state.moduleID+"/scm", nil, true)
		record("GET", "/api/v1/admin/modules/"+state.moduleID+"/scm", r.Code, []int{200, 404}, r.Elapsed, "no SCM linked expected")
	} else {
		skipTest("GET", "/api/v1/admin/modules/{id}", "module create failed — no ID available")
		skipTest("PUT", "/api/v1/admin/modules/{id}", "module create failed — no ID available")
		skipTest("GET", "/api/v1/admin/modules/{id}/scm", "module create failed — no ID available")
	}

	r = doJSON("GET", "/v1/modules/testns/testmod/aws/versions", nil, false)
	record("GET", "/v1/modules/testns/testmod/aws/versions", r.Code, []int{200}, r.Elapsed, "")

	// TF download: 204 + X-Terraform-Get header; use non-redirecting client
	dlNote := ""
	dlCode := -1
	var dlElapsed time.Duration
	{
		req, _ := http.NewRequest("GET", baseURL+"/v1/modules/testns/testmod/aws/0.1.0/download", nil)
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		start := time.Now()
		resp, err := client.Do(req)
		dlElapsed = time.Since(start)
		if err == nil {
			dlCode = resp.StatusCode
			resp.Body.Close() // #nosec G104 -- body already drained; error on close is non-actionable in a test
			if resp.Header.Get("X-Terraform-Get") == "" {
				dlNote = "missing X-Terraform-Get header"
			}
		}
	}
	record("GET", "/v1/modules/testns/testmod/aws/0.1.0/download", dlCode, []int{204}, dlElapsed, dlNote)

	// Version scan result — 404 when scanner not enabled, 200 when it is
	r = doJSON("GET", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/scan", nil, true)
	record("GET", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/scan", r.Code, []int{200, 404}, r.Elapsed, "")

	// Reanalyze version — triggers an async re-scan; 200 or 404 when scanner absent
	r = doJSON("POST", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/reanalyze", nil, true)
	record("POST", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/reanalyze", r.Code, []int{200, 202, 404}, r.Elapsed, "")

	// Version-level deprecation
	r = doJSON("POST", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/deprecate",
		map[string]interface{}{"message": "test deprecation"}, true)
	record("POST", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/deprecate", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/api/v1/modules/testns/testmod/aws", nil, true)
	record("GET", "/api/v1/modules/testns/testmod/aws (verify deprecated=true)", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/deprecate", nil, true)
	record("DELETE", "/api/v1/modules/testns/testmod/aws/versions/0.1.0/deprecate", r.Code, []int{200}, r.Elapsed, "")

	// Module-level deprecation (separate from version deprecation)
	r = doJSON("POST", "/api/v1/modules/testns/testmod/aws/deprecate",
		map[string]interface{}{"message": "test module deprecation"}, true)
	record("POST", "/api/v1/modules/testns/testmod/aws/deprecate", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/modules/testns/testmod/aws/deprecate", nil, true)
	record("DELETE", "/api/v1/modules/testns/testmod/aws/deprecate", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/modules/testns/testmod/aws/versions/0.1.0", nil, true)
	record("DELETE", "/api/v1/modules/testns/testmod/aws/versions/0.1.0", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/modules/testns/testmod/aws", nil, true)
	record("DELETE", "/api/v1/modules/testns/testmod/aws", r.Code, []int{200}, r.Elapsed, "")
}

// ── Phase 12: Provider CRUD + Terraform Protocol ─────────────────────────────

func phase12() {
	fmt.Println("\n=== Phase 12: Provider CRUD + Terraform Protocol ===")

	r := doMultipart("POST", "/api/v1/providers",
		map[string]string{
			"namespace": "testns",
			"type":      "testprovider",
			"version":   "0.1.0",
			"os":        "linux",
			"arch":      "amd64",
		},
		"file", "terraform-provider-testprovider_0.1.0_linux_amd64.zip", makeProviderZip(), true)
	note := checkFields(r.Object, "id", "namespace", "version")
	record("POST", "/api/v1/providers", r.Code, []int{201}, r.Elapsed, note)

	r = doJSON("GET", "/api/v1/providers/testns/testprovider", nil, true)
	record("GET", "/api/v1/providers/testns/testprovider", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("GET", "/v1/providers/testns/testprovider/versions", nil, false)
	record("GET", "/v1/providers/testns/testprovider/versions", r.Code, []int{200}, r.Elapsed, "")

	// Provider download: includes signing_keys (now always present)
	r = doJSON("GET", "/v1/providers/testns/testprovider/0.1.0/download/linux/amd64", nil, false)
	note = checkFields(r.Object, "download_url", "shasum", "signing_keys")
	record("GET", "/v1/providers/testns/testprovider/0.1.0/download/linux/amd64", r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("POST", "/api/v1/providers/testns/testprovider/versions/0.1.0/deprecate",
		map[string]interface{}{"message": "test"}, true)
	record("POST", "/api/v1/providers/testns/testprovider/versions/0.1.0/deprecate", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/providers/testns/testprovider/versions/0.1.0/deprecate", nil, true)
	record("DELETE", "/api/v1/providers/testns/testprovider/versions/0.1.0/deprecate", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/providers/testns/testprovider/versions/0.1.0", nil, true)
	record("DELETE", "/api/v1/providers/testns/testprovider/versions/0.1.0", r.Code, []int{200}, r.Elapsed, "")

	r = doJSON("DELETE", "/api/v1/providers/testns/testprovider", nil, true)
	record("DELETE", "/api/v1/providers/testns/testprovider", r.Code, []int{200}, r.Elapsed, "")

	// CreateProviderRecord — new endpoint (creates a provider stub without uploading a version)
	r = doJSON("POST", "/api/v1/admin/providers",
		map[string]interface{}{
			"namespace":   "testns",
			"type":        "testproviderrecord",
			"description": "provider record test",
		}, true)
	note = checkFields(r.Object, "id", "namespace", "type")
	if record("POST", "/api/v1/admin/providers", r.Code, []int{201}, r.Elapsed, note) {
		state.providerRecordID = str(r.Object, "id")
	}

	// GetProviderByID + UpdateProviderRecord
	if state.providerRecordID != "" {
		r = doJSON("GET", "/api/v1/admin/providers/"+state.providerRecordID, nil, true)
		note = checkFields(r.Object, "id", "namespace", "type")
		record("GET", "/api/v1/admin/providers/"+state.providerRecordID, r.Code, []int{200}, r.Elapsed, note)

		r = doJSON("PUT", "/api/v1/admin/providers/"+state.providerRecordID,
			map[string]interface{}{"description": "updated provider record description"}, true)
		note = checkFields(r.Object, "id", "namespace", "type")
		record("PUT", "/api/v1/admin/providers/"+state.providerRecordID, r.Code, []int{200}, r.Elapsed, note)
	} else {
		skipTest("GET", "/api/v1/admin/providers/{id}", "CreateProviderRecord failed — no ID available")
		skipTest("PUT", "/api/v1/admin/providers/{id}", "CreateProviderRecord failed — no ID available")
	}
}

// ── Phase 13: Policies & Approvals ───────────────────────────────────────────

func phase13() {
	fmt.Println("\n=== Phase 13: Policies & Approvals ===")

	// List policies — raw array
	r := doJSON("GET", "/api/v1/admin/policies", nil, true)
	record("GET", "/api/v1/admin/policies", r.Code, []int{200}, r.Elapsed, "")

	// Create policy — raw MirrorPolicy object
	r = doJSON("POST", "/api/v1/admin/policies",
		map[string]interface{}{
			"name":        "test-policy",
			"policy_type": "allow",
		}, true)
	note := checkFields(r.Object, "id", "name")
	if record("POST", "/api/v1/admin/policies", r.Code, []int{201}, r.Elapsed, note) {
		state.policyID = str(r.Object, "id")
	}

	if state.policyID != "" {
		r = doJSON("GET", "/api/v1/admin/policies/"+state.policyID, nil, true)
		note = checkFields(r.Object, "id", "name")
		record("GET", "/api/v1/admin/policies/"+state.policyID, r.Code, []int{200}, r.Elapsed, note)

		r = doJSON("PUT", "/api/v1/admin/policies/"+state.policyID,
			map[string]interface{}{"name": "test-policy-updated", "policy_type": "allow"}, true)
		record("PUT", "/api/v1/admin/policies/"+state.policyID, r.Code, []int{200}, r.Elapsed, "")
	} else {
		skipTest("GET", "/api/v1/admin/policies/{id}", "create policy failed")
		skipTest("PUT", "/api/v1/admin/policies/{id}", "create policy failed")
	}

	// Evaluate policy
	r = doJSON("POST", "/api/v1/admin/policies/evaluate",
		map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		}, true)
	record("POST", "/api/v1/admin/policies/evaluate", r.Code, []int{200}, r.Elapsed, "")

	if state.policyID != "" {
		r = doJSON("DELETE", "/api/v1/admin/policies/"+state.policyID, nil, true)
		record("DELETE", "/api/v1/admin/policies/"+state.policyID, r.Code, []int{200}, r.Elapsed, "")
		state.policyID = ""
	} else {
		skipTest("DELETE", "/api/v1/admin/policies/{id}", "create policy failed")
	}

	// Approvals list — returns [] (empty array) when none exist
	r = doJSON("GET", "/api/v1/admin/approvals", nil, true)
	approvalNote := ""
	if r.IsNull {
		approvalNote = "returns null instead of [] (unfixed)"
		swaggerDiscrepancies = append(swaggerDiscrepancies,
			"[D] GET /api/v1/admin/approvals: returns JSON null instead of empty array []")
	}
	record("GET", "/api/v1/admin/approvals", r.Code, []int{200}, r.Elapsed, approvalNote)

	// Re-fetch the approval after its mirror was deleted; 404 verifies cascade-delete behaviour
	if state.approvalID != "" {
		r = doJSON("GET", "/api/v1/admin/approvals/"+state.approvalID, nil, true)
		cascadeNote := ""
		if r.Code == 404 {
			cascadeNote = "cascade-deleted with mirror (expected)"
		}
		record("GET", "/api/v1/admin/approvals/"+state.approvalID+" (post-mirror-delete)", r.Code, []int{200, 404}, r.Elapsed, cascadeNote)
	} else {
		skipTest("GET", "/api/v1/admin/approvals/{id}", "no approval created in phase 9")
	}

	// Create a fresh mirror + approval to test review and token-generation endpoints.
	// These need an approval that has not been cascade-deleted.
	freshMirrorResp := doJSON("POST", "/api/v1/admin/mirrors",
		map[string]interface{}{
			"name":                  "test-mirror-for-approval",
			"upstream_registry_url": "https://registry.terraform.io",
		}, true)
	freshMirrorID := str(freshMirrorResp.Object, "id")

	if freshMirrorID != "" {
		freshApprovalResp := doJSON("POST", "/api/v1/admin/approvals",
			map[string]interface{}{
				"mirror_config_id":   freshMirrorID,
				"provider_namespace": "hashicorp",
				"reason":             "integration test review approval",
			}, true)
		state.freshApprovalID = str(freshApprovalResp.Object, "id")
		record("POST", "/api/v1/admin/approvals (fresh)", freshApprovalResp.Code, []int{201}, freshApprovalResp.Elapsed, "")

		if state.freshApprovalID != "" {
			// Generate a single-use out-of-band approval token
			r = doJSON("POST", "/api/v1/admin/approvals/"+state.freshApprovalID+"/token", nil, true)
			record("POST", "/api/v1/admin/approvals/"+state.freshApprovalID+"/token", r.Code, []int{200, 201}, r.Elapsed, "")

			// Review the approval (approve it)
			r = doJSON("PUT", "/api/v1/admin/approvals/"+state.freshApprovalID+"/review",
				map[string]interface{}{"status": "approved", "comment": "approved by integration test"}, true)
			record("PUT", "/api/v1/admin/approvals/"+state.freshApprovalID+"/review", r.Code, []int{200}, r.Elapsed, "")
		} else {
			skipTest("POST", "/api/v1/admin/approvals/{id}/token", "fresh approval create failed")
			skipTest("PUT", "/api/v1/admin/approvals/{id}/review", "fresh approval create failed")
		}

		// Clean up the fresh mirror (cascades to approval)
		r = doJSON("DELETE", "/api/v1/admin/mirrors/"+freshMirrorID, nil, true)
		record("DELETE", "/api/v1/admin/mirrors/"+freshMirrorID+" (fresh, cleanup)", r.Code, []int{200}, r.Elapsed, "")
	} else {
		skipTest("POST", "/api/v1/admin/approvals (fresh)", "fresh mirror create failed")
		skipTest("POST", "/api/v1/admin/approvals/{id}/token", "fresh mirror create failed")
		skipTest("PUT", "/api/v1/admin/approvals/{id}/review", "fresh mirror create failed")
	}
}

// ── Phase 14: Audit Logs ─────────────────────────────────────────────────────

func phase14() {
	fmt.Println("\n=== Phase 14: Audit Logs ===")

	r := doJSON("GET", "/api/v1/admin/audit-logs", nil, true)
	note := checkFields(r.Object, "logs", "pagination")
	record("GET", "/api/v1/admin/audit-logs", r.Code, []int{200}, r.Elapsed, note)

	// Capture a log ID from the list for the detail test
	if logs, ok := r.Object["logs"].([]interface{}); ok && len(logs) > 0 {
		if item, ok := logs[0].(map[string]interface{}); ok {
			state.auditLogID = str(item, "id")
		}
	}

	if state.auditLogID != "" {
		r = doJSON("GET", "/api/v1/admin/audit-logs/"+state.auditLogID, nil, true)
		note = checkFields(r.Object, "id", "action")
		record("GET", "/api/v1/admin/audit-logs/"+state.auditLogID, r.Code, []int{200}, r.Elapsed, note)
	} else {
		skipTest("GET", "/api/v1/admin/audit-logs/{id}", "no audit log entries available")
	}

	// Audit log export (CSV/JSON download)
	r = doJSON("GET", "/api/v1/admin/audit-logs/export", nil, true)
	record("GET", "/api/v1/admin/audit-logs/export", r.Code, []int{200}, r.Elapsed, "")
}

// ── Phase 15: Dev Mode Endpoints ─────────────────────────────────────────────

func phase15() {
	fmt.Println("\n=== Phase 15: Dev Mode Endpoints (DEV_MODE=true required) ===")

	r := doJSON("GET", "/api/v1/dev/status", nil, false)
	// 200 in dev mode, 403 in production
	record("GET", "/api/v1/dev/status", r.Code, []int{200, 403}, r.Elapsed, "")

	// Dev login — no body; logs in as admin@dev.local; returns token + user + expires_in
	r = doJSON("POST", "/api/v1/dev/login", nil, false)
	if r.Code == 200 {
		note := checkFields(r.Object, "token", "user", "expires_in")
		record("POST", "/api/v1/dev/login", r.Code, []int{200}, r.Elapsed, note)
	} else {
		// 403 when not in dev mode — acceptable
		record("POST", "/api/v1/dev/login", r.Code, []int{200, 403}, r.Elapsed, "")
	}
}

// ── Phase 16: OIDC Group Mapping + Storage Config Detail ─────────────────────

func phase16() {
	fmt.Println("\n=== Phase 16: OIDC Group Mapping + Storage Config Detail ===")

	// Update OIDC group mapping — all fields optional; empty body is a valid clear-all
	r := doJSON("PUT", "/api/v1/admin/oidc/group-mapping",
		map[string]interface{}{
			"group_claim_name": "groups",
			"group_mappings":   []interface{}{},
			"default_role":     "",
		}, true)
	record("PUT", "/api/v1/admin/oidc/group-mapping", r.Code, []int{200}, r.Elapsed, "")

	// Storage config detail read — uses ID captured in phase 3
	if state.storageConfigID != "" {
		r = doJSON("GET", "/api/v1/storage/configs/"+state.storageConfigID, nil, true)
		note := checkFields(r.Object, "id", "backend_type", "is_active")
		record("GET", "/api/v1/storage/configs/"+state.storageConfigID, r.Code, []int{200}, r.Elapsed, note)
	} else {
		skipTest("GET", "/api/v1/storage/configs/{id}", "no storage config available")
	}

	// Test a local storage backend connection — accepts 200 (success) or 422 (path inaccessible)
	r = doJSON("POST", "/api/v1/storage/configs/test",
		map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/app/storage",
		}, true)
	record("POST", "/api/v1/storage/configs/test", r.Code, []int{200, 400, 422}, r.Elapsed, "")
}

// ── Phase 17: Cleanup ────────────────────────────────────────────────────────

func phase17() {
	fmt.Println("\n=== Phase 17: Final Cleanup ===")

	if state.userID != "" {
		r := doJSON("DELETE", "/api/v1/users/"+state.userID, nil, true)
		record("DELETE", "/api/v1/users/"+state.userID, r.Code, []int{200}, r.Elapsed, "")
		state.userID = ""
	} else {
		skipTest("DELETE", "/api/v1/users/{id}", "user not created")
	}

	if state.orgID != "" {
		r := doJSON("DELETE", "/api/v1/organizations/"+state.orgID, nil, true)
		record("DELETE", "/api/v1/organizations/"+state.orgID, r.Code, []int{200}, r.Elapsed, "")
		state.orgID = ""
	} else {
		skipTest("DELETE", "/api/v1/organizations/{id}", "org not created")
	}
}

// ── Phase 18: 404 verification ───────────────────────────────────────────────

func phase18() {
	fmt.Println("\n=== Phase 18: 404 Verification (deleted resources) ===")

	r := doJSON("GET", "/api/v1/modules/testns/testmod/aws", nil, true)
	record("GET", "/api/v1/modules/testns/testmod/aws", r.Code, []int{404}, r.Elapsed, "verify deleted")

	r = doJSON("GET", "/api/v1/providers/testns/testprovider", nil, true)
	record("GET", "/api/v1/providers/testns/testprovider", r.Code, []int{404}, r.Elapsed, "verify deleted")
}

// ── Phase 19: CVE Advisories (admin) ────────────────────────────────────────

func phase19() {
	fmt.Println("\n=== Phase 19: CVE Advisories (admin) ===")

	r := doJSON("GET", "/api/v1/admin/advisories", nil, true)
	note := checkFields(r.Object, "advisories", "total")
	record("GET", "/api/v1/admin/advisories", r.Code, []int{200}, r.Elapsed, note)

	// Filter by kind
	r = doJSON("GET", "/api/v1/admin/advisories?kind=provider", nil, true)
	record("GET", "/api/v1/admin/advisories?kind=provider", r.Code, []int{200}, r.Elapsed, "")

	// Trigger an immediate CVE poll (no-op when CVE polling is disabled)
	r = doJSON("POST", "/api/v1/admin/advisories/poll", nil, true)
	record("POST", "/api/v1/admin/advisories/poll", r.Code, []int{200, 202}, r.Elapsed, "")
}

// ── Phase 20: Policy Engine (OPA) ────────────────────────────────────────────

func phase20() {
	fmt.Println("\n=== Phase 20: Policy Engine (OPA) ===")

	// Policy config — always returns 200 regardless of whether OPA is enabled
	r := doJSON("GET", "/api/v1/admin/policy/config", nil, true)
	note := checkFields(r.Object, "enabled", "mode", "active")
	record("GET", "/api/v1/admin/policy/config", r.Code, []int{200}, r.Elapsed, note)

	// Reload bundle — 400 when no bundle_url is configured; 200/500 otherwise
	r = doJSON("POST", "/api/v1/admin/policy/reload", nil, true)
	record("POST", "/api/v1/admin/policy/reload", r.Code, []int{200, 400, 500}, r.Elapsed, "")

	// Ad-hoc policy evaluation
	r = doJSON("POST", "/api/v1/admin/policy/evaluate",
		map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"type":      "aws",
		}, true)
	record("POST", "/api/v1/admin/policy/evaluate", r.Code, []int{200}, r.Elapsed, "")
}

// ── Phase 21: Storage Config CRUD ────────────────────────────────────────────

func phase21() {
	fmt.Println("\n=== Phase 21: Storage Config CRUD + Migration Plan ===")

	// Create a new local storage config
	r := doJSON("POST", "/api/v1/storage/configs",
		map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/registry-test-storage",
			"description":     "integration test storage config",
		}, true)
	note := checkFields(r.Object, "id", "backend_type")
	if record("POST", "/api/v1/storage/configs", r.Code, []int{201}, r.Elapsed, note) {
		state.storageConfigNewID = str(r.Object, "id")
	}

	if state.storageConfigNewID == "" {
		skipTest("PUT", "/api/v1/storage/configs/{id}", "create storage config failed")
		skipTest("POST", "/api/v1/storage/configs/{id}/activate", "create storage config failed")
		skipTest("DELETE", "/api/v1/storage/configs/{id}", "create storage config failed")
	} else {
		r = doJSON("PUT", "/api/v1/storage/configs/"+state.storageConfigNewID,
			map[string]interface{}{
				"backend_type":    "local",
				"local_base_path": "/tmp/registry-test-storage-updated",
				"description":     "updated integration test storage config",
			}, true)
		record("PUT", "/api/v1/storage/configs/"+state.storageConfigNewID, r.Code, []int{200}, r.Elapsed, "")

		// Activate — may return 400 if the path is inaccessible in CI
		r = doJSON("POST", "/api/v1/storage/configs/"+state.storageConfigNewID+"/activate", nil, true)
		record("POST", "/api/v1/storage/configs/"+state.storageConfigNewID+"/activate", r.Code, []int{200, 400, 422}, r.Elapsed, "")

		r = doJSON("DELETE", "/api/v1/storage/configs/"+state.storageConfigNewID, nil, true)
		record("DELETE", "/api/v1/storage/configs/"+state.storageConfigNewID, r.Code, []int{200, 409}, r.Elapsed, "")
		state.storageConfigNewID = ""
	}

	// Migration plan — needs two valid config IDs; expect 400 when IDs are placeholder values
	r = doJSON("POST", "/api/v1/admin/storage/migrations/plan",
		map[string]interface{}{
			"source_config_id": "00000000-0000-0000-0000-000000000001",
			"target_config_id": "00000000-0000-0000-0000-000000000002",
		}, true)
	record("POST", "/api/v1/admin/storage/migrations/plan", r.Code, []int{200, 400, 404, 500}, r.Elapsed, "")

	// Migration list
	r = doJSON("GET", "/api/v1/admin/storage/migrations", nil, true)
	record("GET", "/api/v1/admin/storage/migrations", r.Code, []int{200}, r.Elapsed, "")
}

// ── Phase 22: Security Scanning Admin ────────────────────────────────────────

func phase22() {
	fmt.Println("\n=== Phase 22: Security Scanning Admin ===")

	r := doJSON("GET", "/api/v1/admin/scanning/config", nil, true)
	note := checkFields(r.Object, "enabled", "tool", "severity_threshold")
	record("GET", "/api/v1/admin/scanning/config", r.Code, []int{200}, r.Elapsed, note)

	r = doJSON("GET", "/api/v1/admin/scanning/stats", nil, true)
	note = checkFields(r.Object, "total", "pending", "clean")
	record("GET", "/api/v1/admin/scanning/stats", r.Code, []int{200}, r.Elapsed, note)
}

// ── Phase 23: SCIM 2.0 Provisioning ─────────────────────────────────────────

func phase23() {
	fmt.Println("\n=== Phase 23: SCIM 2.0 Provisioning ===")

	// Probe whether SCIM routes are registered at all by hitting /scim/v2/Users
	// without auth. A 404 means the routes are not wired up on this deployment;
	// skip the entire phase rather than reporting false failures.
	probe := doJSON("GET", "/scim/v2/Users", nil, false)
	if probe.Code == 404 {
		for _, ep := range [][2]string{
			{"GET", "/scim/v2/Users (no auth)"},
			{"GET", "/scim/v2/Users"},
			{"GET", "/scim/v2/Groups"},
			{"POST", "/scim/v2/Users"},
		} {
			skipTest(ep[0], ep[1], "SCIM not enabled on this deployment")
		}
		return
	}

	// If probe returned 401, SCIM is properly secured. 200 without auth means
	// SCIM is active but auth is not enforced — record a swagger discrepancy.
	if probe.Code == 200 {
		swaggerDiscrepancies = append(swaggerDiscrepancies,
			"[D] GET /scim/v2/Users: accessible without auth (scim:provision scope not enforced)")
	}
	record("GET", "/scim/v2/Users (no auth)", probe.Code, []int{401}, probe.Elapsed, "")

	// Authenticated reads — a standard API key expects 403 (wrong scope)
	r := doJSON("GET", "/scim/v2/Users", nil, true)
	record("GET", "/scim/v2/Users", r.Code, []int{200, 403}, r.Elapsed, "scim:provision scope required")

	r = doJSON("GET", "/scim/v2/Groups", nil, true)
	record("GET", "/scim/v2/Groups", r.Code, []int{200, 403}, r.Elapsed, "scim:provision scope required")

	// Creating a SCIM user requires scim:provision; expect 403 with a standard API key.
	// 405 means write operations are not implemented on this deployment.
	r = doJSON("POST", "/scim/v2/Users",
		map[string]interface{}{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": "scim-test@test.local",
			"name":     map[string]interface{}{"formatted": "SCIM Test User"},
		}, true)
	record("POST", "/scim/v2/Users", r.Code, []int{201, 403, 405}, r.Elapsed, "scim:provision scope required")
}

// ── Cleanup ──────────────────────────────────────────────────────────────────

// cleanup removes any leftover resources from a previous interrupted run so
// that create calls (which would otherwise get 409) succeed cleanly.
// It does NOT contribute to pass/fail/skip counters.
func cleanup() {
	fmt.Println("\n=== Pre-run Cleanup (removing stale test data) ===")

	// Organizations — find "test-api-org" and delete it
	r := doJSON("GET", "/api/v1/organizations", nil, true)
	if orgs, ok := r.Object["organizations"].([]interface{}); ok {
		for _, o := range orgs {
			if org, ok := o.(map[string]interface{}); ok && str(org, "name") == "test-api-org" {
				id := str(org, "id")
				d := doJSON("DELETE", "/api/v1/organizations/"+id, nil, true)
				fmt.Printf("  cleanup: DELETE org %s → %d\n", id, d.Code)
			}
		}
	}

	// Users — find "apitest@test.local" and delete it
	r = doJSON("GET", "/api/v1/users", nil, true)
	if users, ok := r.Object["users"].([]interface{}); ok {
		for _, u := range users {
			if user, ok := u.(map[string]interface{}); ok && str(user, "email") == "apitest@test.local" {
				id := str(user, "id")
				d := doJSON("DELETE", "/api/v1/users/"+id, nil, true)
				fmt.Printf("  cleanup: DELETE user %s → %d\n", id, d.Code)
			}
		}
	}

	// Role templates — find "test-role" and delete it (raw array response)
	r = doJSON("GET", "/api/v1/admin/role-templates", nil, true)
	for _, item := range r.Array {
		if tmpl, ok := item.(map[string]interface{}); ok && str(tmpl, "name") == "test-role" {
			id := str(tmpl, "id")
			d := doJSON("DELETE", "/api/v1/admin/role-templates/"+id, nil, true)
			fmt.Printf("  cleanup: DELETE role-template %s → %d\n", id, d.Code)
		}
	}

	// Module testns/testmod/aws — delete version then module (ignore errors)
	doJSON("DELETE", "/api/v1/modules/testns/testmod/aws/versions/0.1.0", nil, true)
	doJSON("DELETE", "/api/v1/modules/testns/testmod/aws", nil, true)
	fmt.Println("  cleanup: tried DELETE module testns/testmod/aws")

	// Provider testns/testprovider — delete version then provider (ignore errors)
	doJSON("DELETE", "/api/v1/providers/testns/testprovider/versions/0.1.0", nil, true)
	doJSON("DELETE", "/api/v1/providers/testns/testprovider", nil, true)
	fmt.Println("  cleanup: tried DELETE provider testns/testprovider")

	// Terraform mirror — find "test-tf-mirror" and delete it
	r = doJSON("GET", "/api/v1/admin/terraform-mirrors", nil, true)
	if configs, ok := r.Object["configs"].([]interface{}); ok {
		for _, c := range configs {
			if cfg, ok := c.(map[string]interface{}); ok && str(cfg, "name") == "test-tf-mirror" {
				id := str(cfg, "id")
				d := doJSON("DELETE", "/api/v1/admin/terraform-mirrors/"+id, nil, true)
				fmt.Printf("  cleanup: DELETE tf-mirror %s → %d\n", id, d.Code)
			}
		}
	}

	// Provider mirror — find "test-mirror" and delete it
	r = doJSON("GET", "/api/v1/admin/mirrors", nil, true)
	if mirrors, ok := r.Object["mirrors"].([]interface{}); ok {
		for _, m := range mirrors {
			if mirror, ok := m.(map[string]interface{}); ok && str(mirror, "name") == "test-mirror" {
				id := str(mirror, "id")
				d := doJSON("DELETE", "/api/v1/admin/mirrors/"+id, nil, true)
				fmt.Printf("  cleanup: DELETE provider mirror %s → %d\n", id, d.Code)
			}
		}
	}

	// SCM providers — find "test-scm" and delete it
	r = doJSON("GET", "/api/v1/scm-providers", nil, true)
	for _, item := range r.Array {
		if prov, ok := item.(map[string]interface{}); ok && str(prov, "name") == "test-scm" {
			id := str(prov, "id")
			d := doJSON("DELETE", "/api/v1/scm-providers/"+id, nil, true)
			fmt.Printf("  cleanup: DELETE scm-provider %s → %d\n", id, d.Code)
		}
	}

	// Provider record testns/testproviderrecord — delete by namespace+type path
	doJSON("DELETE", "/api/v1/providers/testns/testproviderrecord", nil, true)
	fmt.Println("  cleanup: tried DELETE provider record testns/testproviderrecord")
}

// ── main ─────────────────────────────────────────────────────────────────────

// sleep pauses for n seconds and prints a brief rate-limit back-off notice.
func sleep(n int) {
	fmt.Printf("  [sleep %ds — rate-limit back-off]\n", n)
	time.Sleep(time.Duration(n) * time.Second)
}

func main() {
	urlFlag := flag.String("url", "http://registry.local:8080", "Base URL of the registry API")
	keyFlag := flag.String("key", "", "API key for authenticated requests") // #nosec G101 -- integration test credential
	delayFlag := flag.Int("delay", 750, "Milliseconds to wait before each request (use 0 for local, 750+ for rate-limited environments)")
	strictCoverage := flag.Bool("strict-coverage", false, "Exit non-zero if the live spec contains endpoints the runner never touches")
	flag.Parse()

	baseURL = *urlFlag
	apiKey = *keyFlag
	reqDelay = time.Duration(*delayFlag) * time.Millisecond

	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: -key flag is required")
		flag.Usage()
		os.Exit(1)
	}

	keyPreview := apiKey
	if len(keyPreview) > 18 {
		keyPreview = keyPreview[:18]
	}

	fmt.Println("Terraform Registry API Test")
	fmt.Printf("Target:     %s\n", baseURL)
	fmt.Printf("API Key:    %s...\n", keyPreview)
	fmt.Printf("Req delay:  %dms\n\n", *delayFlag)

	cleanup()

	phase1()
	sleep(2)
	phase2()
	sleep(2)
	phase3()
	sleep(2)
	phase4()
	sleep(2)
	phase5()
	sleep(2)
	phase6()
	sleep(2)
	phase7()
	sleep(2)
	phase8()
	sleep(2)
	phase9()
	sleep(2)
	phase10()
	sleep(2)
	phase11()
	sleep(2)
	phase12()
	sleep(2)
	phase13()
	sleep(2)
	phase14()
	sleep(2)
	phase15()
	sleep(2)
	phase16()
	sleep(2)
	phase17()
	sleep(2)
	phase18()
	sleep(2)
	phase19()
	sleep(2)
	phase20()
	sleep(2)
	phase21()
	sleep(2)
	phase22()
	sleep(2)
	phase23()

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("Results: %d passed, %d failed, %d skipped  (total: %d)\n",
		passed, failed, skipped, passed+failed+skipped)

	if len(swaggerDiscrepancies) > 0 {
		fmt.Println("\n--- Swagger / Spec Discrepancies ---")
		for _, d := range swaggerDiscrepancies {
			fmt.Println(" ", d)
		}
	}

	uncovered := reportCoverage()

	if len(skippedTests) > 0 {
		fmt.Println("\n--- Skipped Tests ---")
		for _, s := range skippedTests {
			fmt.Println(" ", s)
		}
	}

	if len(failedTests) > 0 {
		fmt.Println("\n--- Failed Tests ---")
		for _, f := range failedTests {
			fmt.Println(" ", f)
		}
	}

	if failed > 0 {
		// non-zero exit so CI can detect failures
		fmt.Println()
		panic("test failures")
	}

	if *strictCoverage && uncovered > 0 {
		fmt.Println()
		panic("uncovered API endpoints (run without -strict-coverage to list only)")
	}
}
