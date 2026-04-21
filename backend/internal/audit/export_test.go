package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func TestToOCSF_BasicFields(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	entry := &LogEntry{
		Timestamp:      ts,
		Action:         "create_module",
		UserID:         "user-123",
		OrganizationID: "org-456",
		IPAddress:      "10.0.0.1",
		AuthMethod:     "oidc",
		StatusCode:     201,
		ResourceType:   "module",
		ResourceID:     "mod-789",
	}

	ev := ToOCSF(entry, "1.5.0")

	if ev.ClassUID != 6003 {
		t.Errorf("ClassUID = %d, want 6003", ev.ClassUID)
	}
	if ev.CategoryUID != 6 {
		t.Errorf("CategoryUID = %d, want 6", ev.CategoryUID)
	}
	if ev.ActivityID != OCSFActivityCreate {
		t.Errorf("ActivityID = %d, want %d (Create)", ev.ActivityID, OCSFActivityCreate)
	}
	if ev.ActivityName != "Create" {
		t.Errorf("ActivityName = %q, want %q", ev.ActivityName, "Create")
	}
	if ev.Time != ts.UnixMilli() {
		t.Errorf("Time = %d, want %d", ev.Time, ts.UnixMilli())
	}
	if ev.Status != "Success" {
		t.Errorf("Status = %q, want %q", ev.Status, "Success")
	}
	if ev.StatusID != 1 {
		t.Errorf("StatusID = %d, want 1", ev.StatusID)
	}
	if ev.StatusCode != "201" {
		t.Errorf("StatusCode = %q, want %q", ev.StatusCode, "201")
	}
	if ev.Actor.User == nil || ev.Actor.User.UID != "user-123" {
		t.Errorf("Actor.User.UID = %v, want user-123", ev.Actor.User)
	}
	if ev.Actor.User.OrgUID != "org-456" {
		t.Errorf("Actor.User.OrgUID = %q, want org-456", ev.Actor.User.OrgUID)
	}
	if ev.Actor.AuthMethod != "oidc" {
		t.Errorf("Actor.AuthMethod = %q, want oidc", ev.Actor.AuthMethod)
	}
	if ev.SrcEndpoint.IP != "10.0.0.1" {
		t.Errorf("SrcEndpoint.IP = %q, want 10.0.0.1", ev.SrcEndpoint.IP)
	}
	if ev.Metadata.Version != "1.1.0" {
		t.Errorf("Metadata.Version = %q, want 1.1.0", ev.Metadata.Version)
	}
	if ev.Metadata.Product.Version != "1.5.0" {
		t.Errorf("Product.Version = %q, want 1.5.0", ev.Metadata.Product.Version)
	}
	if len(ev.Resources) != 1 || ev.Resources[0].UID != "mod-789" {
		t.Errorf("Resources = %v, want [{UID:mod-789}]", ev.Resources)
	}
}

func TestToOCSF_FailureStatus(t *testing.T) {
	entry := &LogEntry{
		Timestamp:  time.Now(),
		Action:     "delete_module",
		StatusCode: 500,
	}
	ev := ToOCSF(entry, "1.0.0")

	if ev.Status != "Failure" {
		t.Errorf("Status = %q, want Failure for 500", ev.Status)
	}
	if ev.StatusID != 2 {
		t.Errorf("StatusID = %d, want 2", ev.StatusID)
	}
	if ev.Severity != OCSFSeverityHigh {
		t.Errorf("Severity = %d, want %d (High) for 500", ev.Severity, OCSFSeverityHigh)
	}
}

func TestToOCSF_NoResource(t *testing.T) {
	entry := &LogEntry{
		Timestamp: time.Now(),
		Action:    "login",
	}
	ev := ToOCSF(entry, "1.0.0")
	if ev.Resources != nil {
		t.Errorf("Resources = %v, want nil when no resource set", ev.Resources)
	}
}

func TestToOCSF_NoStatusCode(t *testing.T) {
	entry := &LogEntry{
		Timestamp: time.Now(),
		Action:    "login",
	}
	ev := ToOCSF(entry, "1.0.0")
	if ev.StatusCode != "" {
		t.Errorf("StatusCode = %q, want empty when status is 0", ev.StatusCode)
	}
}

func TestToOCSF_Metadata(t *testing.T) {
	entry := &LogEntry{
		Timestamp: time.Now(),
		Action:    "create_module",
		Metadata:  map[string]interface{}{"key": "value"},
	}
	ev := ToOCSF(entry, "1.0.0")
	if ev.Unmapped == nil || ev.Unmapped["key"] != "value" {
		t.Errorf("Unmapped = %v, want {key:value}", ev.Unmapped)
	}
}

func TestToOCSFJSON(t *testing.T) {
	entry := &LogEntry{
		Timestamp:  time.Now(),
		Action:     "get_module",
		StatusCode: 200,
	}
	data, err := ToOCSFJSON(entry, "2.0.0")
	if err != nil {
		t.Fatalf("ToOCSFJSON() error = %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["class_uid"] != float64(6003) {
		t.Errorf("class_uid = %v, want 6003", m["class_uid"])
	}
}

func TestMapActionToOCSF(t *testing.T) {
	tests := []struct {
		action   string
		wantType OCSFActivityType
		wantName string
	}{
		{"create_module", OCSFActivityCreate, "Create"},
		{"upload_provider", OCSFActivityCreate, "Create"},
		{"publish_version", OCSFActivityCreate, "Create"},
		{"list_modules", OCSFActivityRead, "Read"},
		{"get_provider", OCSFActivityRead, "Read"},
		{"download_module", OCSFActivityRead, "Read"},
		{"export_data", OCSFActivityRead, "Read"},
		{"update_module", OCSFActivityUpdate, "Update"},
		{"modify_config", OCSFActivityUpdate, "Update"},
		{"rotate_key", OCSFActivityUpdate, "Update"},
		{"resync_mirror", OCSFActivityUpdate, "Update"},
		{"delete_module", OCSFActivityDelete, "Delete"},
		{"remove_member", OCSFActivityDelete, "Delete"},
		{"revoke_key", OCSFActivityDelete, "Delete"},
		{"erase_user", OCSFActivityDelete, "Delete"},
		{"login", OCSFActivityLogin, "Login"},
		{"authenticate_user", OCSFActivityLogin, "Login"},
		{"logout", OCSFActivityLogout, "Logout"},
		{"some_unknown_action", OCSFActivityUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			gotType, gotName := mapActionToOCSF(tt.action)
			if gotType != tt.wantType {
				t.Errorf("mapActionToOCSF(%q) type = %d, want %d", tt.action, gotType, tt.wantType)
			}
			if gotName != tt.wantName {
				t.Errorf("mapActionToOCSF(%q) name = %q, want %q", tt.action, gotName, tt.wantName)
			}
		})
	}
}

func TestMapStatusToSeverity(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		action     string
		wantSev    OCSFSeverity
		wantStr    string
	}{
		{"500 error", 500, "get_module", OCSFSeverityHigh, "High"},
		{"503 error", 503, "list_modules", OCSFSeverityHigh, "High"},
		{"403 forbidden", 403, "create_module", OCSFSeverityMedium, "Medium"},
		{"401 unauthorized", 401, "get_module", OCSFSeverityMedium, "Medium"},
		{"delete action", 200, "delete_module", OCSFSeverityMedium, "Medium"},
		{"erase action", 200, "erase_user", OCSFSeverityMedium, "Medium"},
		{"failed login", 400, "login", OCSFSeverityMedium, "Medium"},
		{"failed auth", 400, "authenticate", OCSFSeverityMedium, "Medium"},
		{"normal success", 200, "get_module", OCSFSeverityInfo, "Informational"},
		{"success create", 201, "create_module", OCSFSeverityInfo, "Informational"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSev, gotStr := mapStatusToSeverity(tt.statusCode, tt.action)
			if gotSev != tt.wantSev {
				t.Errorf("severity = %d, want %d", gotSev, tt.wantSev)
			}
			if gotStr != tt.wantStr {
				t.Errorf("severity string = %q, want %q", gotStr, tt.wantStr)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		s      string
		subs   []string
		expect bool
	}{
		{"create_module", []string{"create"}, true},
		{"CREATE_MODULE", []string{"create"}, true},
		{"nothing_here", []string{"create", "delete"}, false},
		{"delete_user", []string{"create", "delete"}, true},
		{"short", []string{"toolongsubstring"}, false},
		{"", []string{"a"}, false},
	}
	for _, tt := range tests {
		got := containsAny(tt.s, tt.subs...)
		if got != tt.expect {
			t.Errorf("containsAny(%q, %v) = %v, want %v", tt.s, tt.subs, got, tt.expect)
		}
	}
}

func TestToOCSF_TypeUID(t *testing.T) {
	entry := &LogEntry{
		Timestamp: time.Now(),
		Action:    "delete_module",
	}
	ev := ToOCSF(entry, "1.0.0")
	expectedTypeUID := 6003*100 + int(OCSFActivityDelete)
	if ev.TypeUID != expectedTypeUID {
		t.Errorf("TypeUID = %d, want %d", ev.TypeUID, expectedTypeUID)
	}
}
