// Package audit — export.go provides audit log export in multiple formats
// including NDJSON (already in admin/audit_export.go) and OCSF (Open
// Cybersecurity Schema Framework) for SIEM ingestion.
// coverage:skip:pure-data-mapping
package audit

import (
	"encoding/json"
	"fmt"
)

// OCSFActivityType maps audit actions to OCSF activity type IDs.
type OCSFActivityType int

const (
	OCSFActivityUnknown OCSFActivityType = 0
	OCSFActivityCreate  OCSFActivityType = 1
	OCSFActivityRead    OCSFActivityType = 2
	OCSFActivityUpdate  OCSFActivityType = 3
	OCSFActivityDelete  OCSFActivityType = 4
	OCSFActivityLogin   OCSFActivityType = 5
	OCSFActivityLogout  OCSFActivityType = 6
)

// OCSFSeverity maps audit event significance.
type OCSFSeverity int

const (
	OCSFSeverityInfo     OCSFSeverity = 1
	OCSFSeverityLow      OCSFSeverity = 2
	OCSFSeverityMedium   OCSFSeverity = 3
	OCSFSeverityHigh     OCSFSeverity = 4
	OCSFSeverityCritical OCSFSeverity = 5
)

// OCSFEvent represents an audit event in OCSF v1.1 API Activity format
// (class_uid 6003). This maps the registry's LogEntry to the standard schema
// so events can be ingested by Splunk, Elastic, CrowdStrike, or any
// OCSF-compatible SIEM.
type OCSFEvent struct {
	// Required OCSF fields
	ClassUID     int              `json:"class_uid"`    // 6003 = API Activity
	CategoryUID  int              `json:"category_uid"` // 6 = Application Activity
	TypeUID      int              `json:"type_uid"`     // class_uid * 100 + activity_id
	ActivityID   OCSFActivityType `json:"activity_id"`
	ActivityName string           `json:"activity_name"`
	Time         int64            `json:"time"` // epoch millis
	Severity     OCSFSeverity     `json:"severity_id"`
	SeverityStr  string           `json:"severity"`
	Message      string           `json:"message"`
	Status       string           `json:"status"` // "Success" or "Failure"
	StatusCode   string           `json:"status_code,omitempty"`
	StatusID     int              `json:"status_id"` // 1=Success, 2=Failure

	// Actor
	Actor OCSFActor `json:"actor"`

	// API
	API OCSFAPI `json:"api"`

	// Resource
	Resources []OCSFResource `json:"resources,omitempty"`

	// Source endpoint
	SrcEndpoint OCSFEndpoint `json:"src_endpoint,omitempty"`

	// Metadata
	Metadata OCSFMetadata `json:"metadata"`

	// Unmapped fields go here
	Unmapped map[string]interface{} `json:"unmapped,omitempty"`
}

// OCSFActor identifies the entity that performed the action.
type OCSFActor struct {
	User       *OCSFUser `json:"user,omitempty"`
	AuthMethod string    `json:"auth_protocol,omitempty"`
}

// OCSFUser is an OCSF user identity.
type OCSFUser struct {
	UID    string `json:"uid,omitempty"`
	Name   string `json:"name,omitempty"`
	OrgUID string `json:"org_uid,omitempty"`
}

// OCSFAPI describes the API call.
type OCSFAPI struct {
	Operation string       `json:"operation"`
	Request   *OCSFRequest `json:"request,omitempty"`
}

// OCSFRequest holds HTTP request info.
type OCSFRequest struct {
	UID string `json:"uid,omitempty"` // request ID
}

// OCSFResource is a resource affected by the event.
type OCSFResource struct {
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

// OCSFEndpoint is a network endpoint (source IP).
type OCSFEndpoint struct {
	IP string `json:"ip,omitempty"`
}

// OCSFMetadata provides event provenance.
type OCSFMetadata struct {
	Version string      `json:"version"`
	Product OCSFProduct `json:"product"`
}

// OCSFProduct describes the product generating the event.
type OCSFProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version,omitempty"`
}

// ToOCSF converts a registry audit LogEntry to an OCSF API Activity event.
func ToOCSF(entry *LogEntry, registryVersion string) *OCSFEvent {
	activityID, activityName := mapActionToOCSF(entry.Action)
	severity, severityStr := mapStatusToSeverity(entry.StatusCode, entry.Action)

	statusStr := "Success"
	statusID := 1
	if entry.StatusCode >= 400 {
		statusStr = "Failure"
		statusID = 2
	}

	ev := &OCSFEvent{
		ClassUID:     6003,
		CategoryUID:  6,
		TypeUID:      6003*100 + int(activityID),
		ActivityID:   activityID,
		ActivityName: activityName,
		Time:         entry.Timestamp.UnixMilli(),
		Severity:     severity,
		SeverityStr:  severityStr,
		Message:      entry.Action,
		Status:       statusStr,
		StatusID:     statusID,
		Actor: OCSFActor{
			User: &OCSFUser{
				UID:    entry.UserID,
				OrgUID: entry.OrganizationID,
			},
			AuthMethod: entry.AuthMethod,
		},
		API: OCSFAPI{
			Operation: entry.Action,
		},
		SrcEndpoint: OCSFEndpoint{
			IP: entry.IPAddress,
		},
		Metadata: OCSFMetadata{
			Version: "1.1.0",
			Product: OCSFProduct{
				Name:       "Terraform Registry",
				VendorName: "terraform-registry",
				Version:    registryVersion,
			},
		},
	}

	if entry.StatusCode > 0 {
		ev.StatusCode = fmt.Sprintf("%d", entry.StatusCode)
	}

	if entry.ResourceType != "" || entry.ResourceID != "" {
		ev.Resources = []OCSFResource{{
			UID:  entry.ResourceID,
			Type: entry.ResourceType,
		}}
	}

	if len(entry.Metadata) > 0 {
		ev.Unmapped = entry.Metadata
	}

	return ev
}

// ToOCSFJSON converts a LogEntry to OCSF JSON bytes.
func ToOCSFJSON(entry *LogEntry, registryVersion string) ([]byte, error) {
	return json.Marshal(ToOCSF(entry, registryVersion))
}

// mapActionToOCSF maps registry audit actions to OCSF activity types.
func mapActionToOCSF(action string) (OCSFActivityType, string) {
	switch {
	case containsAny(action, "create", "upload", "publish", "register"):
		return OCSFActivityCreate, "Create"
	case containsAny(action, "read", "list", "get", "download", "view", "export"):
		return OCSFActivityRead, "Read"
	case containsAny(action, "update", "modify", "edit", "rotate", "resync"):
		return OCSFActivityUpdate, "Update"
	case containsAny(action, "delete", "remove", "revoke", "erase"):
		return OCSFActivityDelete, "Delete"
	case containsAny(action, "login", "authenticate", "auth"):
		return OCSFActivityLogin, "Login"
	case containsAny(action, "logout"):
		return OCSFActivityLogout, "Logout"
	default:
		return OCSFActivityUnknown, "Unknown"
	}
}

// mapStatusToSeverity assigns an OCSF severity based on HTTP status and action.
func mapStatusToSeverity(statusCode int, action string) (OCSFSeverity, string) {
	if statusCode >= 500 {
		return OCSFSeverityHigh, "High"
	}
	if statusCode == 403 || statusCode == 401 {
		return OCSFSeverityMedium, "Medium"
	}
	if containsAny(action, "delete", "erase", "revoke") {
		return OCSFSeverityMedium, "Medium"
	}
	if containsAny(action, "login", "authenticate") && statusCode >= 400 {
		return OCSFSeverityMedium, "Medium"
	}
	return OCSFSeverityInfo, "Informational"
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				match := true
				for j := 0; j < len(sub); j++ {
					c := s[i+j]
					// case-insensitive comparison
					if c != sub[j] && c != sub[j]-32 && c != sub[j]+32 {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}
	return false
}
