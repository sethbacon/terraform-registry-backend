// audit_export.go implements the NDJSON and OCSF export endpoints for audit logs.
package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// @Summary      Export audit logs
// @Description  Streams audit log entries as newline-delimited JSON (NDJSON) or OCSF 1.1 API
//
//	Activity events for SIEM ingestion. Accepts optional start_date and end_date query
//	parameters in RFC3339 format. Defaults to the last 30 days when no dates are provided.
//	Use format=ocsf to receive OCSF-formatted events (class_uid 6003); default is format=ndjson.
//
// @Tags         Audit
// @Security     Bearer
// @Produce      application/x-ndjson
// @Param        start_date  query  string  false  "Start date in RFC3339 format (default: 30 days ago)"
// @Param        end_date    query  string  false  "End date in RFC3339 format (default: now)"
// @Param        format      query  string  false  "Output format: ndjson (default) or ocsf"  Enums(ndjson, ocsf)
// @Success      200  {string}  string  "NDJSON stream of audit log entries"
// @Failure      400  {object}  map[string]interface{}  "Invalid date or format parameters"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      403  {object}  map[string]interface{}  "Forbidden — audit:read scope required"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/audit-logs/export [get]
// coverage:skip:requires-database
func ExportAuditLogs(auditRepo *repositories.AuditRepository, appVersion string) gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now().UTC()
		startDate := now.AddDate(0, 0, -30)
		endDate := now

		if v := c.Query("start_date"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "start_date must be an RFC3339 timestamp (e.g. 2006-01-02T15:04:05Z)"})
				return
			}
			startDate = t
		}

		if v := c.Query("end_date"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "end_date must be an RFC3339 timestamp (e.g. 2006-01-02T15:04:05Z)"})
				return
			}
			endDate = t
		}

		format := c.DefaultQuery("format", "ndjson")
		if format != "ndjson" && format != "ocsf" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "format must be ndjson or ocsf"})
			return
		}

		rows, err := auditRepo.StreamAuditLogs(c.Request.Context(), startDate, endDate)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query audit logs for export"})
			return
		}
		defer rows.Close()

		ext := "ndjson"
		if format == "ocsf" {
			ext = "ocsf.ndjson"
		}
		filename := "audit-logs-" + now.Format("2006-01-02") + "." + ext
		c.Header("Content-Type", "application/x-ndjson")
		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Status(http.StatusOK)

		enc := json.NewEncoder(c.Writer)
		for rows.Next() {
			var entry auditExportRow
			var metadataJSON []byte

			if err := rows.Scan(
				&entry.ID,
				&entry.UserID,
				&entry.OrganizationID,
				&entry.Action,
				&entry.ResourceType,
				&entry.ResourceID,
				&metadataJSON,
				&entry.IPAddress,
				&entry.CreatedAt,
				&entry.UserEmail,
				&entry.UserName,
			); err != nil {
				// Cannot write a JSON error at this point because headers are already sent.
				return
			}

			if metadataJSON != nil {
				_ = json.Unmarshal(metadataJSON, &entry.Metadata)
			}

			if format == "ocsf" {
				ev := audit.ToOCSF(entry.toLogEntry(), appVersion)
				// Supplement user name/email from the export row (not in LogEntry).
				if ev.Actor.User != nil {
					if entry.UserName != nil {
						ev.Actor.User.Name = *entry.UserName
					}
					if entry.UserEmail != nil {
						if ev.Unmapped == nil {
							ev.Unmapped = make(map[string]interface{})
						}
						ev.Unmapped["user_email"] = *entry.UserEmail
					}
				}
				_ = enc.Encode(ev)
			} else {
				_ = enc.Encode(entry) // writes JSON + "\n"
			}
			c.Writer.Flush()
		}
	}
}

// auditExportRow is a flat struct used for NDJSON serialization of a single audit log entry.
type auditExportRow struct {
	ID             string                 `json:"id"`
	UserID         *string                `json:"user_id,omitempty"`
	UserEmail      *string                `json:"user_email,omitempty"`
	UserName       *string                `json:"user_name,omitempty"`
	OrganizationID *string                `json:"organization_id,omitempty"`
	Action         string                 `json:"action"`
	ResourceType   *string                `json:"resource_type,omitempty"`
	ResourceID     *string                `json:"resource_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	IPAddress      *string                `json:"ip_address,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

// toLogEntry converts the export row into an audit.LogEntry for OCSF conversion.
func (r *auditExportRow) toLogEntry() *audit.LogEntry {
	entry := &audit.LogEntry{
		Timestamp: r.CreatedAt,
		Action:    r.Action,
		Metadata:  r.Metadata,
	}
	if r.UserID != nil {
		entry.UserID = *r.UserID
	}
	if r.OrganizationID != nil {
		entry.OrganizationID = *r.OrganizationID
	}
	if r.ResourceType != nil {
		entry.ResourceType = *r.ResourceType
	}
	if r.ResourceID != nil {
		entry.ResourceID = *r.ResourceID
	}
	if r.IPAddress != nil {
		entry.IPAddress = *r.IPAddress
	}
	return entry
}
