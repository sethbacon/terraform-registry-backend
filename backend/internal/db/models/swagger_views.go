package models

import (
	"time"

	"github.com/google/uuid"
)

// RoleTemplateView mirrors the aliased RoleTemplate for swagger documentation.
// swag cannot resolve type aliases into the external identity module, so handler
// annotations that return a RoleTemplate reference this local view instead; the
// JSON shape is identical to the real type.
type RoleTemplateView struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description *string   `json:"description,omitempty"`
	Scopes      []string  `json:"scopes"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
