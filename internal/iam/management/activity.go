package management

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Session struct {
	ID           identity.SessionID      `json:"id" db:"id"`
	User         identity.UserID         `json:"user_id" db:"user_id"`
	Organization identity.OrganizationID `json:"organization_id" db:"organization_id"`
	Application  identity.ApplicationID  `json:"application_id" db:"application_id"`
	Resource     identity.ResourceID     `json:"resource_id" db:"resource_id"`
	Expires      time.Time               `json:"expires_at" db:"expires_at"`
	Revoked      *time.Time              `json:"revoked_at" db:"revoked_at"`
}
type AuditEvent struct {
	ID      string    `json:"id" db:"id"`
	Actor   string    `json:"actor_id" db:"actor_id"`
	Action  string    `json:"action" db:"action"`
	Target  string    `json:"target_id" db:"target_id"`
	Created time.Time `json:"created_at" db:"created_at"`
}
