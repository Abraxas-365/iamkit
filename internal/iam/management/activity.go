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
	// Display labels for the referenced entities; empty when deleted.
	UserName         string `json:"user_name" db:"user_name"`
	UserEmail        string `json:"user_email" db:"user_email"`
	OrganizationName string `json:"organization_name" db:"organization_name"`
	ApplicationName  string `json:"application_name" db:"application_name"`
	ResourceName     string `json:"resource_name" db:"resource_name"`
}

// SessionFilter narrows the session inventory; zero fields match everything.
type SessionFilter struct {
	User identity.UserID
}
type AuditEvent struct {
	ID      string    `json:"id" db:"id"`
	Actor   string    `json:"actor_id" db:"actor_id"`
	Action  string    `json:"action" db:"action"`
	Target  string    `json:"target_id" db:"target_id"`
	Created time.Time `json:"created_at" db:"created_at"`
	// ActorLabel is the operator or end user email behind Actor; empty for
	// unknown actors (e.g. API keys of removed operators).
	ActorLabel string `json:"actor_label" db:"actor_label"`
	// ActorKind is operator, user, service_account or system.
	ActorKind string `json:"actor_kind" db:"actor_kind"`
	// Organization is the organization the target lies in, when any.
	Organization *identity.OrganizationID `json:"organization_id" db:"organization_id"`
	// TargetLabel is the current name of the entity Target refers to; empty
	// when it cannot be resolved (deleted, or not a named entity).
	TargetLabel string `json:"target_label" db:"target_label"`
}
