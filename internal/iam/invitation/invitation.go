// Package invitation invites email addresses into organizations with initial
// roles and groups. An operator creates the invitation; the invitee accepts it
// with the one-time token delivered by the mail webhook.
package invitation

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// TokenPrefix marks invitation tokens.
const TokenPrefix = "ik_inv_"

// MaxReferences bounds the roles and groups one invitation may grant.
const MaxReferences = 50

// Invitation statuses. Status is derived, never stored.
const (
	StatusPending  = "pending"
	StatusAccepted = "accepted"
	StatusRevoked  = "revoked"
	StatusExpired  = "expired"
)

type Boundary struct {
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

type Invitation struct {
	ID           identity.InvitationID   `json:"id" db:"id"`
	Organization identity.OrganizationID `json:"organization_id" db:"organization_id"`
	Email        string                  `json:"email" db:"email"`
	Roles        []identity.RoleID       `json:"role_ids" db:"-"`
	Groups       []identity.GroupID      `json:"group_ids" db:"-"`
	Inviter      string                  `json:"inviter" db:"inviter"`
	ExpiresAt    time.Time               `json:"expires_at" db:"expires_at"`
	AcceptedAt   *time.Time              `json:"accepted_at" db:"accepted_at"`
	AcceptedUser identity.UserID         `json:"accepted_user_id,omitempty" db:"accepted_user_id"`
	RevokedAt    *time.Time              `json:"revoked_at" db:"revoked_at"`
	Created      time.Time               `json:"created_at" db:"created_at"`
	Status       string                  `json:"status" db:"-"`
}

// State derives the status at now.
func (i Invitation) State(now time.Time) string {
	switch {
	case i.AcceptedAt != nil:
		return StatusAccepted
	case i.RevokedAt != nil:
		return StatusRevoked
	case !now.Before(i.ExpiresAt):
		return StatusExpired
	}
	return StatusPending
}

// Open reports whether the invitation can still be resent or revoked: not
// accepted and not revoked (an expired invitation can be resent).
func (i Invitation) Open() bool { return i.AcceptedAt == nil && i.RevokedAt == nil }

// Input is the create payload.
type Input struct {
	Email  string             `json:"email"`
	Roles  []identity.RoleID  `json:"role_ids"`
	Groups []identity.GroupID `json:"group_ids"`
}

// Validate normalizes the email and removes duplicate references.
func (i *Input) Validate() error {
	email, err := identity.Email(i.Email)
	if err != nil {
		return errx.Validation("email must be a valid address")
	}
	i.Email = email
	if len(i.Roles) > MaxReferences || len(i.Groups) > MaxReferences {
		return errx.Validation("at most 50 role_ids and 50 group_ids")
	}
	i.Roles = unique(i.Roles)
	i.Groups = unique(i.Groups)
	return nil
}

func unique[T interface {
	comparable
	IsZero() bool
}](ids []T) []T {
	seen := make(map[T]bool, len(ids))
	out := make([]T, 0, len(ids))
	for _, id := range ids {
		if !id.IsZero() && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Filter narrows a listing to one status.
type Filter struct{ Status string }

func (f Filter) Validate() error {
	switch f.Status {
	case "", StatusPending, StatusAccepted, StatusRevoked, StatusExpired:
		return nil
	}
	return errx.Validation("status must be pending, accepted, revoked or expired")
}

// Issued is returned once when an invitation is created or resent: the raw
// token and link are never shown again. Delivery reports the webhook result
// ("sent", "failed", or "skipped" when no delivery is configured).
type Issued struct {
	Invitation
	Token    string `json:"token"`
	Link     string `json:"link,omitempty"`
	Delivery string `json:"delivery"`
}

// Mail is the invitation handed to the mail webhook.
type Mail struct {
	Email        string
	Token        string
	Link         string
	Organization string
	Inviter      string
	ExpiresAt    time.Time
}

// Acceptance is the public accept payload.
type Acceptance struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (a *Acceptance) Validate() error {
	if err := ValidToken(a.Token); err != nil {
		return err
	}
	a.Name = strings.TrimSpace(a.Name)
	if len(a.Name) > 200 {
		return errx.Validation("name must be at most 200 characters")
	}
	if a.Password != "" && (len(a.Password) < config.PasswordMinLength || len(a.Password) > config.PasswordMaxLength) {
		return errx.Validation("password must be 12-72 characters long")
	}
	return nil
}

// ValidToken rejects values that cannot be an invitation token, before any
// lookup.
func ValidToken(token string) error {
	if !strings.HasPrefix(token, TokenPrefix) || len(token) > 128 {
		return ErrInvalid
	}
	return nil
}

// ErrInvalid is the uniform answer for unknown, used, revoked or expired
// tokens on accept.
var ErrInvalid = errx.Unauthorized("invalid or expired invitation")

// Accepted is the accept result. The invitee signs in afterwards: with a
// password, or through SSO when SSORequired.
type Accepted struct {
	User         identity.UserID         `json:"user_id"`
	Organization identity.OrganizationID `json:"organization_id"`
	Email        string                  `json:"email"`
	Created      bool                    `json:"created"`
	SSORequired  bool                    `json:"sso_required"`
}

// Preview is what an accept page may show to the token holder.
type Preview struct {
	// Environment brands the hosted accept page; not part of the API body.
	Environment      identity.EnvironmentID  `json:"-"`
	Organization     identity.OrganizationID `json:"organization_id"`
	OrganizationName string                  `json:"organization_name"`
	Email            string                  `json:"email"`
	ExpiresAt        time.Time               `json:"expires_at"`
	Status           string                  `json:"status"`
	PasswordRequired bool                    `json:"password_required"`
	SSORequired      bool                    `json:"sso_required"`
}

// Mask hides the local part of an email except its first character.
func Mask(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 1 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}

// Target is the pending invitation found by token together with the state
// accept and preview depend on.
type Target struct {
	Invitation  Invitation
	Environment identity.EnvironmentID
	OrgName     string
	OrgActive   bool
	SSORequired bool
	Account     Account
}

// Account is the existing user with the invitation's email, if any.
type Account struct {
	ID          identity.UserID
	Active      bool
	HasPassword bool
}

func (a Account) Exists() bool { return !a.ID.IsZero() }

// Organization is the invited organization's state.
type Organization struct {
	Name   string `db:"name"`
	Active bool   `db:"active"`
}

// References counts the invitation's roles in the environment and its
// groups that operators manage in the organization.
type References struct {
	Roles  int
	Groups int
}

// Joining is what accept applies inside its transaction.
type Joining struct {
	Invitation   Invitation
	Environment  identity.EnvironmentID
	User         identity.UserID
	NewUser      bool
	Name         string
	PasswordHash string
}
