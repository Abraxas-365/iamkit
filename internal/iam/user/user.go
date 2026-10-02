package user

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type User struct {
	ID identity.UserID `json:"id" db:"id"`
	// Kind is human or machine (no email: "" for machine users).
	Kind  Kind   `json:"kind" db:"kind"`
	Email string `json:"email" db:"email"`
	Name  string `json:"name" db:"name"`
	// Username is an optional second sign-in identifier, unique in the
	// environment ("" when none).
	Username string `json:"username" db:"username"`
	// HomeOrganization owns the user record: its administrators may edit
	// it (null when none).
	HomeOrganization *identity.OrganizationID `json:"home_organization_id" db:"home_organization_id"`
	// AvatarURL is an https URL to the user's picture ("" when none).
	AvatarURL     string `json:"avatar_url" db:"avatar_url"`
	Active        bool   `json:"active" db:"active"`
	EmailVerified bool   `json:"email_verified" db:"email_verified"`
	OTPEnabled    bool   `json:"otp_enabled" db:"otp_enabled"`
	// Phone is the user's number (E.164, "" when none); PhoneVerified once
	// an SMS code sent to it was entered (SMS second factor).
	Phone         string          `json:"phone" db:"phone"`
	PhoneVerified bool            `json:"phone_verified" db:"phone_verified"`
	Metadata      json.RawMessage `json:"metadata" db:"metadata"`
	// Profile holds the attributes the environment's user schema describes.
	Profile json.RawMessage `json:"profile" db:"profile"`
	// FailedLogins counts wrong passwords in a row; LockedUntil is set while
	// the password policy locks the account (POST .../unlock clears both).
	FailedLogins int        `json:"failed_logins" db:"failed_logins"`
	LockedUntil  *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	// State is derived for display (see State); Active stays the sign-in
	// gate. LastSignedInAt is the last session created by a sign-in.
	State          State      `json:"state" db:"state"`
	LastSignedInAt *time.Time `json:"last_signed_in_at" db:"last_signed_in_at"`
	// TermsAcceptedAt is when the user accepted the terms at sign-up (nil
	// when sign-up did not require it, or the user did not sign up).
	TermsAcceptedAt *time.Time `json:"terms_accepted_at,omitempty" db:"terms_accepted_at"`
}

// State summarizes whether and why a user can sign in. It is computed
// from the account, never stored.
type State string

const (
	// StateSuspended: an operator deactivated the user (active=false);
	// nothing signs in until reactivated.
	StateSuspended State = "suspended"
	// StateLocked: wrong passwords locked password sign-in for now.
	StateLocked State = "locked"
	// StateInitial: the user never signed in (created, invited or
	// provisioned and not used yet).
	StateInitial State = "initial"
	// StateInactive: signed in before but has no active membership in an
	// active organization (deprovisioned by a directory, removed or the
	// organization deactivated), so no sign-in can succeed.
	StateInactive State = "inactive"
	// StateActive: can sign in.
	StateActive State = "active"
)

// States lists every state in precedence order.
var States = []State{StateSuspended, StateLocked, StateInitial, StateInactive, StateActive}

// Filter narrows a user list.
type Filter struct {
	// State keeps only users in that state ("" = all).
	State State
	// HomeOrganization keeps only users homed in that organization.
	HomeOrganization identity.OrganizationID
	// Kind keeps only human or machine users ("" = both).
	Kind Kind
}

func (f Filter) Validate() error {
	if !f.Kind.Valid() {
		return errx.Validation("kind must be human or machine")
	}
	if f.State == "" {
		return nil
	}
	for _, s := range States {
		if f.State == s {
			return nil
		}
	}
	return errx.Validation("state must be one of suspended, locked, initial, inactive, active")
}

// Audit actions of user state changes.
const (
	ActionUnlocked    = "user.unlocked"
	ActionDeactivated = "user.deactivated"
	ActionReactivated = "user.reactivated"
)

type Create struct {
	// Kind is human (default) or machine: a machine user has only a name
	// and signs in with personal access tokens.
	Kind       Kind   `json:"kind"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	OTPEnabled bool   `json:"otp_enabled"`
	AvatarURL  string `json:"avatar_url"`
	// Username is optional (see identity.Username).
	Username string `json:"username"`
	// HomeOrganization is the organization that owns the user record
	// (optional): its administrators may edit the user. Creating a user
	// with one also makes the user a member of it.
	HomeOrganization identity.OrganizationID `json:"home_organization_id"`
}

func (c Create) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("user name is required")
	}
	if !c.Kind.Valid() {
		return errx.Validation("kind must be human or machine")
	}
	if c.Kind == KindMachine {
		switch {
		case c.Email != "":
			return errx.Validation("machine users have no email")
		case c.Password != "":
			return errx.Validation("machine users have no password")
		case c.Username != "":
			return errx.Validation("machine users have no username")
		case c.OTPEnabled:
			return errx.Validation("machine users have no second factor")
		}
	}
	// The environment's password policy sets the minimum (service); 72
	// bytes is bcrypt's limit.
	if len(c.Password) > config.PasswordMaxLength {
		return errx.Validation("password must be at most 72 characters long")
	}
	if _, err := identity.Username(c.Username); err != nil {
		return err
	}
	_, err := identity.AvatarURL(c.AvatarURL)
	return err
}

type Update struct {
	Name       *string         `json:"name"`
	Active     *bool           `json:"active"`
	OTPEnabled *bool           `json:"otp_enabled"`
	Metadata   json.RawMessage `json:"metadata"`
	// HomeOrganization moves the user record to another organization (the
	// user must be a member); "" clears it.
	HomeOrganization *identity.OrganizationID `json:"home_organization_id"`
	// Phone sets the user's number ("" clears it); a changed number is no
	// longer verified. It never changes an enrolled SMS factor.
	Phone *string `json:"phone"`
	// PhoneVerified marks the number (after any Phone change) verified or
	// not, audited ActionPhoneVerifiedSet; true needs a number.
	PhoneVerified *bool `json:"phone_verified"`
	// AvatarURL sets the picture ("" removes it).
	AvatarURL *string `json:"avatar_url"`
	// Username sets the username ("" removes it).
	Username *string `json:"username"`
}

// Normalize brings the phone number to E.164 when it is valid; metadata
// null means no change.
func (u Update) Normalize() Update {
	if strings.TrimSpace(string(u.Metadata)) == "null" {
		u.Metadata = nil
	}
	if u.Phone != nil && strings.TrimSpace(*u.Phone) != "" {
		if phone, err := identity.Phone(*u.Phone); err == nil {
			u.Phone = &phone
		}
	} else if u.Phone != nil {
		empty := ""
		u.Phone = &empty
	}
	if u.AvatarURL != nil {
		avatar := strings.TrimSpace(*u.AvatarURL)
		u.AvatarURL = &avatar
	}
	if u.Username != nil {
		if username, err := identity.Username(*u.Username); err == nil {
			u.Username = &username
		}
	}
	return u
}

func (u Update) Validate() error {
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		return errx.Validation("user name is required")
	}
	if u.Phone != nil && *u.Phone != "" {
		if _, err := identity.Phone(*u.Phone); err != nil {
			return err
		}
	}
	if u.AvatarURL != nil {
		if _, err := identity.AvatarURL(*u.AvatarURL); err != nil {
			return err
		}
	}
	if u.Username != nil {
		if _, err := identity.Username(*u.Username); err != nil {
			return err
		}
	}
	if len(u.Metadata) > 0 {
		return identity.ValidateMetadata(u.Metadata)
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
