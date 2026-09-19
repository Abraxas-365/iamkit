package user

import (
	"encoding/json"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
)

type User struct {
	ID            string          `json:"id"`
	Email         string          `json:"email"`
	Name          string          `json:"name"`
	Active        bool            `json:"active"`
	EmailVerified bool            `json:"email_verified"`
	OTPEnabled    bool            `json:"otp_enabled"`
	Metadata      json.RawMessage `json:"metadata"`
}
type Create struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	OTPEnabled bool   `json:"otp_enabled"`
}

// Validate checks the structural invariants Create owns. Email format and
// normalization is handled separately via identity.Email.
func (c Create) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("user name is required")
	}
	if c.Password != "" && (len(c.Password) < config.PasswordMinLength || len(c.Password) > config.PasswordMaxLength) {
		return errx.Validation("password must be 12-72 bytes")
	}
	return nil
}

type Update struct {
	Name       *string         `json:"name"`
	Active     *bool           `json:"active"`
	OTPEnabled *bool           `json:"otp_enabled"`
	Metadata   json.RawMessage `json:"metadata"`
}

// Validate checks only the fields explicitly supplied.
func (u Update) Validate() error {
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		return errx.Validation("user name is required")
	}
	return nil
}

// Mutation identifies the authenticated operator for transactional audit recording.
type Mutation struct{ Environment, Actor, Action, Target string }
