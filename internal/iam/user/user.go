package user

import "encoding/json"

type User struct {
	ID            string          `json:"id"`
	Email         string          `json:"email"`
	Name          string          `json:"name"`
	Active        bool            `json:"active"`
	EmailVerified bool            `json:"email_verified"`
	Metadata      json.RawMessage `json:"metadata"`
}
type Create struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	OTPEnabled bool   `json:"otp_enabled"`
}
type Update struct {
	Name       *string         `json:"name"`
	Active     *bool           `json:"active"`
	OTPEnabled *bool           `json:"otp_enabled"`
	Metadata   json.RawMessage `json:"metadata"`
}

// Mutation identifies the authenticated operator for transactional audit recording.
type Mutation struct{ Environment, Actor, Action, Target string }
