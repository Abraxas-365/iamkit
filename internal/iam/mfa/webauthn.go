package mfa

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ProofWebAuthn is a security key or passkey assertion.
const ProofWebAuthn = "webauthn"

// ActionCloneDetected is audited when a WebAuthn credential's signature
// counter goes backwards: a copy of the key may exist. The assertion is
// refused.
const ActionCloneDetected = "mfa.clone_detected"

// Ceremony purposes.
const (
	CeremonyRegister = "register"
	CeremonyLogin    = "login"
	CeremonyPasskey  = "passkey"
)

// Credential is the public part of a WebAuthn credential, stored with its
// factor. It never leaves IAMKit except as a credential id in options.
type Credential struct {
	ID                []byte   `json:"id"`
	PublicKey         []byte   `json:"public_key"`
	AttestationType   string   `json:"attestation_type,omitempty"`
	AttestationFormat string   `json:"attestation_format,omitempty"`
	Transports        []string `json:"transports,omitempty"`
	AAGUID            []byte   `json:"aaguid,omitempty"`
	SignCount         uint32   `json:"sign_count"`
	UserPresent       bool     `json:"user_present"`
	UserVerified      bool     `json:"user_verified"`
	BackupEligible    bool     `json:"backup_eligible"`
	BackupState       bool     `json:"backup_state"`
}

// Holder is a user as a WebAuthn relying party sees them: an opaque handle
// (the user id's bytes, never an email), names for the authenticator's
// account picker and the credentials they already have.
type Holder struct {
	Handle      []byte
	Name        string
	DisplayName string
	// RelyingParty names the site in the browser prompt (the environment's
	// hosted-login name).
	RelyingParty string
	Credentials  []Credential
}

// HolderFor builds the holder of a user from their account and active
// WebAuthn factors (only passkeys when passkeys is set).
func HolderFor(user identity.UserID, account Account, factors []Factor, passkeys bool) Holder {
	h := Holder{Handle: []byte(user.String()), Name: account.Email, DisplayName: account.Email, RelyingParty: account.Issuer}
	for _, f := range factors {
		if c, ok := f.WebAuthn(); ok && f.Active() && (f.Passkey || !passkeys) {
			h.Credentials = append(h.Credentials, c)
		}
	}
	return h
}

// HandleUser reads the user id a passkey returned as its user handle.
func HandleUser(handle []byte) (identity.UserID, error) {
	return identity.ParseUserID(string(handle))
}

// Credential finds the factor of an asserted credential.
func CredentialFactor(factors []Factor, credential []byte) (Factor, bool) {
	for _, f := range factors {
		if c, ok := f.WebAuthn(); ok && string(c.ID) == string(credential) {
			return f, true
		}
	}
	return Factor{}, false
}

// Challenge is a started ceremony: the options the browser passes to
// navigator.credentials (the publicKey member, JSON) and the state the
// relying party keeps until the answer arrives.
type Challenge struct {
	Options json.RawMessage
	State   []byte
}

// Assertion is a verified WebAuthn assertion: which credential answered,
// its new counter and flags, and Clone when the counter went backwards.
// Handle is the user handle a passkey returned.
type Assertion struct {
	Credential Credential
	Handle     []byte
	Clone      bool
}

// Relying is the WebAuthn relying party (adapter mfawebauthn). Handles
// are the bytes of user ids (HolderFor); credentials are verified against
// the deployment's relying party id and origins.

// Ceremony is a started registration or assertion waiting for the
// browser's answer, stored under the hash of its ik_wa_ id. User is zero
// for a passkey sign-in (the credential names the user).
type Ceremony struct {
	Environment identity.EnvironmentID
	User        identity.UserID
	Purpose     string
	State       []byte
	// Name and Passkey are what a registration asked for.
	Name    string
	Passkey bool
	Expires time.Time
}

// Registration is a finished WebAuthn registration: the new factor and,
// when it is the user's first, their recovery codes.
type Registration struct {
	Factor        Factor   `json:"factor"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// StartRegistration asks for a new security key or passkey.
type StartRegistration struct {
	Name string `json:"name"`
	// Passkey asks for a discoverable credential that verifies the user,
	// so it can also sign in without a password.
	Passkey bool `json:"passkey"`
}

// Validate bounds the name users give their keys.
func (s StartRegistration) Validate() error {
	if len(strings.TrimSpace(s.Name)) > config.FactorNameMaxLength {
		return errx.Validation("name is too long")
	}
	return nil
}

// Normalized trims the name and names an unnamed key.
func (s StartRegistration) Normalized() StartRegistration {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		s.Name = "Security key"
		if s.Passkey {
			s.Name = "Passkey"
		}
	}
	return s
}

// ValidateFactorName checks a new name for a key.
func ValidateFactorName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", errx.Validation("name is required")
	case len(name) > config.FactorNameMaxLength:
		return "", errx.Validation("name is too long")
	}
	return name, nil
}

// ErrWebAuthnUnavailable answers WebAuthn requests of a deployment without
// a usable relying party (JWT_ISSUER host is an IP address, …).
func ErrWebAuthnUnavailable() error {
	e := errx.Business("security keys are not available on this server")
	e.Code = "FACTOR_NOT_ALLOWED"
	return e
}
