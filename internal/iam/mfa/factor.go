// Package mfa is the second authentication factor of end users: one TOTP
// authenticator per user plus single-use recovery codes.
package mfa

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Factor kinds.
const KindTOTP = "totp"

// Clock is injected so TOTP and expiry are testable.
type Clock func() time.Time

// Proofs a verified second factor can be.
const (
	ProofTOTP     = "totp"
	ProofRecovery = "recovery"
)

// AMR returns the authentication method references a proof adds to a
// session (RFC 8176): an authenticator code is a one-time password; either
// proof makes the login multi-factor.
func AMR(proof string) []string {
	if proof == ProofTOTP {
		return []string{"otp", "mfa"}
	}
	return []string{"mfa"}
}

// Factor is a stored factor. Secret is the sealed TOTP secret and never
// leaves the service.
type Factor struct {
	ID        identity.FactorID `json:"id" db:"id"`
	Kind      string            `json:"kind" db:"kind"`
	Confirmed *time.Time        `json:"confirmed_at" db:"confirmed_at"`
	LastUsed  *time.Time        `json:"last_used_at" db:"last_used_at"`
	Created   time.Time         `json:"created_at" db:"created_at"`
	Secret    string            `json:"-" db:"secret_sealed"`
	LastStep  int64             `json:"-" db:"last_step"`
	// Failures counts wrong codes since the last correct one; the factor
	// refuses every code until LockedUntil.
	Failures    int        `json:"-" db:"failed_attempts"`
	LockedUntil *time.Time `json:"locked_until,omitempty" db:"locked_until"`
}

// Active reports whether the factor was confirmed and counts for login.
func (f Factor) Active() bool { return f.Confirmed != nil }

// Locked reports whether wrong codes locked the factor at now.
func (f Factor) Locked(now time.Time) bool { return f.LockedUntil != nil && f.LockedUntil.After(now) }

// Enrollable reports whether an unconfirmed factor may still be confirmed:
// an abandoned enrollment expires after config.MFAEnrollTTL, so a secret
// planted (or seen) long ago can never become the user's second factor.
func (f Factor) Enrollable(now time.Time) bool {
	return !f.Active() && f.Created.After(now.Add(-config.MFAEnrollTTL))
}

// Fresh checks that a token's auth_time (Unix seconds, 0 when unknown) is
// recent enough to change the user's second factors.
func Fresh(authTime int64, now time.Time) error {
	if authTime != 0 && now.Sub(time.Unix(authTime, 0)) <= config.MFAFreshAuth {
		return nil
	}
	e := errx.Forbidden("sign in again to change your second factors")
	e.Code = "REAUTHENTICATION_REQUIRED"
	return e
}

// Lockout returns how long the factor locks after failures wrong codes in
// a row, or 0: every lockThreshold failures lock it for base, doubled per
// further round, up to max.
func Lockout(failures, threshold int, base, max time.Duration) time.Duration {
	if threshold <= 0 || failures < threshold || failures%threshold != 0 {
		return 0
	}
	d := base
	for round := failures/threshold - 1; round > 0 && d < max; round-- {
		d *= 2
	}
	return min(d, max)
}

// Summary is what a user or operator may see of a user's factors: never
// secrets or codes.
type Summary struct {
	Factors       []Factor `json:"factors"`
	RecoveryCodes int      `json:"recovery_codes_remaining"`
}

// Enrolled reports whether the user has an active factor.
func (s Summary) Enrolled() bool {
	for _, f := range s.Factors {
		if f.Active() {
			return true
		}
	}
	return false
}

// Enrollment is a TOTP factor waiting for its first code. Secret (base32)
// and URI (otpauth://) are shown once so the user can add the account to an
// authenticator app.
type Enrollment struct {
	Factor identity.FactorID `json:"factor_id"`
	Secret string            `json:"secret"`
	URI    string            `json:"otpauth_uri"`
}

// Account names the user in an authenticator app.
type Account struct {
	Email  string `db:"email"`
	Issuer string `db:"issuer"`
}

// Policy is the data a login's second-factor requirement depends on.
type Policy struct {
	Enrolled          bool `db:"enrolled"`
	Required          bool `db:"mfa_required"`
	RequiredFederated bool `db:"mfa_for_federated"`
}

// Requirement decides: federated logins trust the identity provider unless
// the organization says otherwise; a user with a factor always uses it;
// an organization requiring MFA makes users without one enroll.
func (p Policy) Requirement(federated bool) authentication.Requirement {
	if federated && !p.RequiredFederated {
		return authentication.Requirement{}
	}
	if p.Enrolled {
		return authentication.Requirement{Needed: true, Factors: []string{ProofTOTP, ProofRecovery}}
	}
	if p.Required {
		return authentication.Requirement{Needed: true, Enroll: true, Factors: []string{ProofTOTP}}
	}
	return authentication.Requirement{}
}

// Pending is a headless login waiting for its second factor.
type Pending struct {
	Boundary authentication.Context
	User     identity.UserID
	AMR      []string
	Enroll   bool
	Attempts int
	Expires  time.Time
}

// Verification is a verified second factor: the proof used and, when the
// code confirmed a new factor, the user's first recovery codes.
type Verification struct {
	Proof         string
	RecoveryCodes []string
}

// Mutation records who changed factors, for audit_events.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Audit actions of security events.
const (
	ActionEnrolled    = "mfa.enrolled"
	ActionRemoved     = "mfa.removed"
	ActionRegenerated = "mfa.recovery_regenerated"
	ActionRecovery    = "mfa.recovery_used"
	ActionReset       = "mfa.reset"
	ActionLocked      = "mfa.locked"
)

// NormalizeCode strips the spaces and dashes users type into codes and
// lowercases recovery codes.
func NormalizeCode(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ' ' || r == '-' || r == '\t':
			return -1
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		}
		return r
	}, code)
}

// IsTOTPCode reports whether a normalized code is an authenticator code
// (six digits); anything else is treated as a recovery code, which is
// twelve characters even when they all happen to be digits.
func IsTOTPCode(code string) bool {
	if len(code) != config.TOTPDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
