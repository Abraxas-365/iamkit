// Package mfa is the second authentication factor of end users: their
// factors (a TOTP authenticator, …) plus single-use recovery codes.
package mfa

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Factor kinds. TOTP, email and SMS factors are one per user; security keys
// (Phase 5) may be several.
const (
	KindTOTP     = "totp"
	KindEmail    = "email"
	KindSMS      = "sms"
	KindWebAuthn = "webauthn"
)

// Kinds lists every factor kind, in the order they are offered.
var Kinds = identity.FactorKinds

// Clock is injected so TOTP and expiry are testable.
type Clock func() time.Time

// Proofs a verified second factor can be.
const (
	ProofTOTP     = "totp"
	ProofEmail    = "email"
	ProofSMS      = "sms"
	ProofRecovery = "recovery"
)

// AMR returns the authentication method references a proof adds to a
// session (RFC 8176): an authenticator or emailed code is a one-time
// password, a texted code "sms"; every proof makes the login multi-factor.
func AMR(proof string) []string {
	switch proof {
	case ProofTOTP, ProofEmail:
		return []string{"otp", "mfa"}
	case ProofSMS:
		return []string{"sms", "mfa"}
	case ProofWebAuthn:
		return []string{"hwk", "mfa"}
	}
	return []string{"mfa"}
}

// Factor is a stored factor. Secret is the sealed TOTP secret and never
// leaves the service, nor does the code of an email or SMS factor.
type Factor struct {
	ID        identity.FactorID `json:"id" db:"id"`
	Kind      string            `json:"kind" db:"kind"`
	Name      string            `json:"name,omitempty" db:"name"`
	Confirmed *time.Time        `json:"confirmed_at" db:"confirmed_at"`
	LastUsed  *time.Time        `json:"last_used_at" db:"last_used_at"`
	Created   time.Time         `json:"created_at" db:"created_at"`
	// Phone is where an SMS factor sends codes (E.164).
	Phone    string  `json:"phone,omitempty" db:"phone"`
	Secret   *string `json:"-" db:"secret_sealed"`
	LastStep int64   `json:"-" db:"last_step"`
	// Code is the live code of an email or SMS factor (hashed).
	Code         []byte     `json:"-" db:"code_hash"`
	CodeExpires  *time.Time `json:"-" db:"code_expires_at"`
	CodeSent     *time.Time `json:"-" db:"code_sent_at"`
	CodeAttempts int        `json:"-" db:"code_attempts"`
	CodesSent    int        `json:"-" db:"codes_sent"`
	CodesWindow  *time.Time `json:"-" db:"codes_window"`
	// Data is the factor's stored JSON (a WebAuthn Credential).
	Data []byte `json:"-" db:"data"`
	// Passkey marks a WebAuthn credential that can also sign in on its own.
	Passkey bool `json:"passkey,omitempty" db:"passkey"`
	// LockedUntil repeats the user's Lock on each active factor (kept for
	// clients written when a user had one factor).
	LockedUntil *time.Time `json:"locked_until,omitempty" db:"-"`
}

// WebAuthn returns the credential of a WebAuthn factor.
func (f Factor) WebAuthn() (Credential, bool) {
	var c Credential
	if f.Kind != KindWebAuthn || json.Unmarshal(f.Data, &c) != nil || len(c.ID) == 0 {
		return Credential{}, false
	}
	return c, true
}

// Coded reports whether the factor proves possession with a code IAMKit
// sends (email, SMS).
func (f Factor) Coded() bool { return f.Kind == KindEmail || f.Kind == KindSMS }

// CodeLive reports whether the factor holds an unexpired code.
func (f Factor) CodeLive(now time.Time) bool {
	return len(f.Code) > 0 && f.CodeExpires != nil && f.CodeExpires.After(now)
}

// Send is when a new code may go out: the cooldown since the last one and
// the hourly cap (config.FactorCodeCooldown, config.FactorCodesPerHour).
// It returns the counters to store with the new code, or a 429 error.
func (f Factor) Send(now time.Time) (sent int, window time.Time, err error) {
	if f.CodeSent != nil && now.Sub(*f.CodeSent) < config.FactorCodeCooldown {
		e := errx.TooManyRequests("a code was just sent; wait a few seconds before asking for another")
		e.Code = "CODE_COOLDOWN"
		return 0, now, e
	}
	sent, window = f.CodesSent, now
	if f.CodesWindow != nil && now.Sub(*f.CodesWindow) < time.Hour {
		window = *f.CodesWindow
	} else {
		sent = 0
	}
	if sent >= config.FactorCodesPerHour {
		e := errx.TooManyRequests("too many codes sent; try again later")
		e.Code = "CODE_LIMIT"
		return 0, now, e
	}
	return sent + 1, window, nil
}

// Code is a sent email or SMS code about to be stored on its factor.
type Code struct {
	Hash    []byte
	Expires time.Time
	Sent    time.Time
	Count   int
	Window  time.Time
}

// Active reports whether the factor was confirmed and counts for login.
func (f Factor) Active() bool { return f.Confirmed != nil }

// Sealed returns the sealed TOTP secret ("" for other kinds).
func (f Factor) Sealed() string {
	if f.Secret == nil {
		return ""
	}
	return *f.Secret
}

// Lock counts a user's wrong second-factor codes since the last correct
// one, whichever factor they targeted; every factor refuses codes until
// LockedUntil.
type Lock struct {
	Failures    int        `db:"failed_attempts"`
	LockedUntil *time.Time `db:"locked_until"`
}

// Locked reports whether wrong codes locked the user's factors at now.
func (l Lock) Locked(now time.Time) bool { return l.LockedUntil != nil && l.LockedUntil.After(now) }

// Find returns the user's factor of a kind (TOTP, email, SMS: at most one).
func Find(factors []Factor, kind string) (Factor, bool) {
	for _, f := range factors {
		if f.Kind == kind {
			return f, true
		}
	}
	return Factor{}, false
}

// AnyActive reports whether any of the factors is confirmed.
func AnyActive(factors []Factor) bool {
	for _, f := range factors {
		if f.Active() {
			return true
		}
	}
	return false
}

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
// a row, or 0 (authentication.Lockout, shared with password logins).
func Lockout(failures, threshold int, base, max time.Duration) time.Duration {
	return authentication.Lockout(failures, threshold, base, max)
}

// Summary is what a user or operator may see of a user's factors: never
// secrets or codes.
type Summary struct {
	Factors       []Factor `json:"factors"`
	RecoveryCodes int      `json:"recovery_codes_remaining"`
	// LockedUntil is set while wrong codes lock every factor.
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

// Enrolled reports whether the user has an active factor.
func (s Summary) Enrolled() bool { return AnyActive(s.Factors) }

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
	// Active are the kinds of the user's confirmed factors.
	Active []string
	// Allowed are the kinds the environment and the organization (when the
	// login has one) both allow.
	Allowed           []string
	Required          bool
	RequiredFederated bool
}

// Usable returns the user's factor kinds that may prove a login: allowed,
// and never the email factor after an email-code first factor (same
// channel).
func (p Policy) Usable(amr []string) []string {
	out := []string{}
	for _, k := range Kinds {
		if slices.Contains(p.Active, k) && p.allows(k, amr) {
			out = append(out, k)
		}
	}
	return out
}

// Enrollable returns the kinds a login may add while signing in: an
// authenticator app or the email address (SMS needs a phone number, added
// from self-service).
func (p Policy) Enrollable(amr []string) []string {
	out := []string{}
	for _, k := range []string{KindTOTP, KindEmail} {
		if p.allows(k, amr) {
			out = append(out, k)
		}
	}
	return out
}

func (p Policy) allows(kind string, amr []string) bool {
	return slices.Contains(p.Allowed, kind) && !(kind == KindEmail && slices.Contains(amr, "email"))
}

// Requirement decides: federated logins trust the identity provider unless
// the organization says otherwise; a user with a usable factor uses it; an
// organization requiring MFA, or a user whose factors are all unusable
// here, enrolls one. amr are the first factor's method references.
func (p Policy) Requirement(federated bool, amr []string) authentication.Requirement {
	if federated && !p.RequiredFederated {
		return authentication.Requirement{}
	}
	if usable := p.Usable(amr); len(usable) > 0 {
		return authentication.Requirement{Needed: true, Factors: append(usable, ProofRecovery)}
	}
	if p.Required || len(p.Active) > 0 {
		return authentication.Requirement{Needed: true, Enroll: true, Factors: p.Enrollable(amr)}
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
	// PasswordHash replaces the user's expired password once the second
	// factor passed; "" keeps it.
	PasswordHash string
}

// Verification is a verified second factor: the proof used and, when the
// code confirmed a new factor, the user's first recovery codes.
type Verification struct {
	Proof         string
	RecoveryCodes []string
}

// MaskEmail hides most of an address's local part.
func MaskEmail(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return "•••"
	}
	return local[:1] + "•••@" + domain
}

// MaskPhone keeps the country prefix sign and the last two digits.
func MaskPhone(phone string) string {
	if len(phone) < 4 {
		return "•••"
	}
	return phone[:2] + strings.Repeat("•", len(phone)-4) + phone[len(phone)-2:]
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

// Code purposes: a second-factor code (email or SMS), or the code that
// verifies a new SMS factor's phone number.
const (
	PurposeLogin = "mfa"
	PurposePhone = "phone_verification"
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
