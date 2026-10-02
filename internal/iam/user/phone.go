package user

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
)

// Phone numbers. users.phone (E.164, identity.Phone) is informational: it
// is not a sign-in identifier. It becomes phone_verified when the user
// enters a code texted to it (self-service, below, or confirming an SMS
// second factor), or when an operator marks it verified (audited
// ActionPhoneVerifiedSet). Changing the number clears phone_verified.

// Audit actions of phone numbers.
const (
	ActionPhoneVerified    = "user.phone_verified"
	ActionPhoneRemoved     = "user.phone_removed"
	ActionPhoneVerifiedSet = "user.phone_verified_set"
)

// PhoneVerification is a number the user asked to verify: the hashed code
// texted to it and the counters that limit sends and guesses. One per user;
// asking for another number replaces the number and code but keeps the
// counters, so switching numbers does not lift the limits.
type PhoneVerification struct {
	Phone       string     `db:"phone"`
	CodeHash    []byte     `db:"code_hash"`
	Expires     *time.Time `db:"expires_at"`
	Sent        *time.Time `db:"sent_at"`
	Attempts    int        `db:"attempts"`
	CodesSent   int        `db:"codes_sent"`
	CodesWindow *time.Time `db:"codes_window"`
}

// Send returns the verification that texts a new code (hash, expiring
// config.FactorCodeTTL after now) to phone, or a 429 error within
// config.FactorCodeCooldown of the last code or past
// config.FactorCodesPerHour.
func (p PhoneVerification) Send(phone string, hash []byte, now time.Time) (PhoneVerification, error) {
	if p.Sent != nil && now.Sub(*p.Sent) < config.FactorCodeCooldown {
		e := errx.TooManyRequests("a code was just sent; wait a few seconds before asking for another")
		e.Code = "CODE_COOLDOWN"
		return p, e
	}
	sent, window := p.CodesSent, now
	if p.CodesWindow != nil && now.Sub(*p.CodesWindow) < time.Hour {
		window = *p.CodesWindow
	} else {
		sent = 0
	}
	if sent >= config.FactorCodesPerHour {
		e := errx.TooManyRequests("too many codes sent; try again later")
		e.Code = "CODE_LIMIT"
		return p, e
	}
	expires := now.Add(config.FactorCodeTTL)
	return PhoneVerification{Phone: phone, CodeHash: hash, Expires: &expires, Sent: &now, CodesSent: sent + 1, CodesWindow: &window}, nil
}

// Pending reports whether a code can still be entered at now.
func (p PhoneVerification) Pending(now time.Time) bool {
	return len(p.CodeHash) > 0 && p.Expires != nil && now.Before(*p.Expires)
}

// PhoneCodeSent answers a started verification; Destination is masked.
type PhoneCodeSent struct {
	Destination string    `json:"destination"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// MaskPhone keeps the country prefix and the last two digits.
func MaskPhone(phone string) string {
	if len(phone) < 4 {
		return "•••"
	}
	return phone[:2] + strings.Repeat("•", len(phone)-4) + phone[len(phone)-2:]
}

// FreshAuth checks that a token's auth_time (Unix seconds, 0 when unknown)
// is recent enough (config.MFAFreshAuth) to change the user's phone.
func FreshAuth(authTime int64, now time.Time) error {
	if authTime != 0 && now.Sub(time.Unix(authTime, 0)) <= config.MFAFreshAuth {
		return nil
	}
	e := errx.Forbidden("sign in again to change your phone number")
	e.Code = "REAUTHENTICATION_REQUIRED"
	return e
}

// WrongPhoneCode answers a wrong, expired or missing code: 422, so clients
// do not mistake it for an expired access token.
func WrongPhoneCode() error {
	e := errx.Business("invalid verification code")
	e.Code = "INVALID_CODE"
	return e
}
