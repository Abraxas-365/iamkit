package authentication

import (
	"fmt"
	"time"
	"unicode"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// PasswordPolicy is an environment's rules for end-user passwords. An
// environment without one uses DefaultPasswordPolicy (IAMKit's behaviour
// before policies existed). Operators' console passwords never follow it.
type PasswordPolicy struct {
	MinLength     int  `json:"min_length" db:"min_length"`
	RequireUpper  bool `json:"require_upper" db:"require_upper"`
	RequireLower  bool `json:"require_lower" db:"require_lower"`
	RequireDigit  bool `json:"require_digit" db:"require_digit"`
	RequireSymbol bool `json:"require_symbol" db:"require_symbol"`
	// MaxAgeDays is how long a password lasts before the next sign-in must
	// replace it; 0 never expires.
	MaxAgeDays int `json:"max_age_days" db:"max_age_days"`
	// LockoutThreshold wrong passwords in a row lock the account for
	// LockoutMinutes, doubled per further round up to
	// config.PasswordLockoutMax; 0 never locks.
	LockoutThreshold int `json:"lockout_threshold" db:"lockout_threshold"`
	LockoutMinutes   int `json:"lockout_minutes" db:"lockout_minutes"`
	// BreachCheck refuses new passwords found in known breaches (Have I
	// Been Pwned, k-anonymity); an unreachable service lets them through.
	BreachCheck bool `json:"breach_check" db:"breach_check"`
	// Custom is false for the built-in default.
	Custom    bool       `json:"custom" db:"-"`
	UpdatedAt *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

// DefaultPasswordPolicy is the policy of an environment that saved none.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: config.PasswordMinLength, LockoutMinutes: int(config.PasswordLockout / time.Minute)}
}

// Password policy limits.
const (
	PasswordPolicyMinLength   = 8
	PasswordPolicyMaxAgeDays  = 3650
	PasswordPolicyMaxLockouts = 100
	PasswordPolicyMaxMinutes  = 1440
)

func (p PasswordPolicy) Validate() error {
	switch {
	case p.MinLength < PasswordPolicyMinLength || p.MinLength > config.PasswordMaxLength:
		return errx.Validation(fmt.Sprintf("min_length must be between %d and %d", PasswordPolicyMinLength, config.PasswordMaxLength))
	case p.MaxAgeDays < 0 || p.MaxAgeDays > PasswordPolicyMaxAgeDays:
		return errx.Validation(fmt.Sprintf("max_age_days must be between 0 and %d", PasswordPolicyMaxAgeDays))
	case p.LockoutThreshold < 0 || p.LockoutThreshold > PasswordPolicyMaxLockouts:
		return errx.Validation(fmt.Sprintf("lockout_threshold must be between 0 and %d", PasswordPolicyMaxLockouts))
	case p.LockoutMinutes < 1 || p.LockoutMinutes > PasswordPolicyMaxMinutes:
		return errx.Validation(fmt.Sprintf("lockout_minutes must be between 1 and %d", PasswordPolicyMaxMinutes))
	}
	return nil
}

// Password rules a new password can break (PasswordRejected's rule).
const (
	RuleLength   = "length"
	RuleUpper    = "upper"
	RuleLower    = "lower"
	RuleDigit    = "digit"
	RuleSymbol   = "symbol"
	RuleBreached = "breached"
	RuleReused   = "reused"
)

// CodePasswordPolicy marks a new password the policy refuses.
const CodePasswordPolicy = "PASSWORD_POLICY"

// PasswordRejected is the 400 for a new password breaking rule; the
// details carry the rule and the minimum length for translated pages.
func PasswordRejected(rule string, minLength int) error {
	messages := map[string]string{
		RuleLength:   fmt.Sprintf("password must be %d-%d characters long", minLength, config.PasswordMaxLength),
		RuleUpper:    "password must include an uppercase letter",
		RuleLower:    "password must include a lowercase letter",
		RuleDigit:    "password must include a digit",
		RuleSymbol:   "password must include a symbol",
		RuleBreached: "this password appears in a known data breach; choose another",
		RuleReused:   "new password must differ from the current one",
	}
	e := errx.Validation(messages[rule]).WithDetail("rule", rule).WithDetail("min_length", minLength)
	e.Code, e.Public = CodePasswordPolicy, true
	return e
}

// Check applies the composition rules to a new password (not the breach
// check, which needs the network). Length counts bytes: bcrypt reads 72.
func (p PasswordPolicy) Check(password string) error {
	if len(password) < p.MinLength || len(password) > config.PasswordMaxLength {
		return PasswordRejected(RuleLength, p.MinLength)
	}
	var upper, lower, digit, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case !unicode.IsSpace(r):
			symbol = true
		}
	}
	for _, rule := range []struct {
		required, present bool
		name              string
	}{{p.RequireUpper, upper, RuleUpper}, {p.RequireLower, lower, RuleLower}, {p.RequireDigit, digit, RuleDigit}, {p.RequireSymbol, symbol, RuleSymbol}} {
		if rule.required && !rule.present {
			return PasswordRejected(rule.name, p.MinLength)
		}
	}
	return nil
}

// Expired reports whether a password chosen at changed must be replaced.
func (p PasswordPolicy) Expired(changed, now time.Time) bool {
	return p.MaxAgeDays > 0 && !now.Before(changed.Add(time.Duration(p.MaxAgeDays)*24*time.Hour))
}

// LockedUntil is when failures wrong passwords in a row lock the account
// until, or nil.
func (p PasswordPolicy) LockedUntil(failures int, now time.Time) *time.Time {
	d := Lockout(failures, p.LockoutThreshold, time.Duration(p.LockoutMinutes)*time.Minute, config.PasswordLockoutMax)
	if d == 0 {
		return nil
	}
	until := now.Add(d)
	return &until
}

// Lockout returns how long failures in a row lock a credential, or 0:
// every threshold failures lock it for base, doubled per further round, up
// to max. Password logins and second factors share it.
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

// PasswordAccount is the password state of an account signing in.
type PasswordAccount struct {
	ID          identity.UserID `db:"id"`
	Hash        string          `db:"password_hash"`
	Failures    int             `db:"failed_logins"`
	LockedUntil *time.Time      `db:"locked_until"`
	Changed     time.Time       `db:"password_changed_at"`
}

// Locked reports whether wrong passwords locked the account at now.
func (a PasswordAccount) Locked(now time.Time) bool {
	return a.LockedUntil != nil && now.Before(*a.LockedUntil)
}

// Audit actions of password lockout.
const (
	ActionUserLocked                        = "user.locked"
	ActionPasswordPolicyUpdated             = "password_policy.update"
	ActionPasswordPolicyDeleted             = "password_policy.delete"
	ActionOrganizationPasswordPolicyUpdated = "organization_password_policy.update"
	ActionOrganizationPasswordPolicyDeleted = "organization_password_policy.delete"
)

// PasswordRequirements are the password rules an organization adds to its
// environment's policy. Users belong to the environment and have one
// password for every organization, so an organization cannot own their
// policy: a member's policy is the environment's tightened by the
// requirements of each organization they are an active member of
// (PasswordPolicy.Tighten). Zero values add nothing; lockout stays the
// environment's (it counts before any organization is known).
type PasswordRequirements struct {
	// MinLength 0 keeps the environment's minimum.
	MinLength     int  `json:"min_length" db:"min_length"`
	RequireUpper  bool `json:"require_upper" db:"require_upper"`
	RequireLower  bool `json:"require_lower" db:"require_lower"`
	RequireDigit  bool `json:"require_digit" db:"require_digit"`
	RequireSymbol bool `json:"require_symbol" db:"require_symbol"`
	// MaxAgeDays 0 keeps the environment's expiry.
	MaxAgeDays  int  `json:"max_age_days" db:"max_age_days"`
	BreachCheck bool `json:"breach_check" db:"breach_check"`
	// Custom is false when the organization adds nothing.
	Custom    bool       `json:"custom" db:"-"`
	UpdatedAt *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

func (r PasswordRequirements) Validate() error {
	switch {
	case r.MinLength != 0 && (r.MinLength < PasswordPolicyMinLength || r.MinLength > config.PasswordMaxLength):
		return errx.Validation(fmt.Sprintf("min_length must be 0 or between %d and %d", PasswordPolicyMinLength, config.PasswordMaxLength))
	case r.MaxAgeDays < 0 || r.MaxAgeDays > PasswordPolicyMaxAgeDays:
		return errx.Validation(fmt.Sprintf("max_age_days must be between 0 and %d", PasswordPolicyMaxAgeDays))
	}
	return nil
}

// Tighten applies an organization's requirements: the longer minimum,
// every required character class, the shorter expiry and the breach check
// when either asks for it.
func (p PasswordPolicy) Tighten(r PasswordRequirements) PasswordPolicy {
	p.MinLength = max(p.MinLength, r.MinLength)
	p.RequireUpper = p.RequireUpper || r.RequireUpper
	p.RequireLower = p.RequireLower || r.RequireLower
	p.RequireDigit = p.RequireDigit || r.RequireDigit
	p.RequireSymbol = p.RequireSymbol || r.RequireSymbol
	if r.MaxAgeDays > 0 && (p.MaxAgeDays == 0 || r.MaxAgeDays < p.MaxAgeDays) {
		p.MaxAgeDays = r.MaxAgeDays
	}
	p.BreachCheck = p.BreachCheck || r.BreachCheck
	return p
}

// CodePasswordChangeRequired answers a sign-in whose password expired: the
// client sends the password again with new_password.
const CodePasswordChangeRequired = "PASSWORD_CHANGE_REQUIRED"

// ErrPasswordChangeRequired refuses a sign-in until the expired password
// is replaced.
func ErrPasswordChangeRequired() error {
	e := errx.Forbidden("your password has expired; choose a new one to finish signing in")
	e.Code = CodePasswordChangeRequired
	return e
}
