package authentication

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SignInPolicy is which sign-in methods an environment allows and its
// default second-factor rules. An environment without one uses
// DefaultSignInPolicy (IAMKit's behaviour before policies existed).
// Organizations can only narrow the methods (Methods); applications narrow
// them further for the hosted pages (hosted.SignIn). Organization single
// sign-on follows its own enforcement and is not governed here.
type SignInPolicy struct {
	AllowPassword  bool `json:"allow_password" db:"allow_password"`
	AllowEmailCode bool `json:"allow_email_code" db:"allow_email_code"`
	// AllowSocial covers environment connections (Google, Microsoft, ...).
	AllowSocial bool `json:"allow_social" db:"allow_social"`
	// AllowPasswordReset offers "forgot password" (needs AllowPassword).
	AllowPasswordReset bool `json:"allow_password_reset" db:"allow_password_reset"`
	// MFARequired and MFAForFederated apply to every organization, on top
	// of the organization's own mfa_required / mfa_for_federated.
	MFARequired     bool `json:"mfa_required" db:"mfa_required"`
	MFAForFederated bool `json:"mfa_for_federated" db:"mfa_for_federated"`
	// AllowSignup lets people create their own account (verified email
	// first) in SignupOrganization and, when set, SignupGroup. The
	// organization is kept while sign-up is off.
	AllowSignup        bool                    `json:"allow_signup" db:"allow_signup"`
	SignupOrganization identity.OrganizationID `json:"signup_organization_id" db:"signup_organization_id"`
	SignupGroup        identity.GroupID        `json:"signup_group_id" db:"signup_group_id"`
	// Custom is false for the built-in default.
	Custom    bool       `json:"custom" db:"-"`
	UpdatedAt *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

// DefaultSignInPolicy allows every method and requires no second factor.
func DefaultSignInPolicy() SignInPolicy {
	return SignInPolicy{AllowPassword: true, AllowEmailCode: true, AllowSocial: true, AllowPasswordReset: true}
}

// Validate accepts every combination of methods: with all off only
// organization single sign-on remains, which is a valid enterprise setup.
// Sign-up needs an organization and a method new accounts can sign in with.
func (p SignInPolicy) Validate() error {
	if p.AllowPasswordReset && !p.AllowPassword {
		return errx.Validation("allow_password_reset needs allow_password")
	}
	if p.AllowSignup && p.SignupOrganization.IsZero() {
		return errx.Validation("allow_signup needs signup_organization_id")
	}
	if p.AllowSignup && !p.AllowPassword && !p.AllowEmailCode {
		return errx.Validation("allow_signup needs allow_password or allow_email_code")
	}
	if !p.SignupGroup.IsZero() && p.SignupOrganization.IsZero() {
		return errx.Validation("signup_group_id needs signup_organization_id")
	}
	return nil
}

// MethodSocial names environment (social) connections in sign-in
// policies; a Verified login carries MethodSSO for them.
const MethodSocial = "social"

// PolicyMethod is the sign-in policy method of a verified login: "" for
// organization single sign-on, which policies do not govern.
func (v Verified) PolicyMethod() string {
	if v.Method == MethodSSO {
		if v.Organization.IsZero() {
			return MethodSocial
		}
		return ""
	}
	return v.Method
}

// Methods is which sign-in methods an organization allows its members;
// they only narrow the environment's.
type Methods struct {
	Password  bool `db:"allow_password"`
	EmailCode bool `db:"allow_email_code"`
	Social    bool `db:"allow_social"`
}

// AllMethods allows everything (no organization chosen yet).
func AllMethods() Methods { return Methods{Password: true, EmailCode: true, Social: true} }

// Allows reports whether method (MethodPassword, MethodCode, MethodSocial)
// is allowed; "" (organization SSO) always is.
func (m Methods) Allows(method string) bool {
	switch method {
	case MethodPassword:
		return m.Password
	case MethodCode:
		return m.EmailCode
	case MethodSocial:
		return m.Social
	}
	return true
}

// Methods are the environment's allowed methods.
func (p SignInPolicy) Methods() Methods {
	return Methods{Password: p.AllowPassword, EmailCode: p.AllowEmailCode, Social: p.AllowSocial}
}

// Audit actions of sign-in policies.
const (
	ActionSignInPolicyUpdated = "sign_in_policy.update"
	ActionSignInPolicyDeleted = "sign_in_policy.delete"
)

// Error codes of refused sign-in methods.
const (
	CodeMethodNotAllowed      = "METHOD_NOT_ALLOWED"
	CodePasswordResetDisabled = "PASSWORD_RESET_DISABLED"
)

// ErrMethodNotAllowed refuses a sign-in method the environment or the
// organization does not allow.
func ErrMethodNotAllowed() error {
	e := errx.Forbidden("this sign-in method is not allowed here")
	e.Code = CodeMethodNotAllowed
	return e
}

// ErrPasswordResetDisabled refuses a password reset the environment does
// not offer.
func ErrPasswordResetDisabled() error {
	e := errx.Forbidden("password reset is not available; contact your administrator")
	e.Code = CodePasswordResetDisabled
	return e
}
