package authentication

import (
	"slices"
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
	// AllowPasskey lets users sign in with a passkey (needs the webauthn
	// factor allowed). Omitted on update, the stored value is kept.
	AllowPasskey *bool `json:"allow_passkey" db:"allow_passkey"`
	// AllowPasswordReset offers "forgot password" (needs AllowPassword).
	AllowPasswordReset bool `json:"allow_password_reset" db:"allow_password_reset"`
	// MFARequired and MFAForFederated apply to every organization, on top
	// of the organization's own mfa_required / mfa_for_federated.
	MFARequired     bool `json:"mfa_required" db:"mfa_required"`
	MFAForFederated bool `json:"mfa_for_federated" db:"mfa_for_federated"`
	// AllowedFactors are the second-factor kinds users may use (totp,
	// webauthn, sms, email); organizations narrow them. Email and SMS are
	// off by default. Omitted on update, the stored list is kept.
	AllowedFactors []string `json:"allowed_factors" db:"-"`
	// AllowSignup lets people create their own account (verified email
	// first) in SignupOrganization and, when set, SignupGroup. The
	// organization is kept while sign-up is off.
	AllowSignup        bool                    `json:"allow_signup" db:"allow_signup"`
	SignupOrganization identity.OrganizationID `json:"signup_organization_id" db:"signup_organization_id"`
	SignupGroup        identity.GroupID        `json:"signup_group_id" db:"signup_group_id"`
	// RequireTerms makes sign-up record that the person accepted the terms
	// (accept_terms; the hosted page links the branding's terms_url).
	// Omitted on update, the stored value is kept.
	RequireTerms *bool `json:"require_terms" db:"require_terms"`
	// Waitlist puts password / email-code sign-up behind an operator's
	// approval (needs AllowSignup): people join a list instead of getting
	// a code. Federation sign-up, invitations, SCIM and operator-created
	// users are never gated. Omitted on update, the stored value is kept,
	// so a client that does not know the field never opens sign-up.
	Waitlist *bool `json:"waitlist" db:"waitlist"`
	// WaitlistAutoApproveDomains are email domains that skip the list.
	// Omitted (null) on update, the stored list is kept; [] clears it.
	WaitlistAutoApproveDomains []string `json:"waitlist_auto_approve_domains" db:"-"`
	// WaitlistSignupURL is the sign-up page the approval email links to
	// (?waitlist=<token> is appended); empty: the email carries the token
	// but no link. Omitted on update, the stored value is kept.
	WaitlistSignupURL *string `json:"waitlist_signup_url" db:"waitlist_signup_url"`
	// Custom is false for the built-in default.
	Custom    bool       `json:"custom" db:"-"`
	UpdatedAt *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

// DefaultSignInPolicy allows every method and requires no second factor.
func DefaultSignInPolicy() SignInPolicy {
	passkey, waitlist, url := true, false, ""
	return SignInPolicy{AllowPassword: true, AllowEmailCode: true, AllowSocial: true, AllowPasskey: &passkey, AllowPasswordReset: true, AllowedFactors: DefaultFactors(),
		Waitlist: &waitlist, WaitlistAutoApproveDomains: []string{}, WaitlistSignupURL: &url}
}

// DefaultFactors are the second factors of an environment without a policy:
// authenticator apps and security keys. Email and SMS codes are opt-in.
func DefaultFactors() []string { return []string{"totp", "webauthn"} }

// Validate accepts every combination of methods: with all off only
// organization single sign-on remains, which is a valid enterprise setup.
// Sign-up needs an organization and a method new accounts can sign in with.
func (p SignInPolicy) Validate() error {
	if err := identity.ValidateFactors("allowed_factors", p.AllowedFactors); err != nil {
		return err
	}
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
	if p.WaitlistOn() && !p.AllowSignup {
		return errx.Validation("waitlist needs allow_signup")
	}
	if err := validWaitlistDomains(p.WaitlistAutoApproveDomains); err != nil {
		return err
	}
	if u := p.WaitlistURL(); u != "" && !SecureURL(u) {
		return errx.Validation("waitlist_signup_url must use HTTPS (HTTP allowed only on loopback)")
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
	Passkey   bool `db:"allow_passkey"`
}

// AllMethods allows everything (no organization chosen yet).
func AllMethods() Methods {
	return Methods{Password: true, EmailCode: true, Social: true, Passkey: true}
}

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
	case MethodPasskey:
		return m.Passkey
	}
	return true
}

// Methods are the environment's allowed methods.
func (p SignInPolicy) Methods() Methods {
	return Methods{Password: p.AllowPassword, EmailCode: p.AllowEmailCode, Social: p.AllowSocial, Passkey: p.PasskeyAllowed() && slices.Contains(p.AllowedFactors, "webauthn")}
}

// TermsRequired reads RequireTerms (nil: not required, the default).
func (p SignInPolicy) TermsRequired() bool { return p.RequireTerms != nil && *p.RequireTerms }

// WaitlistOn reads Waitlist (nil: off, the default).
func (p SignInPolicy) WaitlistOn() bool { return p.Waitlist != nil && *p.Waitlist }

// WaitlistURL reads WaitlistSignupURL (nil: none).
func (p SignInPolicy) WaitlistURL() string {
	if p.WaitlistSignupURL == nil {
		return ""
	}
	return *p.WaitlistSignupURL
}

// PasskeyAllowed reads AllowPasskey (nil: allowed, the default).
func (p SignInPolicy) PasskeyAllowed() bool {
	return p.AllowPasskey == nil || *p.AllowPasskey
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
// ErrRiskChallenge asks for a risk challenge where none can be parked
// (e.g. a pre_sign_in action's challenge on a path without a pending
// login): the caller turns it into a challenge or refuses the sign-in.
func ErrRiskChallenge() error {
	e := errx.Forbidden("this sign-in needs an extra verification")
	e.Code = CodeRiskChallenge
	return e
}

// ErrChallengeUnavailable: a risk challenge was asked of a user without a
// verified email address.
func ErrChallengeUnavailable() error {
	e := errx.Forbidden("this sign-in needs an extra verification that is not available for this account")
	e.Code = CodeChallengeUnavailable
	return e
}

// Codes of the risk challenge errors.
const (
	CodeRiskChallenge        = "RISK_CHALLENGE"
	CodeChallengeUnavailable = "CHALLENGE_UNAVAILABLE"
)

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
