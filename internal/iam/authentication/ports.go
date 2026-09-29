package authentication

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Commands interface {
	// Login signs in with a password. An expired password answers
	// ErrPasswordChangeRequired unless newPassword replaces it.
	Login(ctx context.Context, boundary Context, email, password, newPassword string) (Result, error)
	Refresh(ctx context.Context, boundary Context, token string) (Issued, error)
	// InitiateChallenge emails a code when the address is eligible; locale
	// is the requested email language ("" = the environment default).
	InitiateChallenge(ctx context.Context, environment identity.EnvironmentID, email, purpose, locale string) (identity.ChallengeID, error)
	VerifyChallenge(ctx context.Context, boundary Context, challenge identity.ChallengeID, code, purpose, password string) (Result, error)
}

// SecondFactor is the multi-factor step of headless logins, implemented by
// the mfa module. Nil disables MFA.
type SecondFactor interface {
	Requirement(ctx context.Context, boundary Context, user identity.UserID, federated bool) (Requirement, error)
	// Begin parks the login until its second factor; passwordHash (a
	// replacement for an expired password) is stored once it passes.
	Begin(ctx context.Context, boundary Context, user identity.UserID, amr []string, enroll bool, passwordHash string) (string, error)
	// Complete verifies the code of a pending login and runs issue before
	// committing: when issue fails the verification rolls back.
	Complete(ctx context.Context, token, code string, issue func(done Completed) error) (Completed, error)
	Enroll(ctx context.Context, token string) (Enrollment, error)
}

// MFACommands finish a headless login that answered mfa_required.
type MFACommands interface {
	VerifyMFA(ctx context.Context, token, code string) (Issued, error)
	EnrollMFA(ctx context.Context, token string) (Enrollment, error)
}

// Authenticator splits login in two for the hosted pages: verify who the
// user is (no organization yet), then issue the session once the
// organization is chosen.
type Authenticator interface {
	VerifyPassword(ctx context.Context, environment identity.EnvironmentID, email, password string) (Verified, error)
	VerifyCode(ctx context.Context, environment identity.EnvironmentID, challenge identity.ChallengeID, code string) (Verified, error)
	// Organizations lists the organizations in which the user may use the
	// target application and resource with the method they verified with
	// (ErrMethodNotAllowed when only the method keeps them out).
	Organizations(ctx context.Context, target Target, verified Verified) ([]Organization, error)
	// Issue creates the session; password and code logins are refused where
	// the organization enforces SSO or does not allow the method, and a
	// verified login whose password expired is refused until ChangePassword.
	Issue(ctx context.Context, boundary Context, verified Verified) (Issued, error)
	// ChangePassword replaces the expired password of a verified login
	// (after any second factor) and returns it cleared.
	ChangePassword(ctx context.Context, environment identity.EnvironmentID, verified Verified, password string) (Verified, error)
}

type SessionCommands interface {
	Logout(ctx context.Context, token Token) error
	UpdateProfile(ctx context.Context, token Token, name string) error
	AddMember(ctx context.Context, token Token, user identity.UserID) error
}
type SessionQueries interface {
	Profile(ctx context.Context, token Token) (Profile, error)
	Organizations(ctx context.Context, token Token) ([]Organization, error)
}

type Delivery interface {
	Send(ctx context.Context, message Message) error
}

// Mailer sends an email IAMKit rendered (SMTP, Resend).
type Mailer interface {
	Deliver(ctx context.Context, email Email) error
}

// Renderer writes the email for a message: the environment's brand
// (Branding), language (message.Locale, else the brand's, else the
// deployment default) and wording (Templates over DefaultCopy). A draft's
// set fields replace the saved wording and brand name, for previews. The
// sender is left empty.
type Renderer interface {
	Render(ctx context.Context, message Message, draft Draft) (Email, error)
}

// Branding reads how an environment's emails look (hosted login branding).
type Branding interface {
	Brand(ctx context.Context, environment identity.EnvironmentID) (Brand, error)
}

// Templates reads an environment's saved wording for one email in one
// language; ok is false when it keeps IAMKit's defaults.
type Templates interface {
	Copy(ctx context.Context, environment identity.EnvironmentID, purpose, locale string) (copy Copy, ok bool, err error)
}

// Cipher seals delivery secrets (SMTP password, Resend API key) at rest
// (IAMKIT_ENCRYPTION_KEY).
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

// DeliveryConfigCommands manages per-environment delivery settings; every
// change is audited (delivery.update, delivery.delete, delivery.test).
type DeliveryConfigCommands interface {
	SetDeliveryConfig(ctx context.Context, m Mutation, input DeliveryConfigInput) error
	DeleteDeliveryConfig(ctx context.Context, m Mutation) error
	// TestDelivery sends a test message through the environment's effective
	// delivery, records and audits the attempt, and returns its outcome.
	TestDelivery(ctx context.Context, m Mutation, input TestInput) (Attempt, error)
}

// DeliveryConfigQueries reads per-environment delivery settings.
type DeliveryConfigQueries interface {
	DeliveryConfig(ctx context.Context, environment identity.EnvironmentID) (DeliveryConfig, error)
	// DeliveryStatus reports the effective source and recent activity.
	DeliveryStatus(ctx context.Context, environment identity.EnvironmentID) (DeliveryStatus, error)
	// Preview renders a sample email as IAMKit would send it for the
	// environment (brand, language, wording); nothing is sent or recorded.
	Preview(ctx context.Context, environment identity.EnvironmentID, input PreviewInput) (Preview, error)
}

// DeliveryConfigRepository is the storage interface for delivery configs.
type DeliveryConfigRepository interface {
	GetDeliveryConfig(ctx context.Context, environment identity.EnvironmentID) (DeliveryConfig, DeliverySecret, error)
	// SetDeliveryConfig stores input without its plaintext secrets: the
	// webhook token as given, sealed as the SMTP password / Resend API key.
	// It and DeleteDeliveryConfig audit m in the same transaction.
	SetDeliveryConfig(ctx context.Context, m Mutation, input DeliveryConfigInput, sealed string) error
	DeleteDeliveryConfig(ctx context.Context, m Mutation) error
	// RecordAttempt stores the environment's latest attempt (and failure).
	RecordAttempt(ctx context.Context, environment identity.EnvironmentID, attempt Attempt) error
	// Activity returns the environment's recorded attempts (empty if none).
	Activity(ctx context.Context, environment identity.EnvironmentID) (Activity, error)
	// Audit writes an audit event for a console action.
	Audit(ctx context.Context, m Mutation) error
}

// TemplateCommands changes an environment's email wording; audited as
// email_template.updated / email_template.reset.
type TemplateCommands interface {
	// SetTemplate saves wording for one email in one language; empty
	// wording resets it.
	SetTemplate(ctx context.Context, m Mutation, key TemplateKey, input Copy) error
	// ResetTemplate returns one email in one language to IAMKit's wording
	// (idempotent).
	ResetTemplate(ctx context.Context, m Mutation, key TemplateKey) error
}

// TemplateQueries reads an environment's email wording.
type TemplateQueries interface {
	// ListTemplates lists every email in every language, customized or not.
	ListTemplates(ctx context.Context, environment identity.EnvironmentID) ([]TemplateSummary, error)
	Template(ctx context.Context, environment identity.EnvironmentID, key TemplateKey) (TemplateView, error)
}

// TemplateRepository stores email wording; writes audit m in the same
// transaction.
type TemplateRepository interface {
	// ListTemplates returns the environment's saved templates.
	ListTemplates(ctx context.Context, environment identity.EnvironmentID) ([]EmailTemplate, error)
	// GetTemplate returns a saved template; NotFound when there is none.
	GetTemplate(ctx context.Context, environment identity.EnvironmentID, key TemplateKey) (EmailTemplate, error)
	SetTemplate(ctx context.Context, m Mutation, key TemplateKey, input Copy) error
	DeleteTemplate(ctx context.Context, m Mutation, key TemplateKey) error
}
type Passwords interface {
	Hash(password string) (string, error)
	Compare(hash, password string) bool
}

// PasswordPolicyCommands manage an environment's password policy and the
// requirements organizations add to it; every change is audited.
type PasswordPolicyCommands interface {
	SetPasswordPolicy(ctx context.Context, m Mutation, input PasswordPolicy) (PasswordPolicy, error)
	// DeletePasswordPolicy returns the environment to the default policy.
	DeletePasswordPolicy(ctx context.Context, m Mutation) error
	SetOrganizationPasswordPolicy(ctx context.Context, m Mutation, organization identity.OrganizationID, input PasswordRequirements) (PasswordRequirements, error)
	// DeleteOrganizationPasswordPolicy drops the organization's requirements.
	DeleteOrganizationPasswordPolicy(ctx context.Context, m Mutation, organization identity.OrganizationID) error
}

// PasswordPolicyQueries read password policies and check new passwords.
type PasswordPolicyQueries interface {
	// PasswordPolicy is the effective policy (Custom false for the default).
	PasswordPolicy(ctx context.Context, environment identity.EnvironmentID) (PasswordPolicy, error)
	// OrganizationPasswordPolicy is what the organization adds (Custom
	// false when nothing).
	OrganizationPasswordPolicy(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (PasswordRequirements, error)
	// CheckPassword applies the environment's policy to a new password,
	// breach check included.
	CheckPassword(ctx context.Context, environment identity.EnvironmentID, password string) error
	// CheckMemberPassword applies the environment's policy tightened by the
	// organization's requirements (a new account joining it).
	CheckMemberPassword(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, password string) error
}

// PasswordPolicyRepository stores password policies; writes audit m in the
// same transaction.
type PasswordPolicyRepository interface {
	// GetPasswordPolicy returns the saved policy; NotFound when there is none.
	GetPasswordPolicy(ctx context.Context, environment identity.EnvironmentID) (PasswordPolicy, error)
	SetPasswordPolicy(ctx context.Context, m Mutation, input PasswordPolicy) error
	DeletePasswordPolicy(ctx context.Context, m Mutation) error
	// GetOrganizationPasswordPolicy returns the organization's saved
	// requirements (Custom false when none); NotFound for an unknown
	// organization.
	GetOrganizationPasswordPolicy(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (PasswordRequirements, error)
	// SetOrganizationPasswordPolicy saves them; NotFound for an unknown
	// organization.
	SetOrganizationPasswordPolicy(ctx context.Context, m Mutation, organization identity.OrganizationID, input PasswordRequirements) error
	DeleteOrganizationPasswordPolicy(ctx context.Context, m Mutation, organization identity.OrganizationID) error
	// MemberRequirements lists the requirements of every active
	// organization the user is an active member of.
	MemberRequirements(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]PasswordRequirements, error)
	// ChallengeRequirements is MemberRequirements for the user of a
	// challenge (empty for an unknown one); read without locks.
	ChallengeRequirements(ctx context.Context, environment identity.EnvironmentID, challenge identity.ChallengeID) ([]PasswordRequirements, error)
}

// SignInPolicyCommands manage an environment's sign-in policy; audited.
type SignInPolicyCommands interface {
	SetSignInPolicy(ctx context.Context, m Mutation, input SignInPolicy) (SignInPolicy, error)
	// DeleteSignInPolicy returns the environment to the default policy.
	DeleteSignInPolicy(ctx context.Context, m Mutation) error
}

// SignInPolicyQueries read an environment's sign-in policy.
type SignInPolicyQueries interface {
	// SignInPolicy is the effective policy (Custom false for the default).
	SignInPolicy(ctx context.Context, environment identity.EnvironmentID) (SignInPolicy, error)
}

// SignInPolicyRepository stores sign-in policies; writes audit m in the
// same transaction.
type SignInPolicyRepository interface {
	// GetSignInPolicy returns the saved policy; NotFound when there is none.
	GetSignInPolicy(ctx context.Context, environment identity.EnvironmentID) (SignInPolicy, error)
	SetSignInPolicy(ctx context.Context, m Mutation, input SignInPolicy) error
	DeleteSignInPolicy(ctx context.Context, m Mutation) error
	// SignupTarget reports whether organization is an active organization
	// of the environment and group (when not zero) an operator-managed
	// (not SCIM) group of it.
	SignupTarget(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, group identity.GroupID) (organizationOK, groupOK bool, err error)
}

// SignupCommands are self-registration: a person asks for an account and
// confirms their email with a code before it exists.
type SignupCommands interface {
	// Signup emails a code to confirm the address; it answers the same
	// for an email that already has an account (nothing is sent then).
	Signup(ctx context.Context, input Signup) (identity.ChallengeID, error)
	// CompleteSignup checks the code and creates the account, its
	// membership in the sign-up organization and its group membership.
	CompleteSignup(ctx context.Context, environment identity.EnvironmentID, signup identity.ChallengeID, code string) (SignedUp, error)
}

// SignupTransaction is the storage of self-registration, one transaction.
type SignupTransaction interface {
	// AccountExists reports whether the environment has a user with email.
	AccountExists(ctx context.Context, environment identity.EnvironmentID, email string) (bool, error)
	// RecentSignups counts sign-ups for email in the last ten minutes.
	RecentSignups(ctx context.Context, environment identity.EnvironmentID, email string) (int, error)
	// CreateSignup stores p and consumes older sign-ups for its email.
	CreateSignup(ctx context.Context, p PendingSignup) error
	// PendingSignup locks the live (unconsumed, unexpired) sign-up;
	// Unauthorized "invalid challenge" when there is none.
	PendingSignup(ctx context.Context, environment identity.EnvironmentID, signup identity.ChallengeID) (PendingSignup, error)
	FailSignup(ctx context.Context, signup identity.ChallengeID) error
	// Join consumes the sign-up and creates its account, membership and
	// group membership, audited with actor = the new user. An account
	// with the email answers ErrAccountExists; an inactive organization
	// ErrSignupDisabled.
	Join(ctx context.Context, j Joining) error
	// SSORequired is Transaction.SSORequired for an environment and email.
	SSORequired(ctx context.Context, environment identity.EnvironmentID, email string) (bool, error)
	// SignupMethods are the methods the sign-up organization allows; none
	// when it is not an active organization of the environment.
	SignupMethods(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (Methods, error)
	Commit() error
	Rollback() error
}

// SignupRepository begins self-registration transactions.
type SignupRepository interface {
	BeginSignup(ctx context.Context) (SignupTransaction, error)
}

// Breaches reports whether a password appears in known data breaches.
// Errors mean the answer is unknown; callers let the password through.
type Breaches interface {
	Breached(ctx context.Context, password string) (bool, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
	Code() (string, error)
}

type TokenIssuer interface {
	Issue(token Token, audience string) (string, error)
	KeyID() string
	JWKS() any
	Machine(ctx context.Context, raw string) (string, error)
}
type TokenValidator interface {
	Validate(ctx context.Context, raw string, audience string, environment identity.EnvironmentID) (Token, error)
	// ValidateSelf verifies a JWT that IAMKit itself issued, without requiring
	// the caller to specify audience/environment upfront. Used by /api/v1/*
	// where the token's own claims determine the environment scope.
	ValidateSelf(ctx context.Context, raw string) (Token, error)
}
type TokenCodec interface {
	Sign(token Token) (string, error)
	Verify(raw, audience string) (Token, error)
	// VerifySelf checks signature, issuer, and expiry without audience enforcement.
	VerifySelf(raw string) (Token, error)
	KeyID() string
	JWKS() any
}

// OAuthTokens reports whether an OAuth-issued access token is still live.
// The OAuth adapter owns token storage (and its signature hashing), so the
// authentication service asks it rather than reading OAuth tables itself.
// signature is the JWT's third segment.
type OAuthTokens interface {
	Active(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, signature string) (bool, error)
}

// Transactions retain the original user/session/challenge lock ordering.
type Repository interface {
	Begin(ctx context.Context) (Transaction, error)
}
type Transaction interface {
	// PasswordUser locks the active user signing in with a password.
	PasswordUser(ctx context.Context, boundary Context, email string) (PasswordAccount, error)
	// SetLoginFailures records wrong passwords in a row and the lock they
	// caused (nil clears it).
	SetLoginFailures(ctx context.Context, user identity.UserID, failures int, lockedUntil *time.Time) error
	// SetPassword stores a new password hash, restarts its age and clears
	// the lockout.
	SetPassword(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, hash string) error
	Audit(ctx context.Context, m Mutation) error
	// SSORequired reports whether the boundary organization requires SSO for
	// the email: it has an active enforced connection, has verified the
	// email's domain, and the email's user has no sso_bypass membership.
	SSORequired(ctx context.Context, boundary Context, email string) (bool, error)
	// OrganizationMethods are the sign-in methods the organization allows;
	// Unauthorized (like a wrong password) for an unknown organization.
	OrganizationMethods(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (Methods, error)
	// AccessibleOrganizations lists active organizations where the user is an
	// active member with grants on the target resource of an active
	// application linked to it, with the methods each allows.
	AccessibleOrganizations(ctx context.Context, target Target, user identity.UserID) ([]Organization, error)
	Resolve(ctx context.Context, boundary Context, user identity.UserID) (Access, error)
	// CreateSession stores the session; authenticated is its auth_time,
	// kept across refreshes.
	CreateSession(ctx context.Context, boundary Context, user identity.UserID, session identity.SessionID, authenticated, expires time.Time, amr []string) error
	SaveRefresh(ctx context.Context, hash []byte, user identity.UserID, session identity.SessionID, expires time.Time) error
	Refresh(ctx context.Context, boundary Context, hash []byte) (Session, error)
	RevokeSession(ctx context.Context, session identity.SessionID) error
	UseRefresh(ctx context.Context, hash []byte) error
	EligibleChallengeUser(ctx context.Context, environment identity.EnvironmentID, email, purpose string) (identity.UserID, error)
	RecentChallenges(ctx context.Context, user identity.UserID, purpose string) (int, error)
	CreateChallenge(ctx context.Context, challenge identity.ChallengeID, user identity.UserID, purpose string, environment identity.EnvironmentID, hash []byte) error
	Challenge(ctx context.Context, challenge identity.ChallengeID, user identity.UserID, purpose string) (Challenge, error)
	FailChallenge(ctx context.Context, challenge identity.ChallengeID) error
	// CompleteChallenge consumes the challenge and verifies the email; a
	// password reset also stores password (a hash) like SetPassword.
	CompleteChallenge(ctx context.Context, challenge identity.ChallengeID, user identity.UserID, purpose string, environment identity.EnvironmentID, password string) error
	Commit() error
	Rollback() error
}

type TokenRepository interface {
	Current(ctx context.Context, token Token, environment identity.EnvironmentID) ([]string, error)
	ActorActive(ctx context.Context, token Token) (bool, error)
	Machine(ctx context.Context, hash []byte) (Token, string, error)
	Revoke(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID) error
	Profile(ctx context.Context, token Token) (Profile, error)
	Organizations(ctx context.Context, token Token) ([]Organization, error)
	UpdateProfile(ctx context.Context, token Token, name string) error
	AddMember(ctx context.Context, token Token, user identity.UserID) error
}
