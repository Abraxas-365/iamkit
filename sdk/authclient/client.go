// Package authclient validates application access and provides identity
// endpoints for end-user authentication. Never use management credentials here.
//
//	client := authclient.New("http://localhost:8080",
//	    authclient.WithHTTPClient(myClient),
//	)
//	tokens, err := client.Login(ctx, authclient.PasswordLogin{...})
package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/Abraxas-365/iamkit/sdk/internal/transport"
)

// Client calls IAMKit's identity API (/identity/v1).
type Client struct {
	baseURL string
	http    *http.Client
}

// Option configures the identity client.
type Option func(*Client)

// WithHTTPClient overrides the default http.Client.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.http = c }
}

// New creates an identity client. baseURL is the IAMKit server root
// (e.g. "http://localhost:8080").
func New(baseURL string, opts ...Option) *Client {
	c := &Client{baseURL: strings.TrimRight(baseURL, "/")}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ── Shared types ──

type LoginContext struct {
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
}

type PasswordLogin struct {
	LoginContext
	Email    string `json:"email"`
	Password string `json:"password"`
	// NewPassword replaces an expired password. Login answers
	// apierror.CodePasswordChangeRequired (403) when the environment's
	// password policy says the password is too old; send the same login
	// again with NewPassword set. With a second factor the new password is
	// saved once VerifyMFA succeeds.
	NewPassword string `json:"new_password,omitempty"`
}

// TokenPair is a login answer. When MFARequired is set there are no tokens
// yet (AccessToken is empty and ExpiresIn is the pending login's lifetime):
// continue with VerifyMFA (and EnrollMFA first if EnrollmentRequired).
// Callers of Login/VerifyChallenge must check MFARequired before using
// AccessToken.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	// RecoveryCodes are returned once, by the login that enrolled the
	// user's first authenticator.
	RecoveryCodes []string `json:"recovery_codes,omitempty"`

	MFARequired        bool     `json:"mfa_required,omitempty"`
	MFAToken           string   `json:"mfa_token,omitempty"`
	Factors            []string `json:"factors,omitempty"`
	EnrollmentRequired bool     `json:"enrollment_required,omitempty"`
}

// Enrollment is an authenticator to add: show the otpauth URI as a QR code
// (or the secret for manual entry).
type Enrollment struct {
	FactorID string `json:"factor_id,omitempty"`
	Secret   string `json:"secret"`
	URI      string `json:"otpauth_uri"`
}

// Factor is a second factor of the user (never its secret). Kind is totp,
// email, sms or webauthn; Name labels security keys and passkeys.
type Factor struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	// Passkey marks a WebAuthn factor that can also sign in on its own.
	Passkey     bool       `json:"passkey,omitempty"`
	Phone       string     `json:"phone,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CodeSent reports a code emailed or texted for an email or SMS factor:
// Destination is masked (a•••@example.com, +1•••••••21).
type CodeSent struct {
	Factor      string    `json:"factor"`
	Destination string    `json:"destination"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Factors lists a user's second factors and remaining recovery codes.
type Factors struct {
	Factors                []Factor `json:"factors"`
	RecoveryCodesRemaining int      `json:"recovery_codes_remaining"`
	// LockedUntil is set while wrong codes lock every factor.
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

// WebAuthnOptions starts a security key or passkey ceremony: pass Options
// to navigator.credentials.create (registration) or .get (assertion), then
// send the browser's PublicKeyCredential JSON back with Session.
type WebAuthnOptions struct {
	Session   string          `json:"webauthn_session"`
	Options   json.RawMessage `json:"options"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// WebAuthnRegistration is a registered security key or passkey; the first
// factor of the user also returns RecoveryCodes (shown once).
type WebAuthnRegistration struct {
	Factor        Factor   `json:"factor"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

type Challenge struct {
	ID        string `json:"challenge_id"`
	Message   string `json:"message"`
	ExpiresIn int    `json:"expires_in"`
}

type ChallengeVerification struct {
	LoginContext
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	Purpose     string `json:"purpose"`
	Password    string `json:"password,omitempty"`
}

type FederationStart struct {
	LoginContext
	ConnectionID string `json:"connection_id"`
}

type FederationResult struct {
	AuthorizationURL string `json:"authorization_url"`
}

// Discovery tells a login screen how an email signs in. Method is "sso"
// (start federation with ConnectionID in OrganizationID) or "password".
// Required means password and email-code login are refused for this email
// in that organization. The answer depends only on the email's domain.
type Discovery struct {
	Method         string `json:"method"`
	OrganizationID string `json:"organization_id,omitempty"`
	ConnectionID   string `json:"connection_id,omitempty"`
	Required       bool   `json:"required"`
	// Provider is "ldap" when the connection is the organization's LDAP
	// directory: ask for the password and call DirectoryLogin instead of
	// redirecting to StartSSO.
	Provider string `json:"provider,omitempty"`
}

// InvitationPreview describes a pending invitation for an accept page.
type InvitationPreview struct {
	OrganizationID   string    `json:"organization_id"`
	OrganizationName string    `json:"organization_name"`
	Email            string    `json:"email"` // masked
	ExpiresAt        time.Time `json:"expires_at"`
	Status           string    `json:"status"`
	PasswordRequired bool      `json:"password_required"`
	SSORequired      bool      `json:"sso_required"`
}

// InvitationAcceptance accepts an invitation. Password is required for a
// new account unless SSO is enforced, and rejected for an existing one.
type InvitationAcceptance struct {
	Token    string `json:"token"`
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

// AcceptedInvitation: the invitee then signs in (password, or SSO when
// SSORequired).
type AcceptedInvitation struct {
	UserID         string `json:"user_id"`
	OrganizationID string `json:"organization_id"`
	Email          string `json:"email"`
	Created        bool   `json:"created"`
	SSORequired    bool   `json:"sso_required"`
}

type AddMemberRequest struct {
	EnvironmentID string `json:"environment_id"`
	Audience      string `json:"audience"`
	UserID        string `json:"user_id"`
}

// ── Internal HTTP helpers ──

func (c *Client) request(ctx context.Context, path, token string, input, output any) error {
	return c.requestMethod(ctx, "POST", path, token, input, output)
}

func (c *Client) requestMethod(ctx context.Context, method, path, token string, input, output any) error {
	var headers []transport.Header
	if token != "" {
		headers = append(headers, transport.Header{Key: "Authorization", Value: "Bearer " + token})
	}
	return transport.Do(c.http, ctx, method, c.baseURL+"/identity/v1"+path, headers, input, output)
}

// ── Authentication ──

// Login authenticates a user with email and password, returning access/refresh tokens.
func (c *Client) Login(ctx context.Context, input PasswordLogin) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/login", "", input, &out)
	return out, err
}

// Refresh exchanges a refresh token for a new token pair.
func (c *Client) Refresh(ctx context.Context, boundary LoginContext, refresh string) (TokenPair, error) {
	var out TokenPair
	input := struct {
		LoginContext
		Token string `json:"refresh_token"`
	}{boundary, refresh}
	err := c.request(ctx, "/refresh", "", input, &out)
	return out, err
}

// MachineToken exchanges a service account credential (ik_svc_) for access tokens.
func (c *Client) MachineToken(ctx context.Context, secret string) (TokenPair, error) {
	if !strings.HasPrefix(secret, "ik_svc_") {
		return TokenPair{}, &apierror.Error{Code: "VALIDATION", Message: "service credential required", HTTPStatus: 400}
	}
	var out TokenPair
	err := c.request(ctx, "/machine-token", secret, nil, &out)
	return out, err
}

// ── Multi-factor authentication ──

// VerifyMFA completes a login that answered MFARequired with an
// authenticator code or a recovery code.
func (c *Client) VerifyMFA(ctx context.Context, mfaToken, code string) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/mfa/verify", "", map[string]string{"mfa_token": mfaToken, "code": code}, &out)
	return out, err
}

// EnrollMFA returns the authenticator to add for a login with
// EnrollmentRequired; confirm it by calling VerifyMFA with its first code
// (the answer then carries RecoveryCodes).
func (c *Client) EnrollMFA(ctx context.Context, mfaToken string) (Enrollment, error) {
	var out Enrollment
	err := c.request(ctx, "/mfa/enroll", "", map[string]string{"mfa_token": mfaToken}, &out)
	return out, err
}

// ChallengeMFA sends a code for a pending login's email or SMS factor
// (factor "email" or "sms"); complete it with VerifyMFA. With
// EnrollmentRequired and "email" allowed, it enrolls the email factor.
func (c *Client) ChallengeMFA(ctx context.Context, mfaToken, factor string) (CodeSent, error) {
	var out CodeSent
	err := c.request(ctx, "/mfa/challenge", "", map[string]string{"mfa_token": mfaToken, "factor": factor}, &out)
	return out, err
}

func selfBody(environment, audience, code string) map[string]string {
	return map[string]string{"environment_id": environment, "audience": audience, "code": code}
}

// ListFactors returns the authenticated user's second factors.
func (c *Client) ListFactors(ctx context.Context, token, environment, audience string) (Factors, error) {
	var out Factors
	q := "?environment_id=" + url.QueryEscape(environment) + "&audience=" + url.QueryEscape(audience)
	err := c.requestMethod(ctx, "GET", "/me/factors"+q, token, nil, &out)
	return out, err
}

// StartTOTP creates an unconfirmed authenticator for the user; confirm it
// with ConfirmTOTP.
func (c *Client) StartTOTP(ctx context.Context, token, environment, audience string) (Enrollment, error) {
	var out Enrollment
	err := c.request(ctx, "/me/factors/totp", token, selfBody(environment, audience, ""), &out)
	return out, err
}

// ConfirmTOTP activates the authenticator with its first code and returns
// the recovery codes (shown once).
func (c *Client) ConfirmTOTP(ctx context.Context, token, environment, audience, code string) ([]string, error) {
	var out struct {
		Codes []string `json:"recovery_codes"`
	}
	err := c.request(ctx, "/me/factors/totp/confirm", token, selfBody(environment, audience, code), &out)
	return out.Codes, err
}

// RemoveTOTP deletes the authenticator; code (TOTP or recovery) proves possession.
func (c *Client) RemoveTOTP(ctx context.Context, token, environment, audience, code string) error {
	return c.requestMethod(ctx, "DELETE", "/me/factors/totp", token, selfBody(environment, audience, code), nil)
}

// StartEmailFactor emails a code to the account address; confirm it with
// ConfirmFactor(…, "email", code).
func (c *Client) StartEmailFactor(ctx context.Context, token, environment, audience string) (CodeSent, error) {
	var out CodeSent
	err := c.request(ctx, "/me/factors/email", token, selfBody(environment, audience, ""), &out)
	return out, err
}

// StartSMSFactor texts a code to phone (E.164); confirm it with
// ConfirmFactor(…, "sms", code), which also verifies the user's phone.
func (c *Client) StartSMSFactor(ctx context.Context, token, environment, audience, phone string) (CodeSent, error) {
	var out CodeSent
	body := selfBody(environment, audience, "")
	body["phone"] = phone
	err := c.request(ctx, "/me/factors/sms", token, body, &out)
	return out, err
}

// ConfirmFactor activates a started factor (kind totp, email or sms) with
// its first code and returns the recovery codes (shown once).
func (c *Client) ConfirmFactor(ctx context.Context, token, environment, audience, kind, code string) ([]string, error) {
	var out struct {
		Codes []string `json:"recovery_codes"`
	}
	err := c.request(ctx, "/me/factors/"+url.PathEscape(kind)+"/confirm", token, selfBody(environment, audience, code), &out)
	return out.Codes, err
}

// SendFactorCode sends a code to the active email or SMS factor, to prove
// possession before RemoveFactor or RegenerateRecoveryCodes.
func (c *Client) SendFactorCode(ctx context.Context, token, environment, audience, kind string) (CodeSent, error) {
	var out CodeSent
	err := c.request(ctx, "/me/factors/"+url.PathEscape(kind)+"/challenge", token, selfBody(environment, audience, ""), &out)
	return out, err
}

// RemoveFactor deletes the factor of kind; code (from any active factor or
// a recovery code) proves possession.
func (c *Client) RemoveFactor(ctx context.Context, token, environment, audience, kind, code string) error {
	return c.requestMethod(ctx, "DELETE", "/me/factors/"+url.PathEscape(kind), token, selfBody(environment, audience, code), nil)
}

// RegenerateRecoveryCodes replaces the recovery codes; code proves possession.
func (c *Client) RegenerateRecoveryCodes(ctx context.Context, token, environment, audience, code string) ([]string, error) {
	var out struct {
		Codes []string `json:"recovery_codes"`
	}
	err := c.request(ctx, "/me/factors/recovery-codes", token, selfBody(environment, audience, code), &out)
	return out.Codes, err
}

// AssertMFA starts the security key prompt of a login that answered
// MFARequired with "webauthn" among its Factors; complete it with
// VerifyMFAWebAuthn.
func (c *Client) AssertMFA(ctx context.Context, mfaToken string) (WebAuthnOptions, error) {
	var out WebAuthnOptions
	err := c.request(ctx, "/mfa/webauthn", "", map[string]string{"mfa_token": mfaToken}, &out)
	return out, err
}

// VerifyMFAWebAuthn completes a pending login with the browser's assertion
// (the PublicKeyCredential JSON) answering AssertMFA.
func (c *Client) VerifyMFAWebAuthn(ctx context.Context, mfaToken, session string, credential json.RawMessage) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/mfa/verify", "", map[string]any{"mfa_token": mfaToken, "webauthn_session": session, "credential": credential}, &out)
	return out, err
}

// BeginPasskeyLogin starts a passkey sign-in in an environment (no email
// first: the browser offers the user's passkeys).
func (c *Client) BeginPasskeyLogin(ctx context.Context, environment string) (WebAuthnOptions, error) {
	var out WebAuthnOptions
	err := c.request(ctx, "/passkeys/login/begin", "", map[string]string{"environment_id": environment}, &out)
	return out, err
}

// DirectoryLogin signs in with the password of the organization's LDAP
// directory (Discovery.Provider "ldap"). It answers like Login, including
// MFARequired.
func (c *Client) DirectoryLogin(ctx context.Context, boundary LoginContext, connection, email, password string) (TokenPair, error) {
	var out TokenPair
	body := struct {
		LoginContext
		Connection string `json:"connection_id"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}{boundary, connection, email, password}
	err := c.request(ctx, "/federation/ldap/login", "", body, &out)
	return out, err
}

// PasskeyLogin signs in with the browser's passkey assertion. A passkey
// verified the user, so no second factor follows (amr hwk, user, mfa).
func (c *Client) PasskeyLogin(ctx context.Context, boundary LoginContext, session string, credential json.RawMessage) (TokenPair, error) {
	var out TokenPair
	body := struct {
		LoginContext
		Session    string          `json:"webauthn_session"`
		Credential json.RawMessage `json:"credential"`
	}{boundary, session, credential}
	err := c.request(ctx, "/passkeys/login/finish", "", body, &out)
	return out, err
}

func webauthnBody(environment, audience string, extra map[string]any) map[string]any {
	extra["environment_id"], extra["audience"] = environment, audience
	return extra
}

// StartWebAuthn begins registering a security key (passkey false) or a
// passkey that can also sign in on its own; finish with FinishWebAuthn.
func (c *Client) StartWebAuthn(ctx context.Context, token, environment, audience, name string, passkey bool) (WebAuthnOptions, error) {
	var out WebAuthnOptions
	err := c.request(ctx, "/me/factors/webauthn", token, webauthnBody(environment, audience, map[string]any{"name": name, "passkey": passkey}), &out)
	return out, err
}

// FinishWebAuthn stores the key from the browser's attestation answering
// StartWebAuthn.
func (c *Client) FinishWebAuthn(ctx context.Context, token, environment, audience, session string, credential json.RawMessage) (WebAuthnRegistration, error) {
	var out WebAuthnRegistration
	err := c.request(ctx, "/me/factors/webauthn/confirm", token, webauthnBody(environment, audience, map[string]any{"webauthn_session": session, "credential": credential}), &out)
	return out, err
}

// ProveWebAuthn starts a key assertion that proves possession for
// RemoveWebAuthn (a code from another factor works too).
func (c *Client) ProveWebAuthn(ctx context.Context, token, environment, audience string) (WebAuthnOptions, error) {
	var out WebAuthnOptions
	err := c.request(ctx, "/me/factors/webauthn/challenge", token, webauthnBody(environment, audience, map[string]any{}), &out)
	return out, err
}

// RenameWebAuthn renames one of the user's security keys or passkeys.
func (c *Client) RenameWebAuthn(ctx context.Context, token, environment, audience, factor, name string) (Factor, error) {
	var out Factor
	err := c.requestMethod(ctx, "PATCH", "/me/factors/webauthn/"+url.PathEscape(factor), token, webauthnBody(environment, audience, map[string]any{"name": name}), &out)
	return out, err
}

// WebAuthnProof proves possession for RemoveWebAuthn: a Code (any active
// factor or a recovery code) or a key assertion (Session + Credential).
type WebAuthnProof struct {
	Code       string
	Session    string
	Credential json.RawMessage
}

// RemoveWebAuthn deletes one security key or passkey.
func (c *Client) RemoveWebAuthn(ctx context.Context, token, environment, audience, factor string, proof WebAuthnProof) error {
	body := map[string]any{"code": proof.Code}
	if proof.Session != "" {
		body["webauthn_session"], body["credential"] = proof.Session, proof.Credential
	}
	return c.requestMethod(ctx, "DELETE", "/me/factors/webauthn/"+url.PathEscape(factor), token, webauthnBody(environment, audience, body), nil)
}

// ── Challenges (OTP / email verification) ──

// InitiateChallenge starts an email-based challenge (login, registration, etc.).
func (c *Client) InitiateChallenge(ctx context.Context, environment, email, purpose string) (Challenge, error) {
	return c.InitiateChallengeWith(ctx, ChallengeRequest{Environment: environment, Email: email, Purpose: purpose})
}

// ChallengeRequest starts an email challenge. Locale is the email language
// (a tag such as "es" or an Accept-Language list); empty uses the
// environment's email language. It applies when IAMKit writes the email
// (smtp, resend); the webhook payload is unchanged.
type ChallengeRequest struct {
	Environment string `json:"environment_id"`
	Email       string `json:"email"`
	Purpose     string `json:"purpose"`
	Locale      string `json:"locale,omitempty"`
}

// InitiateChallengeWith is InitiateChallenge with every option.
func (c *Client) InitiateChallengeWith(ctx context.Context, input ChallengeRequest) (Challenge, error) {
	var out Challenge
	err := c.request(ctx, "/challenges", "", input, &out)
	return out, err
}

// VerifyChallenge completes a challenge by providing the verification code.
func (c *Client) VerifyChallenge(ctx context.Context, input ChallengeVerification) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/challenges/verify", "", input, &out)
	return out, err
}

// ── Self-registration ──

// SignupRequest asks for a new account. Password is optional when the
// environment allows email codes (the account then signs in with them).
// Locale is the email language, as in ChallengeRequest.
type SignupRequest struct {
	Environment string `json:"environment_id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Password    string `json:"password,omitempty"`
	Locale      string `json:"locale,omitempty"`
}

// SignedUp is the account a completed sign-up created.
type SignedUp struct {
	UserID         string `json:"user_id"`
	OrganizationID string `json:"organization_id"`
	Email          string `json:"email"`
}

// Signup emails a code confirming the address. The answer is the same
// whether or not the email already has an account (then nothing is sent).
// Errors: apierror.CodeSignupDisabled (403), CodePasswordPolicy (400),
// SSO_REQUIRED (403).
func (c *Client) Signup(ctx context.Context, input SignupRequest) (Challenge, error) {
	var out Challenge
	err := c.request(ctx, "/signup", "", input, &out)
	return out, err
}

// CompleteSignup creates the account once code is right. It does not sign
// the user in. Errors: 401 for a wrong or expired code (five wrong codes end
// the sign-up), apierror.CodeAccountExists (409).
func (c *Client) CompleteSignup(ctx context.Context, environment, challengeID, code string) (SignedUp, error) {
	var out SignedUp
	err := c.request(ctx, "/signup/verify", "", map[string]string{"environment_id": environment, "challenge_id": challengeID, "code": code}, &out)
	return out, err
}

// ── Federation (SSO) ──

// Discover returns the login method for an email ("home realm discovery").
func (c *Client) Discover(ctx context.Context, environment, email string) (Discovery, error) {
	var out Discovery
	err := c.request(ctx, "/discover", "", map[string]string{"environment_id": environment, "email": email}, &out)
	return out, err
}

// ── Invitations ──

// PreviewInvitation returns what an accept page may show for token.
func (c *Client) PreviewInvitation(ctx context.Context, token string) (InvitationPreview, error) {
	var out InvitationPreview
	err := c.request(ctx, "/invitations/preview", "", map[string]string{"token": token}, &out)
	return out, err
}

// AcceptInvitation joins the invitee to the organization. It does not sign
// them in.
func (c *Client) AcceptInvitation(ctx context.Context, input InvitationAcceptance) (AcceptedInvitation, error) {
	var out AcceptedInvitation
	err := c.request(ctx, "/invitations/accept", "", input, &out)
	return out, err
}

// StartFederation initiates an SSO login flow, returning the IdP authorization URL.
// The user's browser should be redirected to the returned URL.
func (c *Client) StartFederation(ctx context.Context, input FederationStart) (FederationResult, error) {
	var out FederationResult
	err := c.request(ctx, "/federation/start", "", input, &out)
	return out, err
}

// ── Session management ──

// Logout invalidates the user's session.
func (c *Client) Logout(ctx context.Context, token, environment, audience string) error {
	return c.request(ctx, "/logout", token, map[string]string{"environment_id": environment, "audience": audience}, nil)
}

// ── Profile ──

// Profile returns the authenticated user's profile.
func (c *Client) Profile(ctx context.Context, token, environment, audience string) (Profile, error) {
	var out Profile
	q := "?environment_id=" + environment + "&audience=" + audience
	err := c.requestMethod(ctx, "GET", "/me"+q, token, nil, &out)
	return out, err
}

// UpdateProfile changes the authenticated user's display name.
func (c *Client) UpdateProfile(ctx context.Context, token, environment, audience, name string) error {
	return c.requestMethod(ctx, "PATCH", "/me", token, map[string]string{"environment_id": environment, "audience": audience, "name": name}, nil)
}

// Organizations returns the organizations the authenticated user belongs to.
func (c *Client) Organizations(ctx context.Context, token, environment, audience string) ([]Organization, error) {
	var out []Organization
	q := "?environment_id=" + environment + "&audience=" + audience
	err := c.requestMethod(ctx, "GET", "/organizations"+q, token, nil, &out)
	return out, err
}

// ── Membership ──

// AddMember adds a user to an organization (self-service). Requires a valid access token.
func (c *Client) AddMember(ctx context.Context, token string, input AddMemberRequest) error {
	return c.request(ctx, "/memberships", token, input, nil)
}

// ── Token introspection ──

// Introspect validates a token against the server, checking revocation status
// and enforcing the given trust boundaries.
func (c *Client) Introspect(ctx context.Context, token, issuer, audience, environment, application, resource string) (*Claims, error) {
	if issuer == "" || audience == "" || environment == "" || application == "" || resource == "" {
		return nil, &apierror.Error{Code: "VALIDATION", Message: "expected boundaries required", HTTPStatus: 400}
	}
	var out struct {
		Active bool   `json:"active"`
		Claims Claims `json:"claims"`
	}
	if err := c.request(ctx, "/introspect", token, map[string]string{"environment_id": environment, "audience": audience}, &out); err != nil {
		return nil, err
	}
	p := out.Claims
	hasAudience := false
	for _, v := range p.Audience {
		if v == audience {
			hasAudience = true
		}
	}
	if !out.Active || p.Issuer != issuer || !hasAudience || p.EnvironmentID != environment || p.ApplicationID != application || p.ResourceID != resource || p.Subject == "" {
		return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "inactive token or boundary mismatch", HTTPStatus: 401}
	}
	if p.Purpose != "application" && p.Purpose != "machine" {
		return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "invalid token purpose", HTTPStatus: 401}
	}
	return &p, nil
}
