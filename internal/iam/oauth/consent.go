package oauth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Consent policies of an OAuth client (D29): whether its users consent to
// what it asks for at a protected resource. Clients named outside IAMKit
// (metadata documents, dynamic registration) and clients made from a
// preset template are third parties and always ConsentRequired;
// operator-registered clients are first-party (ConsentSkip) unless an
// operator requires consent for one.
const (
	ConsentRequired = "required"
	ConsentSkip     = "skip"
)

// ValidateConsentPolicy accepts required and skip.
func ValidateConsentPolicy(policy string) error {
	if policy != ConsentRequired && policy != ConsentSkip {
		return errx.Validation("consent_policy must be required or skip")
	}
	return nil
}

// ThirdParty reports whether a client is a third party: named outside
// IAMKit, or made from a preset template.
func ThirdParty(source, preset string) bool {
	return (source != "" && source != SourceRegistered) || preset != ""
}

// CheckConsentPolicy refuses skip for a third-party client.
func CheckConsentPolicy(policy, source, preset string) error {
	if err := ValidateConsentPolicy(policy); err != nil {
		return err
	}
	if policy == ConsentSkip && ThirdParty(source, preset) {
		return errx.Validation("consent_policy of a client named outside IAMKit or made from a preset is always required")
	}
	return nil
}

// RequiresConsent reports whether the client's users consent to what it
// asks for at a protected resource. Third parties always do, whatever the
// row says.
func (c Client) RequiresConsent() bool {
	return c.ConsentPolicy == ConsentRequired || c.External()
}

// ConsentableOIDCScopes are the OpenID Connect scopes a user is asked
// about (they release profile data); openid, offline_access and
// organization hints are protocol, never asked.
var ConsentableOIDCScopes = []string{"profile", "email", "phone"}

// ConsentScopes are the scopes of a resource flow authorization a user is
// asked about: the resource's permissions and the profile data scopes
// among granted, in order.
func ConsentScopes(target *ProtectedTarget, granted []string) []string {
	out := []string{}
	for _, s := range granted {
		if slices.Contains(target.Scopes, s) || slices.Contains(ConsentableOIDCScopes, s) {
			out = appendScope(out, s)
		}
	}
	return out
}

// Agreed is what already covers an authorization without asking: the
// user's live consent and, at a server in ConsentModeAdminGranted, the
// administrator's live grants for the client (environment-wide and the
// user's organization).
type Agreed struct {
	User  []string
	Admin []string
}

// Covers is every scope agreed, by the user or an administrator.
func (a Agreed) Covers() []string {
	out := slices.Clone(a.User)
	for _, s := range a.Admin {
		out = appendScope(out, s)
	}
	return out
}

// PendingConsent is what the user must still agree to: the asked scopes
// neither they nor an administrator agreed to. prompt=consent asks again
// everything an administrator did not grant (D29: the page shows only
// what is new, so a consent never re-asks what it holds otherwise).
func PendingConsent(asked []string, agreed Agreed, force bool) []string {
	covered := agreed.Covers()
	if force {
		covered = agreed.Admin
	}
	out := []string{}
	for _, s := range asked {
		if !slices.Contains(covered, s) {
			out = appendScope(out, s)
		}
	}
	return out
}

// AllowedAtRefresh is what a refresh of a consent-checked grant may still
// issue: the scopes the user or an administrator agree to now. A refresh
// issues the session's consented scopes held to it (and to the user's
// current permissions, EffectiveScopes).
func AllowedAtRefresh(consented []string, agreed Agreed) []string {
	covered := agreed.Covers()
	out := []string{}
	for _, s := range consented {
		if slices.Contains(covered, s) {
			out = appendScope(out, s)
		}
	}
	return out
}

// ConsentKey names one consent: a user, in one organization, to a client,
// at a protected resource.
type ConsentKey struct {
	Environment  identity.EnvironmentID
	User         identity.UserID
	Organization identity.OrganizationID
	Client       identity.ClientID
	Protected    identity.ProtectedResourceID
}

// ConsentDecision is a user's answer on a consent page: approving records
// the scopes asked (ConsentRecord), rejecting answers access_denied to the
// client.
type ConsentDecision struct {
	Approve bool
	// UI is ConsentUIHosted or ConsentUICustom: the surface that asked
	// (event data).
	UI string
}

// ConsentRecord is a consent being recorded, with what its event carries
// (never a token).
type ConsentRecord struct {
	Key ConsentKey
	// ID is the row a new consent gets; an existing live consent keeps
	// its own and gains the scopes.
	ID identity.ConsentID
	// Requested are the scopes the authorization asked for; Scopes those
	// the user agreed to now.
	Requested []string
	Scopes    []string
	UI        string
	// ClientID is the client's public client_id; Host its client_id's
	// host ("" for clients not named by a URL).
	ClientID string
	Host     string
	Resource string
}

// Reasons a consent or an administrator grant ended (data.reason of
// oauth_consent.revoked and oauth_client.grant_revoked).
const (
	ConsentRevokedByUser     = "user"
	ConsentRevokedByOperator = "operator"
	ConsentClientBlocked     = "client_blocked"
	GrantRevokedByOperator   = "operator"
	GrantExpired             = "expired"
	// GrantConsentModeChanged: the server went back to per-user consent.
	GrantConsentModeChanged = "consent_mode_changed"
)

// Consent is what a user agreed a client may do in one organization at a
// protected resource.
type Consent struct {
	ID            identity.ConsentID            `json:"id"`
	Organization  identity.OrganizationID       `json:"organization_id"`
	User          identity.UserID               `json:"user_id"`
	Client        identity.ClientID             `json:"client_id"`
	Protected     *identity.ProtectedResourceID `json:"protected_resource_id"`
	Scopes        []string                      `json:"scopes"`
	CreatedAt     time.Time                     `json:"created_at"`
	UpdatedAt     time.Time                     `json:"updated_at"`
	RevokedAt     *time.Time                    `json:"revoked_at,omitempty"`
	RevokedReason string                        `json:"revoked_reason,omitempty"`
}

// ConnectedApp is a client that holds, or may get without asking, access
// to a user's account at one protected resource in one organization: a
// live consent, live sessions, or both (a first-party client has sessions
// only).
type ConnectedApp struct {
	Client ConnectedClient `json:"client"`
	// Protected is the server the client reaches; Resource its URI.
	Protected    identity.ProtectedResourceID `json:"protected_resource_id"`
	Resource     string                       `json:"resource"`
	ResourceName string                       `json:"resource_name"`
	Organization identity.OrganizationID      `json:"organization_id"`
	// Scopes are what the user consented to (empty for a first-party
	// client, which never asks).
	Scopes []string `json:"scopes"`
	// ConsentedAt is when the user first consented (nil: never asked).
	ConsentedAt *time.Time `json:"consented_at"`
	// Sessions are the client's live sessions for the user there;
	// LastUsedAt the newest of their last refresh.
	Sessions   int        `json:"active_sessions"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// ConnectedClient is how a connected app shows its client: never a name
// it chose alone. Host is the client_id URL's host (CIMD); Verified names
// the preset that vouches for it, the only verified identity (M5).
type ConnectedClient struct {
	ID       identity.ClientID `json:"id"`
	ClientID string            `json:"client_id"`
	Source   string            `json:"source"`
	Name     string            `json:"name"`
	Host     string            `json:"host"`
	LogoURI  string            `json:"logo_uri"`
	Preset   string            `json:"preset"`
	Verified string            `json:"verified_name"`
}

// Describe fills a connected client's shown identity from its row: the
// client_id host, the preset that vouches for it, and the logo only on
// that host.
func (c ConnectedClient) Describe(logo string) ConnectedClient {
	c.Host = ClientHost(c.ClientID)
	c.LogoURI = LogoShown(c.ClientID, logo)
	if c.Source == SourceCIMD {
		if p, ok := PresetForClient(c.ClientID); ok {
			c.Preset, c.Verified = p.Key, p.Name
		}
	} else if c.Preset != "" {
		if p, ok := FindPreset(c.Preset); ok {
			c.Verified = p.Name
		}
	}
	return c
}

// ConnectedAppFilter narrows a user's connected apps to one organization
// (nil: every organization of the user).
type ConnectedAppFilter struct {
	Organization *identity.OrganizationID
}

// Disconnect ends a user's connection to a client: their live consents to
// it (revoked_reason Reason) and the client's sessions for them, in the
// filter's organization (nil: all), in one transaction.
type Disconnect struct {
	Environment  identity.EnvironmentID
	User         identity.UserID
	Client       identity.ClientID
	Organization *identity.OrganizationID
	Reason       string
}

// ClientGrant is scopes an administrator granted a client at a protected
// resource for every user of the environment (Organization nil) or of one
// organization (D31). It covers users only while the server is in
// ConsentModeAdminGranted; beyond it users still consent.
type ClientGrant struct {
	ID            identity.ClientGrantID       `json:"id"`
	Protected     identity.ProtectedResourceID `json:"protected_resource_id"`
	Client        identity.ClientID            `json:"client_id"`
	Organization  *identity.OrganizationID     `json:"organization_id"`
	Scopes        []string                     `json:"scopes"`
	ExpiresAt     *time.Time                   `json:"expires_at"`
	CreatedAt     time.Time                    `json:"created_at"`
	UpdatedAt     time.Time                    `json:"updated_at"`
	RevokedAt     *time.Time                   `json:"revoked_at,omitempty"`
	RevokedReason string                       `json:"revoked_reason,omitempty"`
}

// ClientGrantInput grants a client scopes (PUT: replaces the live grant of
// the same client and organization). ExpiresAt nil: until revoked.
type ClientGrantInput struct {
	Scopes       []string                 `json:"scopes"`
	Organization *identity.OrganizationID `json:"organization_id"`
	ExpiresAt    *time.Time               `json:"expires_at"`
}

// MaxConsentScopes bounds a consent's and a grant's scopes.
const MaxConsentScopes = 200

func (in ClientGrantInput) Validate(now time.Time) error {
	if len(in.Scopes) == 0 || len(in.Scopes) > MaxConsentScopes {
		return errx.Validation("scopes must name between 1 and 200 permissions")
	}
	seen := map[string]bool{}
	for _, s := range in.Scopes {
		// Format and duplicates only: CheckScopes holds them to the
		// resource's permissions (identity.ValidatePermissions also caps
		// a list at a resource's own bound, not a grant's).
		if err := identity.ValidatePermissions([]string{s}, ""); err != nil || seen[s] {
			return errx.Validation("scopes must be distinct permissions of the resource")
		}
		seen[s] = true
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		return errx.Validation("expires_at must be in the future")
	}
	return nil
}

// CheckScopes refuses scopes outside the protected resource's permissions.
func (in ClientGrantInput) CheckScopes(permissions []string) error {
	for _, s := range in.Scopes {
		if !slices.Contains(permissions, s) {
			return errx.Validation("scope " + s + " is not a permission of the resource")
		}
	}
	return nil
}

// ClientGrantSave is a grant as the repository writes it.
type ClientGrantSave struct {
	ID        identity.ClientGrantID
	Protected identity.ProtectedResourceID
	Client    identity.ClientID
	Input     ClientGrantInput
}

// ClientGrantFilter narrows a server's grants to one client (nil: all) and
// to live ones unless Revoked.
type ClientGrantFilter struct {
	Client  *identity.ClientID
	Revoked bool
}

// Audited actions of consents and administrator grants.
const (
	ActionConsentRevoke     = "oauth_consent.revoke"
	ActionClientGrant       = "oauth_client.grant"
	ActionClientGrantRevoke = "oauth_client.grant_revoke"
)

// ErrConsentPending is how an authorization that waits for the user's
// consent ends its first pass: the ticket now holds the session and the
// scopes to ask about, and is not spent.
var ErrConsentPending = errors.New("oauth: consent pending")

// ConsentPending is what an authorization's prepare step answers when the
// user must consent first: Flows.Complete stores Session and Scopes on the
// ticket (Authorization.AwaitConsent), commits without spending it and
// returns it (errors.Is(err, ErrConsentPending)).
type ConsentPending struct {
	Session identity.SessionID
	Scopes  []string
	// Hosted: the hosted pages signed Session in (Ticket.ConsentHosted).
	Hosted bool
}

func (p *ConsentPending) Error() string        { return ErrConsentPending.Error() }
func (p *ConsentPending) Is(target error) bool { return target == ErrConsentPending }

// ErrConsentNotPending refuses a consent decision for an authorization
// that does not wait for one (never asked, or decided already).
func ErrConsentNotPending() error {
	e := errx.Conflict("this authorization is not waiting for consent")
	e.Code = CodeConsentNotPending
	return e
}

// Codes of the consent step's refusals (custom UIs branch on them).
const (
	CodeConsentNotPending = "CONSENT_NOT_PENDING"
	CodeConsentHosted     = "CONSENT_UI_HOSTED"
)

// ErrConsentModePerUser refuses an administrator grant at a server where
// every user consents for themselves.
func ErrConsentModePerUser() error {
	return errx.Conflict("the protected resource's consent_mode is per_user: switch it to admin_granted to grant clients scopes")
}

// ErrConsentUI refuses a custom UI's consent decision in an environment
// that consents on the hosted page.
func ErrConsentUI() error {
	e := errx.Forbidden("this environment asks for consent on the hosted page")
	e.Code = CodeConsentHosted
	return e
}

// ConsentPrompt is an authorization waiting for the user's consent: what
// the consent page (hosted, or the environment's own UI) shows. Only the
// scopes the user must still agree to are asked (Pending); Unheld are
// those of them the user does not hold yet (granted only once they do,
// shown apart); Agreed the asked scopes already covered.
type ConsentPrompt struct {
	Client       ConnectedClient
	Protected    identity.ProtectedResourceID
	Resource     string
	ResourceName string
	User         identity.UserID
	Organization identity.OrganizationID
	Pending      []string
	Unheld       []string
	Agreed       []string
	// UI is the environment's consent_ui: a custom UI may decide only
	// when it is ConsentUICustom (the hosted page always may).
	UI string
	// Environment and HostedLogin brand the hosted page.
	Environment identity.EnvironmentID
	Form        string
}

// NewConsentPrompt splits what a waiting authorization asks: pending are
// the ticket's scopes, asked the authorization's consentable scopes and
// permissions the user's current ones.
func NewConsentPrompt(pending, asked, permissions []string) (held, unheld, agreed []string) {
	held, unheld, agreed = []string{}, []string{}, []string{}
	for _, s := range pending {
		if slices.Contains(ConsentableOIDCScopes, s) || slices.Contains(permissions, s) {
			held = append(held, s)
		} else {
			unheld = append(unheld, s)
		}
	}
	for _, s := range asked {
		if !slices.Contains(pending, s) {
			agreed = append(agreed, s)
		}
	}
	return held, unheld, agreed
}

// ConsentCommands are what a user, an operator or the system does with
// consents and administrator grants.
type ConsentCommands interface {
	// Disconnect revokes the user's live consents to a client (Reason
	// ConsentRevokedByUser or ConsentRevokedByOperator) and ends the
	// client's sessions for them, in one transaction. Not found when the
	// client holds neither for the user.
	Disconnect(ctx context.Context, m Mutation, input Disconnect) error
	// GrantClient replaces the live administrator grant of the client at
	// the protected resource for the same organization (nil: every user of
	// the environment). The server must be ConsentModeAdminGranted.
	GrantClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID, input ClientGrantInput) (ClientGrant, error)
	// RevokeClientGrant ends a live grant and the client's sessions it
	// covered (the organization's, or the environment's).
	RevokeClientGrant(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID, grant identity.ClientGrantID) error
	// ExpireClientGrants is the client_grant_expire job.
	ExpireClientGrants(ctx context.Context) (more bool, err error)
	// PruneConsents is the oauth_consent_prune job: revoked consents and
	// grants older than the security retention are deleted.
	PruneConsents(ctx context.Context) (more bool, err error)
}

// ConsentQueries are the reads of the same.
type ConsentQueries interface {
	// Agreed is what covers key now: the user's live consent and (admin)
	// the live administrator grants (refresh, D32).
	Agreed(ctx context.Context, key ConsentKey, admin bool) (Agreed, error)
	// ConnectedApps lists the clients that hold access to the user's
	// account (live consents or sessions), newest first.
	ConnectedApps(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, filter ConnectedAppFilter) ([]ConnectedApp, error)
	ListClientGrants(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter ClientGrantFilter) ([]ClientGrant, error)
}

// ConsentRepository persists consents and grants; every write records
// its event in the same transaction.
type ConsentRepository interface {
	// Agreed reads, without a lock, the user's live consent and (when
	// admin is set) the live administrator grants covering the key.
	Agreed(ctx context.Context, key ConsentKey, admin bool) (Agreed, error)
	ConnectedApps(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, filter ConnectedAppFilter) ([]ConnectedApp, error)
	Disconnect(ctx context.Context, m Mutation, input Disconnect) (int, error)
	// ClientGrantTarget checks the client is a client of the protected
	// resource (an external client of it, or a registered client of its
	// resource) and returns the resource's permissions and consent mode.
	ClientGrantTarget(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (ClientGrantTarget, error)
	SaveClientGrant(ctx context.Context, m Mutation, grant ClientGrantSave) (ClientGrant, error)
	RevokeClientGrant(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID, grant identity.ClientGrantID) error
	ListClientGrants(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter ClientGrantFilter) ([]ClientGrant, error)
	// ExpireClientGrants revokes up to limit grants past their expiry
	// (GrantExpired, actor system) and reports how many.
	ExpireClientGrants(ctx context.Context, limit int) (int, error)
	// PruneConsents deletes up to limit revoked consents and grants revoked
	// before cutoff and reports how many.
	PruneConsents(ctx context.Context, cutoff time.Time, limit int) (int, error)
}

// ClientGrantTarget is what granting a client scopes needs to know about
// the server.
type ClientGrantTarget struct {
	Permissions []string
	ConsentMode string
}
