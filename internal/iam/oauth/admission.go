package oauth

import (
	"context"
	"net/url"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Admission management (phase b, W2): what IT does with the clients of
// metadata documents a protected resource sees, the allowlist that admits
// them without review, and the presets that fill it (or create a fixed
// client) in one click. All of it reuses iam:protected-resources:read/write.

// Audited actions of admission management (event.Classify maps them; the
// target is the client or allowlist entry id).
const (
	ActionClientApprove   = "oauth_client.approve"
	ActionClientBlock     = "oauth_client.block"
	ActionClientUnblock   = "oauth_client.unblock"
	ActionClientForget    = "oauth_client.forget"
	ActionAllowlistCreate = "oauth_client_allowlist.create"
	ActionAllowlistDelete = "oauth_client_allowlist.delete"
)

// Codes of the refusals a hosted page explains (errx codes; the details
// they carry are never serialized to API clients).
const (
	CodeClientPending        = "CLIENT_ADMISSION_PENDING"
	CodeClientBacklog        = "CLIENT_ADMISSION_BACKLOG"
	CodeClientBlocked        = "CLIENT_BLOCKED"
	CodeClientRegisteredOnly = "CLIENT_REGISTERED_ONLY"
	CodeClientDisabled       = "CLIENT_METADATA_DISABLED"
)

// Why an approved external client went back to pending without anyone
// blocking it (oauth_client.demoted, data.reason).
const (
	// DemotionDocumentsOff: the protected resource stopped taking clients
	// named by a metadata document (allow_client_metadata off). Every
	// approval goes, manual ones included.
	DemotionDocumentsOff = "metadata_documents_disabled"
	// DemotionFeatureOff: the client_metadata_documents feature is off in
	// the environment. Every approval goes, manual ones included.
	DemotionFeatureOff = "feature_disabled"
	// DemotionPolicyEnded: the allowlist entry, preset or open mode that
	// admitted the client no longer does. Manual approvals stay.
	DemotionPolicyEnded = "admission_policy_ended"
)

// IsClientRefusal reports whether err refuses an external client in a way a
// hosted page explains (waiting for IT, blocked, backlog, request limit, registered
// clients only, documents disabled).
func IsClientRefusal(err error) bool {
	var e *errx.Error
	if !errx.As(err, &e) || e == nil {
		return false
	}
	switch e.Code {
	case CodeClientPending, CodeClientBacklog, CodeClientRequestLimit, CodeClientBlocked, CodeClientRegisteredOnly, CodeClientDisabled:
		return true
	}
	return false
}

// ErrClientBlocked refuses an external client IT blocked.
func ErrClientBlocked() *errx.Error {
	e := errx.Forbidden("IT blocked this application for this server")
	e.Code = CodeClientBlocked
	return e
}

// ErrClientRegisteredOnly refuses a client_id URL at a server that takes
// registered clients only.
func ErrClientRegisteredOnly() *errx.Error {
	e := errx.Forbidden("this server accepts registered clients only")
	e.Code = CodeClientRegisteredOnly
	return e
}

// ErrClientDisabled refuses a client_id URL in an environment that does not
// accept clients identified by a metadata document.
func ErrClientDisabled() *errx.Error {
	e := errx.Forbidden("this environment does not accept clients identified by a metadata document")
	e.Code = CodeClientDisabled
	return e
}

// WithClient adds to a refusal what its page shows: the client_id URL, the
// document's name and logo and the environment (for its branding). Details
// of an error are not public, so API clients never see them.
func WithClient(err error, environment identity.EnvironmentID, clientID, name, logo string) error {
	var e *errx.Error
	if !errx.As(err, &e) || e == nil {
		return err
	}
	e.Details = map[string]interface{}{"environment_id": environment.String(), "client_id": clientID, "client_name": name, "logo_uri": logo}
	return e
}

// Refused adds to a refusal of client what its page shows (WithClient),
// unless it already carries it; any other error is returned as is.
func Refused(err error, c *Client) error {
	var e *errx.Error
	if c == nil || !IsClientRefusal(err) || !errx.As(err, &e) || e == nil {
		return err
	}
	if _, named := e.Details["client_id"]; named {
		return err
	}
	return WithClient(err, c.Environment, c.ExternalID, c.Name, c.LogoURI)
}

// ClientHost is the host a client_id URL names ("" for anything else): the
// one thing about an external client IAMKit can vouch for.
func ClientHost(clientID string) string {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" {
		return ""
	}
	return u.Host
}

// LogoShown is logo when it may be displayed next to clientID: https on the
// client_id's own host (a document cannot make IAMKit show, or fetch, an
// image from elsewhere; IAMKit proxies nothing).
func LogoShown(clientID, logo string) string {
	u, err := url.Parse(logo)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Host != ClientHost(clientID) {
		return ""
	}
	return logo
}

// AccessRequestView is a user who asked for an external client.
type AccessRequestView struct {
	User        identity.UserID `json:"user_id" db:"user_id"`
	Email       string          `json:"email" db:"email"`
	Name        string          `json:"name" db:"name"`
	RequestedAt time.Time       `json:"requested_at" db:"requested_at"`
}

// PresetApply names a preset to apply. A metadata-document preset adds an
// allowlist entry (for Protected, or every server of the environment when
// nil); a template preset creates a client at Protected.
type PresetApply struct {
	Preset    string                        `json:"preset"`
	Protected *identity.ProtectedResourceID `json:"protected_resource_id"`
}

// Validate requires a preset.
func (a PresetApply) Validate() error {
	if a.Preset == "" {
		return errx.Validation("preset is required")
	}
	return nil
}

// PresetView is a catalog entry with what to tell the operator.
type PresetView struct {
	Preset
	Warnings []string `json:"warnings"`
}

// TemplateClient is the registered public client a template preset made.
type TemplateClient struct {
	// ClientID is the value to give the client (its uuid).
	ClientID        identity.ClientID `json:"client_id"`
	RedirectURIs    []string          `json:"redirect_uris"`
	LoopbackAnyPort bool              `json:"loopback_any_port"`
	// Created is false when the preset had made the client already.
	Created bool `json:"created"`
}

// PresetResult is what applying a preset did: an allowlist entry or a
// client, with the exposure warnings of the preset.
type PresetResult struct {
	Preset    string          `json:"preset"`
	Name      string          `json:"name"`
	Mechanism string          `json:"mechanism"`
	Network   string          `json:"network"`
	Warnings  []string        `json:"warnings"`
	Allowlist *AllowlistEntry `json:"allowlist_entry"`
	Client    *TemplateClient `json:"client"`
}

// TemplateRegistration is the registered client a template preset stands
// for: public, no secret, hosted sign-in, authorization code + refresh,
// the preset's known redirect URIs.
func TemplateRegistration(p Preset, application identity.ApplicationID, resource identity.ResourceID) Registration {
	r := Registration{Application: application, Resource: resource, Redirects: append([]string{}, p.Redirects...), Public: true, HostedLogin: true,
		AccessTokenFormat: TokenFormatJWT, Preset: p.Key, LoopbackAnyPort: p.LoopbackAnyPort}
	r.ClientAuth = r.ClientAuth.WithDefaults(true)
	return r
}

// AdmissionCommands are what IT does with external clients, the allowlist
// and the presets of a protected resource.
type AdmissionCommands interface {
	// ApproveClient approves the client (from any state), optionally until
	// input.ExpiresAt; the approval vouches for the document's current
	// redirect URIs, jwks_uri and authentication method.
	ApproveClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID, input Approval) error
	// BlockClient refuses the client from now on and ends its grants and
	// sessions in the same transaction.
	BlockClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error
	// UnblockClient returns a blocked client to pending.
	UnblockClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error
	// ForgetClient deletes the client with its grants and sessions; it is
	// discovered afresh (pending unless policy approves it) if it asks again.
	ForgetClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error
	CreateAllowlistEntry(ctx context.Context, m Mutation, input AllowlistCreate) (AllowlistEntry, error)
	DeleteAllowlistEntry(ctx context.Context, m Mutation, entry identity.AllowlistEntryID) error
	// ApplyPreset adds the allowlist entry of a metadata-document preset or
	// creates the client of a template preset.
	ApplyPreset(ctx context.Context, m Mutation, input PresetApply) (PresetResult, error)
	// CreateClientTemplate creates (or returns) the registered client of a
	// template preset at the protected resource.
	CreateClientTemplate(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, input PresetApply) (PresetResult, error)
	// ExpireApprovals is the client_admission_expire job: approvals past
	// their expiry return to pending and lose their grants. more is true
	// when a full batch was processed.
	ExpireApprovals(ctx context.Context) (more bool, err error)
	// ReconcileDocuments is the client_documents_reconcile job: in every
	// environment where the client_metadata_documents feature is off, the
	// approved external clients return to pending and lose their grants
	// (DemotionFeatureOff). The feature is another module's setting, so
	// this follows it; the check at use (Client.Disabled) is immediate.
	ReconcileDocuments(ctx context.Context) (more bool, err error)
}

// AdmissionQueries are the reads of the same.
type AdmissionQueries interface {
	ListExternalClients(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter ExternalClientFilter, page query.Pagination) (query.Paginated[ExternalClientView], error)
	FindExternalClient(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (ExternalClientView, error)
	ListAccessRequests(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID, page query.Pagination) (query.Paginated[AccessRequestView], error)
	// ExternalClientImpact counts what blocking or forgetting the client
	// would end (live sessions, their people).
	ExternalClientImpact(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (ExternalClientImpact, error)
	// ListAllowlist lists the environment's entries; protected, when set,
	// narrows them to those that apply to that server.
	ListAllowlist(ctx context.Context, environment identity.EnvironmentID, protected *identity.ProtectedResourceID, page query.Pagination) (query.Paginated[AllowlistEntry], error)
	// ListPresets is the catalog the environment is offered (development
	// presets need the development_clients feature).
	ListPresets(ctx context.Context, environment identity.EnvironmentID) ([]PresetView, error)
}

// AdmissionRepository persists the same; the service decides, it stores.
type AdmissionRepository interface {
	FindProtectedResource(ctx context.Context, environment identity.EnvironmentID, id identity.ProtectedResourceID) (ProtectedResource, error)
	ListExternalClients(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter ExternalClientFilter, page query.Pagination) (query.Paginated[ExternalClientView], error)
	FindExternalClient(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (ExternalClientView, error)
	ListAccessRequests(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID, page query.Pagination) (query.Paginated[AccessRequestView], error)
	ExternalClientImpact(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (ExternalClientImpact, error)
	ApproveClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID, input Approval) error
	// BlockClient, UnblockClient and ForgetClient write their audit event
	// in the same transaction as the change and the revocation.
	BlockClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error
	UnblockClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error
	ForgetClient(ctx context.Context, m Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error
	// ExpireApprovals returns up to limit approvals past their expiry to
	// pending, revoking their grants, and reports how many.
	ExpireApprovals(ctx context.Context, limit int) (int, error)
	// ApprovedEnvironments lists the environments that hold approved
	// external clients; DemoteDocuments returns up to limit of an
	// environment's to pending (DemotionFeatureOff) and reports how many.
	ApprovedEnvironments(ctx context.Context) ([]identity.EnvironmentID, error)
	DemoteDocuments(ctx context.Context, environment identity.EnvironmentID, limit int) (int, error)
	ListAllowlist(ctx context.Context, environment identity.EnvironmentID, protected *identity.ProtectedResourceID, page query.Pagination) (query.Paginated[AllowlistEntry], error)
	FindAllowlistEntry(ctx context.Context, environment identity.EnvironmentID, entry identity.AllowlistEntryID) (AllowlistEntry, error)
	// CreateAllowlistEntry stores a resolved entry and approves the pending
	// clients it matches.
	CreateAllowlistEntry(ctx context.Context, m Mutation, entry identity.AllowlistEntryID, input AllowlistCreate) error
	DeleteAllowlistEntry(ctx context.Context, m Mutation, entry identity.AllowlistEntryID) error
	// CreateTemplateClient stores the template's client, or returns the
	// one the preset made before (created false).
	CreateTemplateClient(ctx context.Context, m Mutation, id identity.ClientID, input Registration) (identity.ClientID, bool, error)
}
