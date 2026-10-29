package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ExternalTarget is the protected resource an authorization request of a
// client_id URL names (its resource parameter): where the client is
// materialized and how it is admitted.
type ExternalTarget struct {
	Environment identity.EnvironmentID
	Protected   identity.ProtectedResourceID
	Application identity.ApplicationID
	Resource    identity.ResourceID
	// AllowClientMetadata is false when the server takes registered
	// clients only.
	AllowClientMetadata bool
	// ClientAdmission is ClientAdmissionAllowlist or ClientAdmissionOpen.
	ClientAdmission string
	// Allowlist are the entries of the environment that apply to this
	// server (its own and those for every server).
	Allowlist []AllowlistEntry
}

// Admission is the admission of a client seen at this server for the
// first time.
func (t ExternalTarget) Admission(clientID *url.URL) string {
	return InitialAdmission(t.ClientAdmission, t.Allowlist, clientID)
}

// Admission sources: who approved an external client (the
// oauth_clients.admission_source column; "" reads as manual).
const (
	SourceManual    = "manual"
	SourceAllowlist = "allowlist"
	SourceOpen      = "open"
	SourcePreset    = "preset"
)

// AdmissionSource is why InitialAdmission approves clientID: a preset's or
// an operator's allowlist entry, else an open server ("" when it does not).
func (t ExternalTarget) AdmissionSource(clientID *url.URL) string {
	for _, e := range t.Allowlist {
		if e.Matches(clientID) {
			if e.Preset != "" {
				return SourcePreset
			}
			return SourceAllowlist
		}
	}
	if t.ClientAdmission == ClientAdmissionOpen {
		return SourceOpen
	}
	return ""
}

// MetadataHash is the digest of what an approval vouches for: the redirect
// URIs (sorted), the jwks_uri and the token endpoint authentication method.
// A document that changes any of them is a different client to the IT that
// approved it (D23, review H2).
func MetadataHash(redirects []string, jwksURI, method string) string {
	sorted := slices.Clone(redirects)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n") + "\x00" + jwksURI + "\x00" + method))
	return hex.EncodeToString(sum[:])
}

// Hash is MetadataHash of the document.
func (e ExternalClient) Hash() string {
	return MetadataHash(e.Redirects, e.Auth.JWKSURI, e.Auth.Method)
}

// Fetch admits one network read of a document (nil: always): it returns an
// error, e.g. 429, when the environment read too many this minute. It is
// asked only for reads the cache could not answer.
type Fetch func(ctx context.Context) error

// MetadataDocuments reads Client ID Metadata Documents (adapter
// oauthcimd): the validated document at a client_id URL and when it was
// fetched (an earlier time when served from the cache). admit is asked
// before a network read, never for a cached answer.
type MetadataDocuments interface {
	Document(ctx context.Context, clientID *url.URL, admit Fetch) (ExternalClient, time.Time, error)
}

// Throttle counts events of a key in fixed windows (usage.Window).
type Throttle interface {
	Take(ctx context.Context, key string, max int64, window time.Duration) (bool, error)
}

// Features reads IAMKit's feature flags (feature.Queries).
type Features interface {
	Enabled(ctx context.Context, environment identity.EnvironmentID, name string) (bool, error)
}

// ExternalRepository persists the clients of metadata documents.
type ExternalRepository interface {
	// ExternalTarget is the active protected resource (of an active
	// application) whose URI is uri, a canonical resource URI.
	ExternalTarget(ctx context.Context, uri string) (ExternalTarget, error)
	// ExternalTargetByID is ExternalTarget of a protected resource by id.
	ExternalTargetByID(ctx context.Context, protected identity.ProtectedResourceID) (ExternalTarget, error)
	// ExternalClientID is the row of the (server, URL) pair, zero when
	// the pair was never persisted.
	ExternalClientID(ctx context.Context, protected identity.ProtectedResourceID, externalID string) (identity.ClientID, error)
	// FindExternal is the live client named by a metadata document with
	// this row id (found through its URL, a stored grant or a ticket);
	// FindActive never returns one (H-1).
	FindExternal(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (*Client, error)
	// UnsavedExternal is the client a document names at target when no row
	// exists (and policy does not approve it): pending, id zero, with the
	// document's fields and the resource's audience and TTLs. Nothing is
	// written.
	UnsavedExternal(ctx context.Context, target ExternalTarget, doc ExternalClient) (*Client, error)
	// SaveExternalClient materializes save.Document at save.Target: a new
	// (server, URL) pair is inserted as save.ID (event
	// oauth_client.discovered); a known one keeps its id and takes the
	// document's fields when save.Fetched is newer than the stored copy
	// (event oauth_client.updated when they changed; a manually approved
	// client whose redirect URIs, jwks_uri or authentication method changed
	// returns to pending). It returns the row's id.
	SaveExternalClient(ctx context.Context, save ExternalSave) (identity.ClientID, error)
	// RequestExternalAccess records that a signed-in user asked for a
	// client IT has not approved, in one transaction: the row of a pair
	// never persisted (access.ID, pending; refused with ErrAdmissionBacklog
	// when the environment already holds access.MaxPending pending
	// clients), the request (once per client and user and access.Interval)
	// and its event oauth_client.access_requested.
	RequestExternalAccess(ctx context.Context, access AccessRequest) error
	// TouchExternal sets last_used_at of an external client, at most once
	// per interval.
	TouchExternal(ctx context.Context, client identity.ClientID, interval time.Duration) error
	// PruneExternal deletes up to limit pending clients nobody used
	// (last_used_at never set) discovered before the given time.
	PruneExternal(ctx context.Context, before time.Time, limit int) (int, error)
	// GrantClient is the external client named clientID that holds the
	// live stored grant of kind ("code", "refresh" or "access") with the
	// given signature hash.
	GrantClient(ctx context.Context, clientID, kind, signatureHash string) (identity.EnvironmentID, identity.ClientID, error)
}

// ExternalSave is a document to materialize at a protected resource.
type ExternalSave struct {
	Target   ExternalTarget
	ID       identity.ClientID
	Document ExternalClient
	Fetched  time.Time
	// Admission and Source are those of a new row (Source: AdmissionSource).
	Admission string
	Source    string
}

// AccessRequest is a signed-in user asking for an external client.
type AccessRequest struct {
	Target ExternalTarget
	// ID is the row's id if the pair has none yet; Document and Fetched
	// create it, pending.
	ID           identity.ClientID
	Document     ExternalClient
	Fetched      time.Time
	User         identity.UserID
	Organization identity.OrganizationID
	MaxPending   int
	// MaxPerUser and MaxPerOrganization (0: no cap) bound the requests the
	// user, and the organization they ask from, keep for clients still
	// waiting, made within Interval (M-3).
	MaxPerUser         int
	MaxPerOrganization int
	Interval           time.Duration
}

// CodeDocumentUnavailable is the code of ErrDocumentUnavailable.
const CodeDocumentUnavailable = "CLIENT_DOCUMENT_UNAVAILABLE"

// ErrDocumentUnavailable is a document that could not be read for a reason
// that says nothing about it: the host did not answer or answered an error
// status (still a 422, as before). Only these failures, and a spent fetch
// budget, let an approved client's stored metadata stand in (M-4).
func ErrDocumentUnavailable(message string) error {
	e := errx.Validation(message)
	e.Code = CodeDocumentUnavailable
	return e
}

// CodeFetchBudget is the code of ErrFetchBudget.
const CodeFetchBudget = "CLIENT_METADATA_FETCH_BUDGET"

// ErrFetchBudget refuses a network read of a document: the environment, or
// the caller's address, read too many this minute.
func ErrFetchBudget() error {
	e := errx.TooManyRequests("too many client metadata documents requested; try again in a minute")
	e.Code = CodeFetchBudget
	return e
}

// CodeClientRequestLimit is the code of ErrAccessRequestLimit.
const CodeClientRequestLimit = "CLIENT_ACCESS_REQUEST_LIMIT"

// ErrAccessRequestLimit refuses a request for access: the user, or the
// organization they ask from, already has as many requests waiting for IT as
// they may (M-3). Nothing is persisted; it frees as IT answers them or the
// interval passes.
func ErrAccessRequestLimit() error {
	e := errx.TooManyRequests("too many of your requests for applications are waiting for approval; try again later")
	e.Code = CodeClientRequestLimit
	return e
}

// ErrAdmissionBacklog refuses a new request for access: the environment
// already holds as many clients waiting for IT as it keeps.
func ErrAdmissionBacklog() error {
	e := errx.TooManyRequests("too many applications are waiting for approval at this server; try again later")
	e.Code = "CLIENT_ADMISSION_BACKLOG"
	return e
}

// ErrAdmissionPending refuses to finish an authorization of an external
// client IT has not approved (or whose approval expired).
func ErrAdmissionPending() error {
	e := errx.Forbidden("IT has not approved this application for this server yet")
	e.Code = "CLIENT_ADMISSION_PENDING"
	return e
}

// AdmitRedirect lets the protocol engine accept a redirect URI that
// RedirectRegistered matched without an exact entry (a loopback URI on
// another port, RFC 8252 §7.3): fosite compares http://localhost exactly.
// Call it only after ValidateAuthorization accepted requested.
func (c *Client) AdmitRedirect(requested string) {
	if requested != "" && !slices.Contains(c.Redirects, requested) && c.RedirectRegistered(requested) {
		c.Redirects = append(slices.Clone(c.Redirects), requested)
		c.admitted = requested
	}
}
