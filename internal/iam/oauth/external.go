package oauth

import (
	"context"
	"net/url"
	"slices"
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

// MetadataDocuments reads Client ID Metadata Documents (adapter
// oauthcimd): the validated document at a client_id URL and when it was
// fetched (an earlier time when served from the cache).
type MetadataDocuments interface {
	Document(ctx context.Context, clientID *url.URL) (ExternalClient, time.Time, error)
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
	// SaveExternalClient materializes doc at target: a new (server, URL)
	// pair is inserted as id with admission (event oauth_client.discovered);
	// a known one keeps its id and admission and takes the document's
	// fields when fetched is newer than the stored copy (event
	// oauth_client.updated when they changed). It returns the row's id.
	SaveExternalClient(ctx context.Context, target ExternalTarget, id identity.ClientID, doc ExternalClient, fetched time.Time, admission string) (identity.ClientID, error)
	// GrantClient is the external client named clientID that holds the
	// live stored grant of kind ("code", "refresh" or "access") with the
	// given signature hash.
	GrantClient(ctx context.Context, clientID, kind, signatureHash string) (identity.EnvironmentID, identity.ClientID, error)
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
	}
}
