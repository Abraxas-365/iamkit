package iamclient

import (
	"context"
	"net/url"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

// ConnectedApp is a client that holds, or may get without asking, access
// to a user's account at one protected resource in one organization.
type ConnectedApp = authclient.ConnectedApp

// ConnectedClient is how a connected app shows its client.
type ConnectedClient = authclient.ConnectedClient

// ClientGrant is scopes an administrator granted a client at a protected
// resource for every user of the environment (OrganizationID nil) or of
// one organization. It covers users only while the server is in
// ConsentModeAdminGranted; beyond it users still consent.
type ClientGrant struct {
	ID                  string     `json:"id"`
	ProtectedResourceID string     `json:"protected_resource_id"`
	ClientID            string     `json:"client_id"`
	OrganizationID      *string    `json:"organization_id"`
	Scopes              []string   `json:"scopes"`
	ExpiresAt           *time.Time `json:"expires_at"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	// RevokedAt and RevokedReason are set on revoked grants (see
	// ClientGrants with revoked true).
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
}

// ClientGrantInput grants a client scopes (GrantClient replaces the live
// grant of the same client and organization). Scopes are permissions of
// the protected resource's resource.
type ClientGrantInput struct {
	Scopes []string `json:"scopes"`
	// OrganizationID limits the grant to one organization (nil: every
	// user of the environment).
	OrganizationID *string `json:"organization_id,omitempty"`
	// ExpiresAt ends the grant (nil: until revoked).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ClientGrants lists the administrator grants of a client at a protected
// resource (client is ExternalClient.ID or OAuthClientView.ID); revoked
// true lists the revoked ones as well.
func (e Environment) ClientGrants(ctx context.Context, protectedResource, client string, revoked bool) ([]ClientGrant, error) {
	var out struct {
		Items []ClientGrant `json:"items"`
	}
	for _, part := range []string{protectedResource, client} {
		if err := safeSegment(part); err != nil {
			return nil, err
		}
	}
	var q url.Values
	if revoked {
		q = url.Values{"revoked": {"true"}}
	}
	if err := e.client.do(ctx, "GET", e.path("protected-resources/"+protectedResource+"/clients/"+client+"/grants"), q, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []ClientGrant{}, nil
	}
	return out.Items, nil
}

// GrantClient grants a client scopes at a protected resource for users
// without asking them (the server must be ConsentModeAdminGranted for it
// to cover users). It replaces the live grant of the same client and
// organization.
func (e Environment) GrantClient(ctx context.Context, protectedResource, client string, input ClientGrantInput) (ClientGrant, error) {
	var out ClientGrant
	err := e.operation(ctx, "PUT", []string{"protected-resources", protectedResource, "clients", client, "grants"}, input, &out)
	return out, err
}

// RevokeClientGrant revokes an administrator grant; the sessions it
// covered end.
func (e Environment) RevokeClientGrant(ctx context.Context, protectedResource, client, grant string) error {
	return e.operation(ctx, "DELETE", []string{"protected-resources", protectedResource, "clients", client, "grants", grant}, nil, nil)
}

// UserConnectedApps lists the apps connected to a user's account, in
// organization (empty: all of the user's organizations).
func (e Environment) UserConnectedApps(ctx context.Context, user, organization string) ([]ConnectedApp, error) {
	var out struct {
		Items []ConnectedApp `json:"items"`
	}
	if err := safeSegment(user); err != nil {
		return nil, err
	}
	var q url.Values
	if organization != "" {
		q = url.Values{"organization_id": {organization}}
	}
	if err := e.client.do(ctx, "GET", e.path("users/"+user+"/connected-apps"), q, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []ConnectedApp{}, nil
	}
	return out.Items, nil
}

// DisconnectUserApp ends a user's connection to a client (ConnectedClient.ID):
// their consents to it and its sessions for them, in organization (empty:
// all). Audited as oauth_consent.revoke.
func (e Environment) DisconnectUserApp(ctx context.Context, user, client, organization string) error {
	for _, part := range []string{user, client} {
		if err := safeSegment(part); err != nil {
			return err
		}
	}
	var q url.Values
	if organization != "" {
		q = url.Values{"organization_id": {organization}}
	}
	return e.client.do(ctx, "DELETE", e.path("users/"+user+"/connected-apps/"+client), q, nil, nil)
}
