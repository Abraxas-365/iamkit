package authclient

import (
	"context"
	"net/url"
	"time"
)

// ConnectedClient is how a connected app shows its client. Name is the
// client's own word; Host (the client_id URL's host) and VerifiedName (the
// preset that vouches for it) are the only facts IAMKit vouches for.
type ConnectedClient struct {
	// ID is the client's row id, used to disconnect it.
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	// Source is "registered", "cimd" or "dcr".
	Source       string `json:"source"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	LogoURI      string `json:"logo_uri"`
	Preset       string `json:"preset"`
	VerifiedName string `json:"verified_name"`
}

// ConnectedApp is a client that holds, or may get without asking, access
// to the user's account at one protected resource in one organization: a
// live consent, live sessions, or both (a first-party client has sessions
// only).
type ConnectedApp struct {
	Client ConnectedClient `json:"client"`
	// ProtectedResourceID is the server the client reaches; Resource its URI.
	ProtectedResourceID string `json:"protected_resource_id"`
	Resource            string `json:"resource"`
	ResourceName        string `json:"resource_name"`
	OrganizationID      string `json:"organization_id"`
	// Scopes are what the user consented to (empty for a first-party client).
	Scopes []string `json:"scopes"`
	// ConsentedAt is when the user first consented (nil: never asked).
	ConsentedAt *time.Time `json:"consented_at"`
	// ActiveSessions are the client's live sessions for the user there;
	// LastUsedAt the newest of their last refresh.
	ActiveSessions int        `json:"active_sessions"`
	LastUsedAt     *time.Time `json:"last_used_at"`
}

func connectedQuery(environment, audience, organization string) string {
	q := sessionQuery(environment, audience)
	if organization != "" {
		q += "&organization_id=" + url.QueryEscape(organization)
	}
	return q
}

// ListConnectedApps returns the apps connected to the user's account,
// across organizations or only organization (empty: all). Apps are
// clients with a live consent or sessions at a protected resource.
func (c *Client) ListConnectedApps(ctx context.Context, token, environment, audience, organization string) ([]ConnectedApp, error) {
	var out struct {
		Items []ConnectedApp `json:"items"`
	}
	err := c.requestMethod(ctx, "GET", "/me/connected-apps?"+connectedQuery(environment, audience, organization), token, nil, &out)
	if out.Items == nil {
		out.Items = []ConnectedApp{}
	}
	return out.Items, err
}

// DisconnectApp ends the user's connection to a client: their consents to
// it and its sessions for them, in organization (empty: all). client is
// ConnectedClient.ID. Another user's or an unknown client is a 404 error,
// an impersonated token a 403.
func (c *Client) DisconnectApp(ctx context.Context, token, environment, audience, client, organization string) error {
	return c.requestMethod(ctx, "DELETE", "/me/connected-apps/"+url.PathEscape(client)+"?"+connectedQuery(environment, audience, organization), token, nil, nil)
}
