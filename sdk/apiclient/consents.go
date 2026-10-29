package apiclient

import (
	"context"
	"net/url"
)

// UserConnectedApps lists the apps connected to a user's account, in
// organization (empty: all of the user's organizations); requires
// iam:users:read.
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
	if err := e.client.do(ctx, "GET", e.path("users", user, "connected-apps"), q, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []ConnectedApp{}, nil
	}
	return out.Items, nil
}

// DisconnectUserApp ends a user's connection to a client (ConnectedClient.ID):
// their consents to it and its sessions for them, in organization (empty:
// all); requires iam:users:write.
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
	return e.client.do(ctx, "DELETE", e.path("users", user, "connected-apps", client), q, nil, nil)
}
