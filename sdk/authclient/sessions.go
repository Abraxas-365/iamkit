package authclient

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// Session is one of the user's live sessions (see ListSessions).
type Session struct {
	ID string `json:"id"`
	// Current marks the session of the token that asked.
	Current      bool `json:"current"`
	Organization struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"organization"`
	Application struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"application"`
	// OAuthClientID is the OAuth client the session was opened through (nil: none).
	OAuthClientID   *string   `json:"oauth_client_id"`
	CreatedAt       time.Time `json:"created_at"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	AMR             []string  `json:"amr"`
	// IPAddress and UserAgent are where the session was opened from (nil when unknown).
	IPAddress *string `json:"ip_address"`
	UserAgent *string `json:"user_agent"`
	// Impersonated sessions were opened by an operator or service account.
	Impersonated bool `json:"impersonated"`
}

// Sessions is one page of the user's sessions.
type Sessions struct {
	Items []Session `json:"items"`
	Page  struct {
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	} `json:"page"`
}

func sessionQuery(environment, audience string) string {
	return "environment_id=" + url.QueryEscape(environment) + "&audience=" + url.QueryEscape(audience)
}

// ListSessions returns the user's live sessions across organizations and
// applications, newest first (limit 0 = the server default). Sessions
// opened by token exchange are not listed: they end with their parent.
func (c *Client) ListSessions(ctx context.Context, token, environment, audience string, limit, offset int) (Sessions, error) {
	var out Sessions
	q := "?" + sessionQuery(environment, audience)
	if limit > 0 {
		q += "&limit=" + strconv.Itoa(limit)
	}
	if offset > 0 {
		q += "&offset=" + strconv.Itoa(offset)
	}
	err := c.requestMethod(ctx, "GET", "/me/sessions"+q, token, nil, &out)
	return out, err
}

// RevokeSession ends one of the user's sessions (the current one too);
// another user's or an unknown id is a 404 error, an impersonated token a 403.
func (c *Client) RevokeSession(ctx context.Context, token, environment, audience, session string) error {
	return c.requestMethod(ctx, "DELETE", "/me/sessions/"+url.PathEscape(session)+"?"+sessionQuery(environment, audience), token, nil, nil)
}

// RevokeOtherSessions ends every session of the user but the token's own
// and returns how many ended.
func (c *Client) RevokeOtherSessions(ctx context.Context, token, environment, audience string) (int, error) {
	var out struct {
		Count int `json:"count"`
	}
	err := c.requestMethod(ctx, "POST", "/me/sessions/revoke-others?"+sessionQuery(environment, audience), token, nil, &out)
	return out.Count, err
}
