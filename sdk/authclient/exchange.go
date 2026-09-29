package authclient

import (
	"context"
	"net/url"
	"strings"
)

// Token exchange (RFC 8693) at /oauth/token.
const (
	// TokenExchangeGrantType goes in an OAuth client's grant_types.
	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// AccessTokenType is the subject type of ExchangeToken and the type of
	// every issued token.
	AccessTokenType = "urn:ietf:params:oauth:token-type:access_token"
	// UserIDTokenType is the subject type of Impersonate.
	UserIDTokenType = "urn:iamkit:params:oauth:token-type:user_id"
)

// ExchangedToken is the answer of a token exchange: an access token only
// (no refresh or ID token).
type ExchangedToken struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// ExchangeToken turns a user's access token into one for another resource
// (audience) of the same application, keeping the user, organization and
// sign-in. The client must be confidential with TokenExchangeGrantType in
// its grant_types. permissions, when given, narrow the new token to some of
// the user's permissions on that resource. The new token ends with the
// original session.
func (c *OAuthClient) ExchangeToken(ctx context.Context, subjectToken, audience string, permissions ...string) (ExchangedToken, error) {
	form := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {subjectToken}, "subject_token_type": {AccessTokenType}, "audience": {audience}}
	if len(permissions) > 0 {
		form.Set("scope", strings.Join(permissions, " "))
	}
	var out ExchangedToken
	err := c.request(ctx, "token", form, &out)
	return out, err
}

// Impersonate gets the access token of user in organization for a service
// account an owner allowed to impersonate (NewOAuth with the account ID
// and secret, or WithPrivateKeyJWT). reason (at least 10 characters) is
// kept on the session and audited; the token's act claim names the
// account.
func (c *OAuthClient) Impersonate(ctx context.Context, user, organization, reason string) (ExchangedToken, error) {
	form := url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {user}, "subject_token_type": {UserIDTokenType}, "organization_id": {organization}, "reason": {reason}}
	var out ExchangedToken
	err := c.request(ctx, "token", form, &out)
	return out, err
}
