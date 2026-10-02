package authclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/golang-jwt/jwt/v5"
)

// OAuthClient wraps the OAuth2 authorization code / PKCE flow endpoints.
type OAuthClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
	// secretPost sends the secret in the form (client_secret_post).
	secretPost bool
	// assertion signs RFC 7523 client assertions (private_key_jwt).
	assertion *assertionKey
}

type assertionKey struct {
	key    crypto.Signer
	kid    string
	method jwt.SigningMethod
}

// OAuthTokens extends TokenPair with OAuth-specific fields.
type OAuthTokens struct {
	TokenPair
	IDToken string `json:"id_token,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// OAuthError represents an OAuth2 error response.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	HTTPStatus  int    `json:"-"`
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

// OAuthOption configures the OAuth client.
type OAuthOption func(*OAuthClient)

// WithOAuthHTTPClient overrides the default http.Client for OAuth requests.
func WithOAuthHTTPClient(c *http.Client) OAuthOption {
	return func(cl *OAuthClient) { cl.http = c }
}

// WithClientSecretPost sends the client secret in the request body
// (token_endpoint_auth_method client_secret_post) instead of HTTP Basic.
func WithClientSecretPost() OAuthOption {
	return func(cl *OAuthClient) { cl.secretPost = true }
}

// WithPrivateKeyJWT authenticates with a JWT signed by key
// (token_endpoint_auth_method private_key_jwt, RFC 7523) instead of a
// secret. kid names the key in the client's registered key set; alg is
// the registered token_endpoint_auth_signing_alg (RS256, PS256, ES256, …).
func WithPrivateKeyJWT(key crypto.Signer, kid, alg string) OAuthOption {
	return func(cl *OAuthClient) {
		cl.assertion = &assertionKey{key: key, kid: kid, method: jwt.GetSigningMethod(alg)}
	}
}

// NewOAuth creates an OAuth2 client for the authorization code flow, or
// for a service account's client_credentials (clientID = account ID,
// clientSecret = its ik_svc_ secret). clientSecret may be empty for public
// clients (PKCE) and with WithPrivateKeyJWT.
func NewOAuth(baseURL, clientID, clientSecret string, opts ...OAuthOption) *OAuthClient {
	c := &OAuthClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// NewPKCE generates a PKCE code verifier and S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	var bytes [32]byte
	if _, err = rand.Read(bytes[:]); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(bytes[:])
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return
}

func (c *OAuthClient) request(ctx context.Context, path string, form url.Values, out any) error {
	if c.clientID == "" {
		return &apierror.Error{Code: "VALIDATION", Message: "OAuth client ID required", HTTPStatus: 400}
	}
	form.Set("client_id", c.clientID)
	basic := false
	switch {
	case c.assertion != nil && path != "introspect":
		signed, err := c.clientAssertion()
		if err != nil {
			return err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", signed)
	case c.clientSecret != "" && c.secretPost && path != "introspect":
		form.Set("client_secret", c.clientSecret)
	case c.clientSecret != "":
		basic = true
	}
	return c.send(ctx, path, form, basic, out)
}

// send posts form to /oauth/path (with HTTP Basic client authentication
// when basic) and decodes the answer into out.
func (c *OAuthClient) send(ctx context.Context, path string, form url.Values, basic bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth/"+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
	}
	transport := c.http
	if transport == nil {
		transport = http.DefaultClient
	}
	client := *transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		failure := &OAuthError{HTTPStatus: res.StatusCode}
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(failure)
		if failure.Code == "" {
			failure.Code = "http_error"
		}
		return failure
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

// clientAssertion is a one-minute RFC 7523 assertion for the token
// endpoint with a fresh jti (each is accepted once).
func (c *OAuthClient) clientAssertion() (string, error) {
	if c.assertion.method == nil {
		return "", &apierror.Error{Code: "VALIDATION", Message: "unsupported client assertion algorithm", HTTPStatus: 400}
	}
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", err
	}
	now := time.Now()
	token := jwt.NewWithClaims(c.assertion.method, jwt.RegisteredClaims{Issuer: c.clientID, Subject: c.clientID, Audience: jwt.ClaimStrings{c.baseURL + "/oauth/token"}, ID: base64.RawURLEncoding.EncodeToString(jti[:]), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))})
	token.Header["kid"] = c.assertion.kid
	return token.SignedString(c.assertion.key)
}

// ClientCredentials gets a service account's access token (grant
// client_credentials): the same token as Client.MachineToken.
func (c *OAuthClient) ClientCredentials(ctx context.Context) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "token", url.Values{"grant_type": {"client_credentials"}}, &out)
	return out, err
}

// Exchange trades an authorization code for tokens (the second leg of the auth code flow).
func (c *OAuthClient) Exchange(ctx context.Context, code, redirect, verifier string) (OAuthTokens, error) {
	var out OAuthTokens
	err := c.request(ctx, "token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}, &out)
	return out, err
}

// Refresh exchanges a refresh token for new tokens.
func (c *OAuthClient) Refresh(ctx context.Context, token string) (OAuthTokens, error) {
	var out OAuthTokens
	err := c.request(ctx, "token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}, &out)
	return out, err
}

// Revoke invalidates a token.
func (c *OAuthClient) Revoke(ctx context.Context, token string) error {
	return c.request(ctx, "revoke", url.Values{"token": {token}}, nil)
}

// UserInfo is the OpenID Connect UserInfo answer. Name needs the profile
// scope; Email and EmailVerified need the email scope.
type UserInfo struct {
	Subject        string `json:"sub"`
	Name           string `json:"name,omitempty"`
	Email          string `json:"email,omitempty"`
	EmailVerified  bool   `json:"email_verified,omitempty"`
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id,omitempty"`
}

// UserInfo reads the signed-in user's claims with an OAuth access token.
func (c *OAuthClient) UserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	var out UserInfo
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/oauth/userinfo", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	transport := c.http
	if transport == nil {
		transport = http.DefaultClient
	}
	res, err := transport.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		failure := &OAuthError{HTTPStatus: res.StatusCode}
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(failure)
		if failure.Code == "" {
			failure.Code = "http_error"
		}
		return out, failure
	}
	return out, json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out)
}

// Introspection is an RFC 7662 answer. Inactive tokens only set Active.
type Introspection struct {
	Active         bool     `json:"active"`
	Subject        string   `json:"sub,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	Scope          string   `json:"scope,omitempty"`
	TokenType      string   `json:"token_type,omitempty"`
	TokenUse       string   `json:"token_use,omitempty"`
	Audience       []string `json:"aud,omitempty"`
	Issuer         string   `json:"iss,omitempty"`
	ExpiresAt      int64    `json:"exp,omitempty"`
	IssuedAt       int64    `json:"iat,omitempty"`
	EnvironmentID  string   `json:"environment_id,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	SessionID      string   `json:"sid,omitempty"`
}

// Introspect asks whether an access or refresh token of this client's
// environment is active. Needs a confidential client (client secret).
func (c *OAuthClient) Introspect(ctx context.Context, token string) (Introspection, error) {
	var out Introspection
	if c.clientSecret == "" {
		return out, &OAuthError{Code: "invalid_client", Description: "introspection needs a confidential client", HTTPStatus: 401}
	}
	err := c.request(ctx, "introspect", url.Values{"token": {token}}, &out)
	return out, err
}

// EndSessionURL builds the RP-initiated logout URL to send the browser to.
// redirect must be one of the client's post_logout_redirect_uris (or empty
// for IAMKit's "Signed out" page); state is echoed back on the redirect.
func (c *OAuthClient) EndSessionURL(idTokenHint, redirect, state string) string {
	q := url.Values{}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if c.clientID != "" {
		q.Set("client_id", c.clientID)
	}
	if redirect != "" {
		q.Set("post_logout_redirect_uri", redirect)
	}
	if state != "" {
		q.Set("state", state)
	}
	return c.baseURL + "/oauth/end_session?" + q.Encode()
}
