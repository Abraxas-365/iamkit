package authclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// OAuthClient wraps the OAuth2 authorization code / PKCE flow endpoints.
type OAuthClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
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

// NewOAuth creates an OAuth2 client for the authorization code flow.
// clientSecret may be empty for public clients (PKCE).
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
		return fmt.Errorf("OAuth client ID required")
	}
	form.Set("client_id", c.clientID)
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth/"+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.clientSecret != "" {
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
