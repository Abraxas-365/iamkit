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

type OAuthClient struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}
type OAuthTokens struct {
	TokenPair
	IDToken string `json:"id_token,omitempty"`
	Scope   string `json:"scope,omitempty"`
}
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	HTTPStatus  int    `json:"-"`
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }
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
func (c OAuthClient) request(ctx context.Context, path string, form url.Values, out any) error {
	if c.ClientID == "" {
		return fmt.Errorf("OAuth client ID required")
	}
	form.Set("client_id", c.ClientID)
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.BaseURL, "/")+"/oauth/"+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	transport := c.HTTP
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
func (c OAuthClient) Exchange(ctx context.Context, code, redirect, verifier string) (OAuthTokens, error) {
	var out OAuthTokens
	err := c.request(ctx, "token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}, &out)
	return out, err
}
func (c OAuthClient) Refresh(ctx context.Context, token string) (OAuthTokens, error) {
	var out OAuthTokens
	err := c.request(ctx, "token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}, &out)
	return out, err
}
func (c OAuthClient) Revoke(ctx context.Context, token string) error {
	return c.request(ctx, "revoke", url.Values{"token": {token}}, nil)
}
