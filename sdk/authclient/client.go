// Package authclient validates application access and provides identity
// endpoints for end-user authentication. Never use management credentials here.
//
//	client := authclient.New("http://localhost:8080",
//	    authclient.WithHTTPClient(myClient),
//	)
//	tokens, err := client.Login(ctx, authclient.PasswordLogin{...})
package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

// Client calls IAMKit's identity API (/identity/v1).
type Client struct {
	baseURL string
	http    *http.Client
}

// ClientOption configures the identity client.
type ClientOption func(*Client)

// WithHTTPClient overrides the default http.Client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) { cl.http = c }
}

// New creates an identity client. baseURL is the IAMKit server root
// (e.g. "http://localhost:8080").
func New(baseURL string, opts ...ClientOption) *Client {
	c := &Client{baseURL: strings.TrimRight(baseURL, "/")}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ── Shared types ──

type LoginContext struct {
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
}

type PasswordLogin struct {
	LoginContext
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type Challenge struct {
	ID        string `json:"challenge_id"`
	Message   string `json:"message"`
	ExpiresIn int    `json:"expires_in"`
}

type ChallengeVerification struct {
	LoginContext
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	Purpose     string `json:"purpose"`
	Password    string `json:"password,omitempty"`
}

type FederationStart struct {
	LoginContext
	ConnectionID string `json:"connection_id"`
}

type FederationResult struct {
	AuthorizationURL string `json:"authorization_url"`
}

type AddMemberRequest struct {
	EnvironmentID string `json:"environment_id"`
	Audience      string `json:"audience"`
	UserID        string `json:"user_id"`
}

// ── Internal HTTP helpers ──

func (c *Client) request(ctx context.Context, path, token string, input, output any) error {
	return c.requestMethod(ctx, "POST", path, token, input, output)
}

func (c *Client) requestMethod(ctx context.Context, method, path, token string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/identity/v1"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
		var envelope struct {
			Error apierror.Error `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&envelope) == nil && envelope.Error.Code != "" {
			envelope.Error.HTTPStatus = res.StatusCode
			return &envelope.Error
		}
		return &apierror.Error{Code: "HTTP_ERROR", Message: "identity request failed", HTTPStatus: res.StatusCode}
	}
	if output == nil || res.StatusCode == 204 {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(output)
}

// ── Authentication ──

// Login authenticates a user with email and password, returning access/refresh tokens.
func (c *Client) Login(ctx context.Context, input PasswordLogin) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/login", "", input, &out)
	return out, err
}

// Refresh exchanges a refresh token for a new token pair.
func (c *Client) Refresh(ctx context.Context, boundary LoginContext, refresh string) (TokenPair, error) {
	var out TokenPair
	input := struct {
		LoginContext
		Token string `json:"refresh_token"`
	}{boundary, refresh}
	err := c.request(ctx, "/refresh", "", input, &out)
	return out, err
}

// MachineToken exchanges a service account credential (ik_svc_) for access tokens.
func (c *Client) MachineToken(ctx context.Context, secret string) (TokenPair, error) {
	if !strings.HasPrefix(secret, "ik_svc_") {
		return TokenPair{}, fmt.Errorf("service credential required")
	}
	var out TokenPair
	err := c.request(ctx, "/machine-token", secret, nil, &out)
	return out, err
}

// ── Challenges (OTP / email verification) ──

// InitiateChallenge starts an email-based challenge (login, registration, etc.).
func (c *Client) InitiateChallenge(ctx context.Context, environment, email, purpose string) (Challenge, error) {
	var out Challenge
	err := c.request(ctx, "/challenges", "", map[string]string{"environment_id": environment, "email": email, "purpose": purpose}, &out)
	return out, err
}

// VerifyChallenge completes a challenge by providing the verification code.
func (c *Client) VerifyChallenge(ctx context.Context, input ChallengeVerification) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/challenges/verify", "", input, &out)
	return out, err
}

// ── Federation (SSO) ──

// StartFederation initiates an SSO login flow, returning the IdP authorization URL.
// The user's browser should be redirected to the returned URL.
func (c *Client) StartFederation(ctx context.Context, input FederationStart) (FederationResult, error) {
	var out FederationResult
	err := c.request(ctx, "/federation/start", "", input, &out)
	return out, err
}

// ── Session management ──

// Logout invalidates the user's session.
func (c *Client) Logout(ctx context.Context, token, environment, audience string) error {
	return c.request(ctx, "/logout", token, map[string]string{"environment_id": environment, "audience": audience}, nil)
}

// ── Profile ──

// Profile returns the authenticated user's profile.
func (c *Client) Profile(ctx context.Context, token, environment, audience string) (Profile, error) {
	var out Profile
	q := "?environment_id=" + environment + "&audience=" + audience
	err := c.requestMethod(ctx, "GET", "/me"+q, token, nil, &out)
	return out, err
}

// UpdateProfile changes the authenticated user's display name.
func (c *Client) UpdateProfile(ctx context.Context, token, environment, audience, name string) error {
	return c.requestMethod(ctx, "PATCH", "/me", token, map[string]string{"environment_id": environment, "audience": audience, "name": name}, nil)
}

// Organizations returns the organizations the authenticated user belongs to.
func (c *Client) Organizations(ctx context.Context, token, environment, audience string) ([]Organization, error) {
	var out []Organization
	q := "?environment_id=" + environment + "&audience=" + audience
	err := c.requestMethod(ctx, "GET", "/organizations"+q, token, nil, &out)
	return out, err
}

// ── Membership ──

// AddMember adds a user to an organization (self-service). Requires a valid access token.
func (c *Client) AddMember(ctx context.Context, token string, input AddMemberRequest) error {
	return c.request(ctx, "/memberships", token, input, nil)
}

// ── Token introspection ──

// Introspect validates a token against the server, checking revocation status
// and enforcing the given trust boundaries.
func (c *Client) Introspect(ctx context.Context, token, issuer, audience, environment, application, resource string) (*Claims, error) {
	if issuer == "" || audience == "" || environment == "" || application == "" || resource == "" {
		return nil, fmt.Errorf("expected boundaries required")
	}
	var out struct {
		Active bool   `json:"active"`
		Claims Claims `json:"claims"`
	}
	if err := c.request(ctx, "/introspect", token, map[string]string{"environment_id": environment, "audience": audience}, &out); err != nil {
		return nil, err
	}
	p := out.Claims
	hasAudience := false
	for _, v := range p.Audience {
		if v == audience {
			hasAudience = true
		}
	}
	if !out.Active || p.Issuer != issuer || !hasAudience || p.EnvironmentID != environment || p.ApplicationID != application || p.ResourceID != resource || p.Subject == "" {
		return nil, fmt.Errorf("inactive token or boundary mismatch")
	}
	if p.Purpose != "application" && p.Purpose != "machine" {
		return nil, fmt.Errorf("invalid purpose")
	}
	return &p, nil
}
