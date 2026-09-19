// Package apiclient calls IAMKit's permission-scoped API (/api/v1/*) using a
// JWT obtained from authclient.MachineToken or a user login. The JWT carries
// fine-grained iam:* permissions and is sent as Authorization: Bearer.
//
//	tokens, _ := auth.MachineToken(ctx, "ik_svc_...")
//	client := apiclient.New("http://localhost:8080", tokens.AccessToken)
//	env := client.Environment("env-uuid")
//	users, err := env.Users(ctx)
package apiclient

import (
	"context"
	"net/http"
	"strings"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/Abraxas-365/iamkit/sdk/internal/transport"
)

// Client calls IAMKit's API routes. Use New to construct.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// Option configures the API client.
type Option func(*Client)

// WithHTTPClient overrides the default http.Client used for requests.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.http = c }
}

// New creates an API client. baseURL is the IAMKit server root (e.g.
// "http://localhost:8080") and token is a JWT from MachineToken or user login.
func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SetToken replaces the JWT used for subsequent requests. Useful when
// refreshing an expired token without constructing a new client.
func (c *Client) SetToken(token string) { c.token = token }

// Do calls an API-relative path, for example /environments/<id>/users.
func (c *Client) Do(ctx context.Context, method, path string, input, output any) error {
	if c.token == "" {
		return &apierror.Error{Code: "UNAUTHORIZED", Message: "bearer token required", HTTPStatus: 401}
	}
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") {
		return &apierror.Error{Code: "VALIDATION", Message: "invalid API path", HTTPStatus: 400}
	}
	return transport.Do(c.http, ctx, method, c.baseURL+"/api/v1"+path, []transport.Header{
		{Key: "Authorization", Value: "Bearer " + c.token},
	}, input, output)
}

// Environment returns a handle scoped to the given environment ID.
func (c *Client) Environment(id string) Environment {
	return Environment{client: c, id: id}
}
