// Package scimclient provisions organization memberships using scoped credentials.
//
//	client := scimclient.New("http://localhost:8080", "ik_scim_...")
//	user, err := client.Create(ctx, scimclient.User{...})
package scimclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

// Client calls IAMKit's SCIM 2.0 provisioning API.
type Client struct {
	baseURL string
	secret  string
	http    *http.Client
}

// Option configures the SCIM client.
type Option func(*Client)

// WithHTTPClient overrides the default http.Client.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.http = c }
}

// New creates a SCIM client. secret must be an ik_scim_ credential.
func New(baseURL, secret string, opts ...Option) *Client {
	c := &Client{baseURL: strings.TrimRight(baseURL, "/"), secret: secret}
	for _, o := range opts {
		o(c)
	}
	return c
}

type Enterprise struct {
	Manager struct {
		Value string `json:"value"`
	} `json:"manager"`
}

type User struct {
	Schemas     []string    `json:"schemas,omitempty"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Active      *bool       `json:"active,omitempty"`
	Enterprise  *Enterprise `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

type List struct {
	TotalResults int    `json:"totalResults"`
	StartIndex   int    `json:"startIndex"`
	ItemsPerPage int    `json:"itemsPerPage"`
	Resources    []User `json:"Resources"`
}

type Operation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value"`
}

func (c *Client) request(ctx context.Context, method, path string, input, output any) error {
	if !strings.HasPrefix(c.secret, "ik_scim_") {
		return fmt.Errorf("provisioning credential required")
	}
	var body bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&body).Encode(input); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/scim/v2"+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.secret)
	req.Header.Set("Content-Type", "application/scim+json")
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
		var failure struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&failure)
		return &apierror.Error{Code: "SCIM_ERROR", HTTPStatus: res.StatusCode, Message: failure.Detail}
	}
	if output == nil || res.StatusCode == 204 {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(output)
}

func userPath(id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/\\?#.%") {
		return "", fmt.Errorf("invalid user ID")
	}
	return "/Users/" + id, nil
}

// Create provisions a new user.
func (c *Client) Create(ctx context.Context, input User) (User, error) {
	var out User
	err := c.request(ctx, "POST", "/Users", input, &out)
	return out, err
}

// Get retrieves a user by ID.
func (c *Client) Get(ctx context.Context, id string) (User, error) {
	var out User
	path, err := userPath(id)
	if err != nil {
		return out, err
	}
	err = c.request(ctx, "GET", path, nil, &out)
	return out, err
}

// List queries users with a SCIM filter.
func (c *Client) List(ctx context.Context, filter string, start, count int) (List, error) {
	var out List
	q := url.Values{"filter": {filter}, "startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(count)}}
	err := c.request(ctx, "GET", "/Users?"+q.Encode(), nil, &out)
	return out, err
}

// Replace fully replaces a user.
func (c *Client) Replace(ctx context.Context, id string, input User) (User, error) {
	var out User
	path, err := userPath(id)
	if err != nil {
		return out, err
	}
	err = c.request(ctx, "PUT", path, input, &out)
	return out, err
}

// Patch applies partial updates to a user.
func (c *Client) Patch(ctx context.Context, id string, operations []Operation) (User, error) {
	var out User
	path, err := userPath(id)
	if err != nil {
		return out, err
	}
	err = c.request(ctx, "PATCH", path, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": operations}, &out)
	return out, err
}

// Delete removes a user.
func (c *Client) Delete(ctx context.Context, id string) error {
	path, err := userPath(id)
	if err != nil {
		return err
	}
	return c.request(ctx, "DELETE", path, nil, nil)
}
