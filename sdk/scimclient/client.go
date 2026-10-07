// Package scimclient provisions organization memberships and groups using
// scoped credentials (SCIM 2.0, RFC 7643/7644).
//
//	client := scimclient.New("http://localhost:8080", "ik_scim_...")
//	user, err := client.Create(ctx, scimclient.User{...})
//	group, err := client.CreateGroup(ctx, scimclient.Group{DisplayName: "Engineering"})
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

// Email is a SCIM emails[] element. The primary address is userName; other
// entries are stored as aliases.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Name is the SCIM name attribute; displayName wins when both are sent.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// PhoneNumber is a SCIM phoneNumbers[] element. Only the type "mobile"
// number is stored, and only when the connection maps phones.
type PhoneNumber struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta is the read-only resource metadata.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

type User struct {
	Schemas      []string      `json:"schemas,omitempty"`
	ID           string        `json:"id,omitempty"`
	ExternalID   string        `json:"externalId,omitempty"`
	UserName     string        `json:"userName"`
	DisplayName  string        `json:"displayName"`
	Name         *Name         `json:"name,omitempty"`
	Active       *bool         `json:"active,omitempty"`
	Emails       []Email       `json:"emails,omitempty"`
	PhoneNumbers []PhoneNumber `json:"phoneNumbers,omitempty"`
	Enterprise   *Enterprise   `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta         *Meta         `json:"meta,omitempty"`
}

// List is a page of users (ListResponse).
type List = ListResponse[User]

// ListResponse is a SCIM ListResponse; StartIndex is 1-based.
type ListResponse[T any] struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
	Resources    []T `json:"Resources"`
}

const patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

// Operation is one PatchOp operation: op "add", "remove" or "replace".
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
	if !safeID(id) {
		return "", fmt.Errorf("invalid user ID")
	}
	return "/Users/" + id, nil
}

func safeID(id string) bool {
	return id != "" && !strings.ContainsAny(id, "/\\?#.%")
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

// List queries users with a SCIM filter (`attribute eq "value"`; "" for
// all). start is 1-based; count 0 uses the server's page size.
func (c *Client) List(ctx context.Context, filter string, start, count int) (List, error) {
	var out List
	err := c.request(ctx, "GET", "/Users"+listQuery(filter, start, count, nil), nil, &out)
	return out, err
}

func listQuery(filter string, start, count int, extra url.Values) string {
	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	if filter != "" {
		q.Set("filter", filter)
	}
	if start > 0 {
		q.Set("startIndex", strconv.Itoa(start))
	}
	if count > 0 {
		q.Set("count", strconv.Itoa(count))
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
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
	err = c.request(ctx, "PATCH", path, map[string]any{"schemas": []string{patchSchema}, "Operations": operations}, &out)
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
