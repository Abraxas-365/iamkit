// Package iamclient calls IAMKit's management API using an operator credential.
// Management credentials must only be stored on trusted servers, never browsers.
//
//	client := iamclient.New("http://localhost:8080", "ik_mgmt_...",
//	    iamclient.WithHTTPClient(myClient),
//	)
//	env := client.Environment("env-uuid")
//	user, err := env.CreateUser(ctx, iamclient.CreateUser{...})
package iamclient

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

// Client calls IAMKit's management API. Use New to construct.
type Client struct {
	baseURL string
	key     string
	http    *http.Client
}

// Option configures the management client.
type Option func(*Client)

// WithHTTPClient overrides the default http.Client used for requests.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.http = c }
}

// New creates a management client. baseURL is the IAMKit server root (e.g.
// "http://localhost:8080") and key is an ik_mgmt_ credential.
func New(baseURL, key string, opts ...Option) *Client {
	c := &Client{baseURL: strings.TrimRight(baseURL, "/"), key: key}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Do calls a management-relative path, for example /projects. End-user tokens
// are not interchangeable with Key. Caller controls context cancellation.
func (c *Client) Do(ctx context.Context, method, path string, input, output any) error {
	if !strings.HasPrefix(c.key, "ik_mgmt_") {
		return fmt.Errorf("management credential required")
	}
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") {
		return fmt.Errorf("invalid management path")
	}
	var body bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&body).Encode(input); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/management/v1"+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	transport := c.http
	if transport == nil {
		transport = http.DefaultClient
	}
	// Do not forward management credentials through redirects.
	client := *transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var response struct {
			Error apierror.Error `json:"error"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&response); err == nil && response.Error.Code != "" {
			response.Error.HTTPStatus = resp.StatusCode
			return &response.Error
		}
		return &apierror.Error{Code: "HTTP_ERROR", Message: "IAMKit management request failed", HTTPStatus: resp.StatusCode}
	}
	if output == nil || resp.StatusCode == 204 {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(output)
}
