// Package iamclient calls IAMKit's management API using an operator credential.
// Management credentials must only be stored on trusted servers, never browsers.
package iamclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	BaseURL string
	Key     string
	HTTP    *http.Client
}

// Do calls a management-relative path, for example /projects. End-user tokens
// are not interchangeable with Key. Caller controls context cancellation.
func (c Client) Do(ctx context.Context, method, path string, input, output any) error {
	if !strings.HasPrefix(c.Key, "ik_mgmt_") {
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
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+"/management/v1"+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	transport := c.HTTP
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
