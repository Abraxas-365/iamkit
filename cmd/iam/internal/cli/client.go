package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// client wraps the management API. Zero imports from internal/iam/*.
type client struct {
	base string
	key  string
	http *http.Client
}

// resolve returns the effective value for a setting using the resolution order:
// flag > env var > config file value.
func resolve(flag, envVar, configVal string) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return configVal
}

func newClient() (*client, error) {
	profileName := flagProfile
	if profileName == "" {
		profileName = os.Getenv("IAMKIT_PROFILE")
	}
	if profileName == "" {
		profileName = "default"
	}

	p := loadProfile(profileName)

	u := resolve(flagURL, "IAMKIT_URL", p.URL)
	if u == "" {
		return nil, fmt.Errorf("no URL configured. Run \"iam configure\" or set IAMKIT_URL")
	}
	k := resolve(flagKey, "IAMKIT_KEY", p.Key)
	if k == "" {
		return nil, fmt.Errorf("no API key configured. Run \"iam configure\" or set IAMKIT_KEY")
	}
	return &client{
		base: strings.TrimRight(u, "/") + "/management/v1",
		key:  k,
		http: http.DefaultClient,
	}, nil
}

func mustClient(cmd interface{ Name() string }) *client {
	c, err := newClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	return c
}

// envPath returns /environments/:id. Exits if no environment is configured.
func envPath() string {
	profileName := flagProfile
	if profileName == "" {
		profileName = os.Getenv("IAMKIT_PROFILE")
	}
	if profileName == "" {
		profileName = "default"
	}
	p := loadProfile(profileName)

	e := resolve(flagEnvironment, "IAMKIT_ENVIRONMENT", p.Environment)
	if e == "" {
		fmt.Fprintln(os.Stderr, "Error: no environment configured. Set --environment, IAMKIT_ENVIRONMENT, or run \"iam configure\"")
		os.Exit(1)
	}
	return "/environments/" + e
}

// apiError is the JSON error shape returned by the server.
type apiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (e apiError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("%s: %s", e.Type, e.Message)
	}
	return e.Message
}

// do executes an HTTP request against the management API.
func (c *client) do(method, path string, body any) (json.RawMessage, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.base+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var ae apiError
		if json.Unmarshal(raw, &ae) == nil && ae.Message != "" {
			return nil, &ae
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(raw))
	}

	// 204 No Content
	if len(raw) == 0 {
		return nil, nil
	}
	return json.RawMessage(raw), nil
}

// Convenience methods.
func (c *client) get(path string) (json.RawMessage, error) { return c.do("GET", path, nil) }
func (c *client) post(path string, body any) (json.RawMessage, error) {
	return c.do("POST", path, body)
}
func (c *client) put(path string, body any) (json.RawMessage, error) {
	return c.do("PUT", path, body)
}
func (c *client) patch(path string, body any) (json.RawMessage, error) {
	return c.do("PATCH", path, body)
}
func (c *client) delete(path string) (json.RawMessage, error) { return c.do("DELETE", path, nil) }

// listQuery builds ?limit=&offset=&search= query string.
func listQuery(limit, offset int, search string) string {
	params := url.Values{}
	if limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", limit))
	}
	if offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", offset))
	}
	if search != "" {
		params.Set("search", search)
	}
	if len(params) == 0 {
		return ""
	}
	return "?" + params.Encode()
}
