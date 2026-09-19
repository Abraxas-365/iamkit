// Package transport provides a shared HTTP round-trip helper for SDK clients.
// It is internal to the SDK and must not be imported by consumer code.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

// maxBody is the maximum response body size the SDK will read (1 MiB).
const maxBody = 1 << 20

// Header is a key-value pair added to every request.
type Header struct{ Key, Value string }

// Do executes an HTTP request with JSON body encoding/decoding, redirect
// blocking, and structured error handling.
//
// Parameters:
//   - client: optional *http.Client (nil → http.DefaultClient)
//   - ctx:    request context
//   - method: HTTP method
//   - url:    fully-qualified URL
//   - headers: additional headers (auth, content-type overrides)
//   - input:  request body (JSON-encoded) or nil
//   - output: response body (JSON-decoded) or nil
func Do(client *http.Client, ctx context.Context, method, url string, headers []Header, input, output any) error {
	var body bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&body).Encode(input); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, h := range headers {
		req.Header.Set(h.Key, h.Value)
	}

	transport := client
	if transport == nil {
		transport = http.DefaultClient
	}
	// Copy the client so we can override CheckRedirect without mutating the original.
	// Credentials must never be forwarded through redirects.
	safe := *transport
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	res, err := safe.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return decodeError(res)
	}
	if output == nil || res.StatusCode == 204 {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(output)
}

// decodeError attempts to read a structured error from the response body.
// It handles the IAMKit {"error":{...}} envelope and falls back to a generic error.
func decodeError(res *http.Response) error {
	var envelope struct {
		Error apierror.Error `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(&envelope) == nil && envelope.Error.Code != "" {
		envelope.Error.HTTPStatus = res.StatusCode
		return &envelope.Error
	}
	return &apierror.Error{Code: "HTTP_ERROR", Message: http.StatusText(res.StatusCode), HTTPStatus: res.StatusCode}
}
