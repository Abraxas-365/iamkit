// Package oauth defines environment-bound OAuth client registration.
package oauth

// Client is independent of persistence and OAuth protocol libraries.
type Client struct {
	ID          string
	Environment string
	Application string
	Resource    string
	Audience    string
	Redirects   []string
	Public      bool
	Secret      []byte
}
