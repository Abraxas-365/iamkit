package oauth

import "github.com/Abraxas-365/iamkit/internal/identity"

type Client struct {
	ID          identity.ClientID
	Environment identity.EnvironmentID
	Application identity.ApplicationID
	Resource    identity.ResourceID
	Audience    string
	Redirects   []string
	Public      bool
	Secret      []byte
	// HostedLogin sends the browser to IAMKit's hosted sign-in pages instead
	// of returning the headless authorization ticket.
	HostedLogin bool
}
