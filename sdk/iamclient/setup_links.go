package iamclient

import (
	"context"
	"time"
)

// Setup intents: what a setup link lets the customer's IT administrator
// configure.
const (
	SetupIntentSSO       = "sso"
	SetupIntentDirectory = "directory"
	SetupIntentDomains   = "domains"
)

// SetupLinkInput asks for a setup link. ExpiresIn is a Go duration such as
// "72h" (default 7 days, at most 30 days).
type SetupLinkInput struct {
	Intents   []string `json:"intents"`
	ExpiresIn string   `json:"expires_in,omitempty"`
}

// SetupLink is a created link. URL carries the secret in its fragment and
// is returned only here: hand it to the customer.
type SetupLink struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	Intents   []string  `json:"intents"`
}

// SetupLinkInfo is a listed link (never its secret).
type SetupLinkInfo struct {
	ID         string     `json:"id"`
	Intents    []string   `json:"intents"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func (e Environment) setupLinksPath(organization string) string {
	return e.path("organizations/" + organization + "/setup-links")
}

// CreateSetupLink issues an expiring link to the organization's setup
// portal for its IT administrator. Audited as org_setup_link.created.
func (e Environment) CreateSetupLink(ctx context.Context, organization string, input SetupLinkInput) (SetupLink, error) {
	var out SetupLink
	err := e.client.Do(ctx, "POST", e.setupLinksPath(organization), input, &out)
	return out, err
}

// SetupLinks lists the organization's setup links, newest first.
func (e Environment) SetupLinks(ctx context.Context, organization string) ([]SetupLinkInfo, error) {
	return collect[SetupLinkInfo](ctx, e.client, e.setupLinksPath(organization), nil)
}

// RevokeSetupLink ends a link and every session exchanged from it. Audited
// as org_setup_link.revoked.
func (e Environment) RevokeSetupLink(ctx context.Context, organization, link string) error {
	return e.client.Do(ctx, "DELETE", e.setupLinksPath(organization)+"/"+link, nil, nil)
}
