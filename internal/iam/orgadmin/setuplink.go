package orgadmin

import (
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Secret prefixes: the link a customer's IT administrator opens, and the
// opaque bearer the portal exchanges it for.
const (
	SetupLinkPrefix    = "ik_setup_"
	SetupSessionPrefix = "ik_setupsess_"
)

// Setup intents: what a setup link lets its holder configure.
const (
	IntentSSO       = "sso"
	IntentDirectory = "directory"
	IntentDomains   = "domains"
)

// Intents lists every setup intent.
var Intents = []string{IntentSSO, IntentDirectory, IntentDomains}

// IntentPermissions maps intents to the organization permissions their
// bearer holds (sorted, without duplicates): sso and directory both need
// the connection and directory writes, domains the domain writes. Unknown
// intents grant nothing.
func IntentPermissions(intents []string) []string {
	var out []string
	for _, intent := range intents {
		switch intent {
		case IntentSSO, IntentDirectory:
			out = append(out, authorization.PermOrgRead, authorization.PermOrgSSOWrite)
		case IntentDomains:
			out = append(out, authorization.PermOrgRead, authorization.PermOrgDomainsWrite)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// SetupLinkInput asks for a setup link. ExpiresIn is a Go duration
// ("72h"); absent = config.SetupLinkTTL.
type SetupLinkInput struct {
	Intents   []string `json:"intents"`
	ExpiresIn *string  `json:"expires_in,omitempty"`
}

// Normalized returns the intents deduplicated in catalog order.
func (i SetupLinkInput) Normalized() []string {
	out := []string{}
	for _, intent := range Intents {
		if slices.Contains(i.Intents, intent) {
			out = append(out, intent)
		}
	}
	return out
}

// TTL is the link's lifetime.
func (i SetupLinkInput) TTL() (time.Duration, error) {
	if i.ExpiresIn == nil || *i.ExpiresIn == "" {
		return config.SetupLinkTTL, nil
	}
	d, err := time.ParseDuration(*i.ExpiresIn)
	if err != nil {
		return 0, errx.Validation("invalid expires_in: must be a Go duration (e.g. \"72h\")")
	}
	if d < config.SetupLinkMinTTL {
		return 0, errx.Validation("expires_in must be at least 5m")
	}
	if d > config.SetupLinkMaxTTL {
		return 0, errx.Validation("expires_in must be at most 720h (30 days)")
	}
	return d, nil
}

func (i SetupLinkInput) Validate() error {
	if len(i.Intents) == 0 {
		return errx.Validation("intents must name at least one of sso, directory, domains")
	}
	for _, intent := range i.Intents {
		if !slices.Contains(Intents, intent) {
			return errx.Validation("unknown intent " + intent + ": use sso, directory or domains")
		}
	}
	_, err := i.TTL()
	return err
}

// SetupLink is a stored link; its secret is never readable again.
type SetupLink struct {
	ID         identity.SetupLinkID `json:"id" db:"id"`
	Intents    []string             `json:"intents" db:"-"`
	ExpiresAt  time.Time            `json:"expires_at" db:"expires_at"`
	RevokedAt  *time.Time           `json:"revoked_at" db:"revoked_at"`
	CreatedBy  string               `json:"created_by" db:"created_by"`
	CreatedAt  time.Time            `json:"created_at" db:"created_at"`
	LastUsedAt *time.Time           `json:"last_used_at" db:"last_used_at"`
}

// IssuedSetupLink is a new link: the URL carries the secret in its
// fragment and is shown once.
type IssuedSetupLink struct {
	ID        identity.SetupLinkID `json:"id"`
	URL       string               `json:"url"`
	ExpiresAt time.Time            `json:"expires_at"`
	Intents   []string             `json:"intents"`
}

// SetupGrant is what a live setup bearer stands for.
type SetupGrant struct {
	Link         identity.SetupLinkID
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Intents      []string
}

// Permissions are the organization permissions the grant holds.
func (g SetupGrant) Permissions() []string { return IntentPermissions(g.Intents) }

// SetupExchanged is what the repository returns for an exchanged link.
type SetupExchanged struct {
	Grant            SetupGrant
	OrganizationName string
	ExpiresAt        time.Time
}

// SetupSession is the answer of exchanging a link: the bearer for
// /api/v1/…/admin routes, limited to the link's intents.
type SetupSession struct {
	AccessToken      string                  `json:"access_token"`
	TokenType        string                  `json:"token_type"`
	ExpiresIn        int                     `json:"expires_in"`
	EnvironmentID    identity.EnvironmentID  `json:"environment_id"`
	OrganizationID   identity.OrganizationID `json:"organization_id"`
	Intents          []string                `json:"intents"`
	OrganizationName string                  `json:"organization_name"`
}

// SetupExchange is the body of the public exchange.
type SetupExchange struct {
	Token string `json:"token"`
}

// SetupMutation is a change to a setup link, audited.
type SetupMutation struct {
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Actor        string
	Action       string
	Target       string
}
