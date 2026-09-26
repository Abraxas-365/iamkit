package organization

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Domain verification methods.
const (
	DomainVerifiedDNS    = "dns"
	DomainVerifiedManual = "manual"
)

// DomainChallengeLabel prefixes the domain for the verification TXT record,
// whose value is DomainChallengeValue followed by the domain's token.
const (
	DomainChallengeLabel = "_iamkit-challenge."
	DomainChallengeValue = "iamkit-verification="
)

// Domain is a DNS name claimed by an organization. It belongs to at most one
// organization per environment, verified or not. Verification is on demand;
// it is never re-checked in the background. Only the exact name is claimed:
// subdomains are separate domains.
type Domain struct {
	ID           identity.DomainID       `json:"id" db:"id"`
	Organization identity.OrganizationID `json:"organization_id" db:"organization_id"`
	Name         string                  `json:"domain" db:"domain"`
	Token        string                  `json:"-" db:"verification_token"`
	VerifiedAt   *time.Time              `json:"verified_at" db:"verified_at"`
	VerifiedBy   *string                 `json:"verified_by" db:"verified_by"`
	Method       *string                 `json:"verification_method" db:"verification_method"`
	Created      time.Time               `json:"created_at" db:"created_at"`
	Verified     bool                    `json:"verified" db:"-"`
	Record       DomainRecord            `json:"verification" db:"-"`
}

// DomainRecord is the DNS record that proves control of a domain.
type DomainRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Presented fills the derived fields exposed to clients.
func (d Domain) Presented() Domain {
	d.Verified = d.VerifiedAt != nil
	d.Record = DomainRecord{Type: "TXT", Name: DomainChallengeLabel + d.Name, Value: DomainChallengeValue + d.Token}
	return d
}

type DomainInput struct {
	Domain string `json:"domain"`
}

func (d DomainInput) Validate() error {
	_, err := identity.Domain(d.Domain)
	return err
}

// ErrDomainNotVerified reports that the verification TXT record was not found.
func ErrDomainNotVerified(record DomainRecord) error {
	return errx.Business("verification record not found: publish TXT " + record.Name + " with value " + record.Value + " and retry")
}
