package orgsvc

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Domains manages the DNS domains organizations claim and verifies them on
// demand through a TXT record.
type Domains struct {
	repository organization.DomainRepository
	resolver   organization.Resolver
}

func NewDomains(r organization.DomainRepository, resolver organization.Resolver) *Domains {
	return &Domains{repository: r, resolver: resolver}
}

var _ organization.DomainCommands = (*Domains)(nil)
var _ organization.DomainQueries = (*Domains)(nil)

// verificationToken is published in DNS, so it only needs to be unguessable
// enough that another party cannot pre-publish it.
func verificationToken() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", errx.Wrap(err, "token generation failed", errx.TypeInternal)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}

func (s *Domains) AddDomain(ctx context.Context, b organization.Boundary, m organization.Mutation, input organization.DomainInput) (organization.Domain, error) {
	name, err := identity.Domain(input.Domain)
	if err != nil {
		return organization.Domain{}, err
	}
	token, err := verificationToken()
	if err != nil {
		return organization.Domain{}, err
	}
	id := identity.NewDomainID()
	if err = s.repository.CreateDomain(ctx, b, m, id, name, token); err != nil {
		return organization.Domain{}, err
	}
	return s.FindDomain(ctx, b, id)
}

func (s *Domains) VerifyDomain(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.DomainID) (organization.Domain, error) {
	d, err := s.FindDomain(ctx, b, id)
	if err != nil || d.Verified {
		return d, err
	}
	records, err := s.resolver.TXT(ctx, d.Record.Name)
	if err != nil {
		return d, err
	}
	if !hasRecord(records, d.Record.Value) {
		return d, organization.ErrDomainNotVerified(d.Record)
	}
	if err = s.repository.VerifyDomain(ctx, b, m, id, organization.DomainVerifiedDNS); err != nil {
		return d, err
	}
	return s.FindDomain(ctx, b, id)
}

// hasRecord reports whether one TXT record equals want, ignoring surrounding
// whitespace and quotes some DNS panels add.
func hasRecord(records []string, want string) bool {
	for _, r := range records {
		if strings.Trim(strings.TrimSpace(r), `"`) == want {
			return true
		}
	}
	return false
}

func (s *Domains) ForceVerifyDomain(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.DomainID) (organization.Domain, error) {
	d, err := s.FindDomain(ctx, b, id)
	if err != nil || d.Verified {
		return d, err
	}
	if err = s.repository.VerifyDomain(ctx, b, m, id, organization.DomainVerifiedManual); err != nil {
		return d, err
	}
	return s.FindDomain(ctx, b, id)
}

func (s *Domains) DeleteDomain(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.DomainID) error {
	if id.IsZero() {
		return errx.NotFound("domain not found")
	}
	return s.repository.DeleteDomain(ctx, b, m, id)
}

func (s *Domains) ListDomains(ctx context.Context, b organization.Boundary, page query.Pagination) (query.Paginated[organization.Domain], error) {
	out, err := s.repository.ListDomains(ctx, b, page)
	for i := range out.Items {
		out.Items[i] = out.Items[i].Presented()
	}
	return out, err
}

func (s *Domains) FindDomain(ctx context.Context, b organization.Boundary, id identity.DomainID) (organization.Domain, error) {
	if id.IsZero() {
		return organization.Domain{}, errx.NotFound("domain not found")
	}
	d, err := s.repository.FindDomain(ctx, b, id)
	if err != nil {
		return d, err
	}
	return d.Presented(), nil
}
