package orgsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type domainRepository struct {
	organization.DomainRepository
	domain   organization.Domain
	name     string
	token    string
	verified string
}

func (r *domainRepository) CreateDomain(_ context.Context, _ organization.Boundary, _ organization.Mutation, id identity.DomainID, name, token string) error {
	r.domain = organization.Domain{ID: id, Name: name, Token: token}
	r.name, r.token = name, token
	return nil
}

func (r *domainRepository) FindDomain(context.Context, organization.Boundary, identity.DomainID) (organization.Domain, error) {
	return r.domain, nil
}

func (r *domainRepository) VerifyDomain(_ context.Context, _ organization.Boundary, _ organization.Mutation, _ identity.DomainID, method string) error {
	r.verified = method
	return nil
}

type txt []string

func (t txt) TXT(context.Context, string) ([]string, error) { return t, nil }

func errType(err error) errx.Type {
	var e *errx.Error
	if errx.As(err, &e) && e != nil {
		return e.Type
	}
	return ""
}

func TestAddDomainNormalizesAndIssuesToken(t *testing.T) {
	repo := &domainRepository{}
	d, err := NewDomains(repo, txt(nil)).AddDomain(context.Background(), organization.Boundary{}, organization.Mutation{}, organization.DomainInput{Domain: "Acme.COM."})
	if err != nil || repo.name != "acme.com" || len(repo.token) < 30 || d.ID.IsZero() {
		t.Fatalf("add: %+v %v repo=%+v", d, err, repo)
	}
	if d.Record.Name != "_iamkit-challenge.acme.com" || d.Record.Value != "iamkit-verification="+repo.token {
		t.Errorf("record: %+v", d.Record)
	}
	if _, err := NewDomains(repo, txt(nil)).AddDomain(context.Background(), organization.Boundary{}, organization.Mutation{}, organization.DomainInput{Domain: "co.uk"}); errType(err) != errx.TypeValidation {
		t.Errorf("public suffix accepted: %v", err)
	}
}

func TestVerifyDomainMatchesTXTRecord(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records txt
		ok      bool
	}{
		{"missing", nil, false},
		{"other values", txt{"v=spf1 -all", "iamkit-verification=nope"}, false},
		{"exact", txt{"iamkit-verification=tok"}, true},
		{"quoted with spaces", txt{"v=spf1 -all", ` "iamkit-verification=tok" `}, true},
		{"prefix only", txt{"iamkit-verification=tokextra"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &domainRepository{domain: organization.Domain{ID: identity.NewDomainID(), Name: "acme.com", Token: "tok"}}
			_, err := NewDomains(repo, tc.records).VerifyDomain(context.Background(), organization.Boundary{}, organization.Mutation{}, repo.domain.ID)
			if tc.ok && (err != nil || repo.verified != organization.DomainVerifiedDNS) {
				t.Fatalf("want verified: err=%v method=%q", err, repo.verified)
			}
			if !tc.ok && (errType(err) != errx.TypeBusiness || repo.verified != "") {
				t.Fatalf("want 422: err=%v method=%q", err, repo.verified)
			}
		})
	}
}
