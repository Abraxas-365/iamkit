package orgadminsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

var (
	ownCredential     = identity.MustParseCredentialID("5e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a01")
	foreignCredential = identity.MustParseCredentialID("5e7c7a4e-3b2c-4d55-9d0a-1c1f3b2e4a02")
)

// directories plays the provisioning control: it records what the service
// issues and revokes, and answers 404 for credentials of another organization,
// as the repository's SQL does.
type directories struct {
	provisioning.ControlCommands
	provisioning.ControlQueries
	issued     []provisioning.CredentialInput
	revoked    []identity.CredentialID
	revokedMut []provisioning.Mutation
	listed     []identity.OrganizationID
}

func (d *directories) Issue(_ context.Context, _ provisioning.Mutation, input provisioning.CredentialInput) (provisioning.Credential, error) {
	d.issued = append(d.issued, input)
	return provisioning.Credential{ID: ownCredential, Secret: "ik_scim_x"}, nil
}
func (d *directories) RevokeOrganization(_ context.Context, m provisioning.Mutation, organization identity.OrganizationID, id identity.CredentialID) error {
	if organization != org || id != ownCredential {
		return errx.NotFound("resource not found")
	}
	d.revoked = append(d.revoked, id)
	d.revokedMut = append(d.revokedMut, m)
	return nil
}
func (d *directories) OrganizationCredentials(_ context.Context, _ identity.EnvironmentID, organization identity.OrganizationID, _ query.Pagination) (query.Paginated[provisioning.CredentialView], error) {
	d.listed = append(d.listed, organization)
	return query.Paginated[provisioning.CredentialView]{Items: []provisioning.CredentialView{{ID: ownCredential, Organization: organization}}}, nil
}

func directoryFixture() (*Service, *directories) {
	d := &directories{}
	return New(Deps{Directories: d, DirectoryViews: d, Issuer: "https://iam.example/"}), d
}

func TestDirectoryOrganizationIsForced(t *testing.T) {
	s, d := directoryFixture()
	p := principal(manager, authorization.PermOrgSSOWrite, authorization.PermOrgRead)
	p.Action, p.Target = "POST", "/api/v1/directories"
	secret := "30d"
	if _, err := s.IssueDirectory(ctx, p, orgadmin.NewDirectory{Name: "Okta", ExpiresIn: &secret}); err != nil {
		t.Fatal(err)
	}
	if len(d.issued) != 1 || d.issued[0].Organization != org || !d.issued[0].Connection.IsZero() {
		t.Fatalf("issued: %+v", d.issued)
	}
	list, err := s.Directories(ctx, p, query.Pagination{Limit: 10})
	if err != nil || len(d.listed) != 1 || d.listed[0] != org || len(list.Items) != 1 || list.SCIMURL != "https://iam.example/scim/v2" {
		t.Fatalf("list: %+v %v %v", list, d.listed, err)
	}
	if err := s.RevokeDirectory(ctx, p, ownCredential); err != nil {
		t.Fatal(err)
	}
	if m := d.revokedMut[0]; m.Environment != env || m.Actor != manager.String() || m.Action != "POST" {
		t.Fatalf("mutation: %+v", m)
	}
}

func TestDirectoryOfAnotherOrganizationIsNotFound(t *testing.T) {
	s, d := directoryFixture()
	p := principal(manager, authorization.PermOrgSSOWrite)
	kind(t, s.RevokeDirectory(ctx, p, foreignCredential), 404)
	if len(d.revoked) != 0 {
		t.Fatalf("revoked %v", d.revoked)
	}
}

func TestDirectoryNeedsPermissions(t *testing.T) {
	s, d := directoryFixture()
	_, err := s.IssueDirectory(ctx, principal(manager, authorization.PermOrgRead), orgadmin.NewDirectory{Name: "Okta"})
	kind(t, err, 403)
	kind(t, s.RevokeDirectory(ctx, principal(manager, authorization.PermOrgRead), ownCredential), 403)
	_, err = s.Directories(ctx, principal(manager, authorization.PermOrgSSOWrite), query.Pagination{Limit: 10})
	kind(t, err, 403)
	if len(d.issued)+len(d.revoked)+len(d.listed) != 0 {
		t.Fatal("a refused call reached provisioning")
	}
}

func TestDirectoryNeedsAName(t *testing.T) {
	s, d := directoryFixture()
	_, err := s.IssueDirectory(ctx, principal(manager, authorization.PermOrgSSOWrite), orgadmin.NewDirectory{})
	kind(t, err, 400)
	if len(d.issued) != 0 {
		t.Fatal("invalid input issued")
	}
}

func TestSetupLinkDirectoryLimits(t *testing.T) {
	s, d := directoryFixture()
	p := principal(manager, authorization.PermOrgSSOWrite, authorization.PermOrgRead)
	p.SetupLink = identity.NewSetupLinkID()
	yes, never, year := true, "never", "8760h"
	_, err := s.IssueDirectory(ctx, p, orgadmin.NewDirectory{Name: "Okta", AdoptExistingMembers: &yes})
	kind(t, err, 400)
	_, err = s.IssueDirectory(ctx, p, orgadmin.NewDirectory{Name: "Okta", ExpiresIn: &never})
	kind(t, err, 400)
	if len(d.issued) != 0 {
		t.Fatalf("issued: %+v", d.issued)
	}
	no := false
	if _, err = s.IssueDirectory(ctx, p, orgadmin.NewDirectory{Name: "Okta", ExpiresIn: &year, AdoptExistingMembers: &no}); err != nil {
		t.Fatal(err)
	}

	// Regular administrators keep both.
	admin := principal(manager, authorization.PermOrgSSOWrite)
	if _, err = s.IssueDirectory(ctx, admin, orgadmin.NewDirectory{Name: "Okta", ExpiresIn: &never, AdoptExistingMembers: &yes}); err != nil {
		t.Fatal(err)
	}
}
