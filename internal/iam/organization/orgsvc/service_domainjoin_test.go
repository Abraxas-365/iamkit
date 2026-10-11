package orgsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type joinRepository struct {
	organization.Repository
	operator bool
	updated  bool
}

func (r *joinRepository) OperatorGroup(context.Context, identity.EnvironmentID, identity.OrganizationID, identity.GroupID) (bool, error) {
	return r.operator, nil
}

func (r *joinRepository) Update(context.Context, organization.Mutation, identity.OrganizationID, organization.Update) error {
	r.updated = true
	return nil
}

func TestUpdateChecksDomainJoinGroup(t *testing.T) {
	group := identity.NewGroupID()
	clear := identity.GroupID{}
	on := true
	for name, tc := range map[string]struct {
		operator bool
		input    organization.Update
		want     errx.Type
	}{
		"operator group":   {true, organization.Update{DomainJoin: &on, DomainJoinGroup: &group}, ""},
		"foreign or SCIM":  {false, organization.Update{DomainJoin: &on, DomainJoinGroup: &group}, errx.TypeValidation},
		"clearing is free": {false, organization.Update{DomainJoinGroup: &clear}, ""},
		"no group change":  {false, organization.Update{DomainJoin: &on}, ""},
	} {
		repo := &joinRepository{operator: tc.operator}
		err := New(repo).Update(context.Background(), organization.Mutation{}, identity.NewOrganizationID(), tc.input)
		if got := errType(err); got != tc.want || (tc.want != "" && repo.updated) {
			t.Errorf("%s: error %q (%v), updated=%v", name, got, err, repo.updated)
		}
	}
}
