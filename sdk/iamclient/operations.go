package iamclient

import (
	"context"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

type Impersonation struct {
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
	UserID         string `json:"user_id"`
	Reason         string `json:"reason"`
}
type UnitImpact struct {
	HasChildren   bool     `json:"has_children"`
	UserIDs       []string `json:"affected_user_ids"`
	AssignmentIDs []string `json:"assignment_ids"`
}
type ReportingMember struct {
	UserID    string  `json:"user_id"`
	ManagerID *string `json:"manager_id"`
	OrgUnitID *string `json:"org_unit_id"`
	Name      string  `json:"name"`
	Email     string  `json:"email"`
}

func (e Environment) Impersonate(ctx context.Context, input Impersonation) (authclient.TokenPair, error) {
	var out authclient.TokenPair
	err := e.operation(ctx, "POST", []string{"impersonations"}, input, &out)
	return out, err
}
func (e Environment) LinkProvisionedIdentity(ctx context.Context, connection, user, external string) error {
	return e.operation(ctx, "POST", []string{"provisioned-identities"}, map[string]string{"connection_id": connection, "user_id": user, "external_id": external}, nil)
}
func (e Environment) Resource(ctx context.Context, id string) (Resource, error) {
	var out Resource
	err := e.operation(ctx, "GET", []string{"resources", id}, nil, &out)
	return out, err
}
func (e Environment) OrgUnitDeleteImpact(ctx context.Context, org, id string) (UnitImpact, error) {
	var out UnitImpact
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-units", id, "delete-impact"}, nil, &out)
	return out, err
}
func (e Environment) OrgChart(ctx context.Context, org string) ([]ReportingMember, error) {
	var out []ReportingMember
	err := e.operation(ctx, "GET", []string{"organizations", org, "org-chart"}, nil, &out)
	return out, err
}
