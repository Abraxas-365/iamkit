package orgadminsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
)

func hostedMutation(p orgadmin.Principal) hosted.Mutation {
	return hosted.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

func authMutation(p orgadmin.Principal) authentication.Mutation {
	return authentication.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

// Branding

func (s *Service) Branding(ctx context.Context, p orgadmin.Principal) (hosted.OrganizationSettings, error) {
	if err := p.Require(authorization.PermOrgRead); err != nil {
		return hosted.OrganizationSettings{}, err
	}
	return s.d.BrandingViews.OrganizationSettings(ctx, p.Environment, p.Organization)
}

func (s *Service) SaveBranding(ctx context.Context, p orgadmin.Principal, input hosted.OrganizationSettings) (hosted.OrganizationSettings, error) {
	if err := p.Require(authorization.PermOrgSettingsWrite); err != nil {
		return hosted.OrganizationSettings{}, err
	}
	return s.d.Branding.SaveOrganizationSettings(ctx, hostedMutation(p), p.Organization, input)
}

func (s *Service) DeleteBranding(ctx context.Context, p orgadmin.Principal) error {
	if err := p.Require(authorization.PermOrgSettingsWrite); err != nil {
		return err
	}
	return s.d.Branding.DeleteOrganizationSettings(ctx, hostedMutation(p), p.Organization)
}

// Password policy

func (s *Service) PasswordPolicy(ctx context.Context, p orgadmin.Principal) (authentication.PasswordRequirements, error) {
	if err := p.Require(authorization.PermOrgRead); err != nil {
		return authentication.PasswordRequirements{}, err
	}
	return s.d.PasswordPolicyViews.OrganizationPasswordPolicy(ctx, p.Environment, p.Organization)
}

func (s *Service) SetPasswordPolicy(ctx context.Context, p orgadmin.Principal, input authentication.PasswordRequirements) (authentication.PasswordRequirements, error) {
	if err := p.Require(authorization.PermOrgSettingsWrite); err != nil {
		return authentication.PasswordRequirements{}, err
	}
	return s.d.PasswordPolicies.SetOrganizationPasswordPolicy(ctx, authMutation(p), p.Organization, input)
}

func (s *Service) DeletePasswordPolicy(ctx context.Context, p orgadmin.Principal) error {
	if err := p.Require(authorization.PermOrgSettingsWrite); err != nil {
		return err
	}
	return s.d.PasswordPolicies.DeleteOrganizationPasswordPolicy(ctx, authMutation(p), p.Organization)
}
