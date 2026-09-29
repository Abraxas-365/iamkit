package authsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SignInPolicies implements the sign-in policy use cases.
type SignInPolicies struct {
	repository authentication.SignInPolicyRepository
}

func NewSignInPolicies(repository authentication.SignInPolicyRepository) *SignInPolicies {
	return &SignInPolicies{repository: repository}
}

var (
	_ authentication.SignInPolicyCommands = (*SignInPolicies)(nil)
	_ authentication.SignInPolicyQueries  = (*SignInPolicies)(nil)
)

func (p *SignInPolicies) SignInPolicy(ctx context.Context, environment identity.EnvironmentID) (authentication.SignInPolicy, error) {
	if environment.IsZero() {
		return authentication.SignInPolicy{}, errx.NotFound("environment not found")
	}
	policy, err := p.repository.GetSignInPolicy(ctx, environment)
	var e *errx.Error
	if errx.As(err, &e) && e.Type == errx.TypeNotFound {
		return authentication.DefaultSignInPolicy(), nil
	}
	return policy, err
}

func (p *SignInPolicies) SetSignInPolicy(ctx context.Context, m authentication.Mutation, input authentication.SignInPolicy) (authentication.SignInPolicy, error) {
	if err := input.Validate(); err != nil {
		return authentication.SignInPolicy{}, err
	}
	if !input.SignupOrganization.IsZero() {
		organization, group, err := p.repository.SignupTarget(ctx, m.Environment, input.SignupOrganization, input.SignupGroup)
		if err != nil {
			return authentication.SignInPolicy{}, err
		}
		if !organization {
			return authentication.SignInPolicy{}, errx.Validation("signup_organization_id must be an active organization")
		}
		if !group {
			return authentication.SignInPolicy{}, errx.Validation("signup_group_id must be an operator-managed group of the sign-up organization")
		}
	}
	m.Action, m.Target = authentication.ActionSignInPolicyUpdated, signInTarget(m.Environment)
	if err := p.repository.SetSignInPolicy(ctx, m, input); err != nil {
		return authentication.SignInPolicy{}, err
	}
	return p.SignInPolicy(ctx, m.Environment)
}

func (p *SignInPolicies) DeleteSignInPolicy(ctx context.Context, m authentication.Mutation) error {
	m.Action, m.Target = authentication.ActionSignInPolicyDeleted, signInTarget(m.Environment)
	return p.repository.DeleteSignInPolicy(ctx, m)
}

func signInTarget(environment identity.EnvironmentID) string {
	return "/environments/" + environment.String() + "/sign-in-policy"
}

// signInPolicy is the environment's sign-in policy, the default when the
// service has no policy store (tests).
func (s *Service) signInPolicy(ctx context.Context, environment identity.EnvironmentID) (authentication.SignInPolicy, error) {
	if s.signIns == nil {
		return authentication.DefaultSignInPolicy(), nil
	}
	return s.signIns.SignInPolicy(ctx, environment)
}

// allowed refuses a method the environment, or the boundary's organization
// when set, does not allow. It reads nothing about the account, so a refusal
// reveals none. An unknown organization answers like a wrong password.
func (s *Service) allowed(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, method string) error {
	policy, err := s.signInPolicy(ctx, boundary.EnvironmentID)
	if err != nil {
		return err
	}
	if !policy.Methods().Allows(method) {
		return authentication.ErrMethodNotAllowed()
	}
	if boundary.OrganizationID.IsZero() {
		return nil
	}
	methods, err := tx.OrganizationMethods(ctx, boundary.EnvironmentID, boundary.OrganizationID)
	if err != nil {
		return err
	}
	if !methods.Allows(method) {
		return authentication.ErrMethodNotAllowed()
	}
	return nil
}

// environmentAllows refuses a method the environment does not allow.
func (s *Service) environmentAllows(ctx context.Context, environment identity.EnvironmentID, method string) error {
	policy, err := s.signInPolicy(ctx, environment)
	if err != nil {
		return err
	}
	if !policy.Methods().Allows(method) {
		return authentication.ErrMethodNotAllowed()
	}
	return nil
}

// resetAllowed refuses a password reset the environment does not offer.
func (s *Service) resetAllowed(ctx context.Context, environment identity.EnvironmentID) error {
	policy, err := s.signInPolicy(ctx, environment)
	if err != nil {
		return err
	}
	if !policy.AllowPassword || !policy.AllowPasswordReset {
		return authentication.ErrPasswordResetDisabled()
	}
	return nil
}
