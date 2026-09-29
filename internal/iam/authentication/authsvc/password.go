package authsvc

import (
	"context"
	"log/slog"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// PasswordPolicies implements the password policy use cases and the checks
// every new end-user password goes through.
type PasswordPolicies struct {
	repository authentication.PasswordPolicyRepository
	breaches   authentication.Breaches // nil skips the breach check
}

func NewPasswordPolicies(repository authentication.PasswordPolicyRepository, breaches authentication.Breaches) *PasswordPolicies {
	return &PasswordPolicies{repository: repository, breaches: breaches}
}

var (
	_ authentication.PasswordPolicyCommands = (*PasswordPolicies)(nil)
	_ authentication.PasswordPolicyQueries  = (*PasswordPolicies)(nil)
)

func (p *PasswordPolicies) PasswordPolicy(ctx context.Context, environment identity.EnvironmentID) (authentication.PasswordPolicy, error) {
	if environment.IsZero() {
		return authentication.PasswordPolicy{}, errx.NotFound("environment not found")
	}
	policy, err := p.repository.GetPasswordPolicy(ctx, environment)
	var e *errx.Error
	if errx.As(err, &e) && e.Type == errx.TypeNotFound {
		return authentication.DefaultPasswordPolicy(), nil
	}
	return policy, err
}

func (p *PasswordPolicies) SetPasswordPolicy(ctx context.Context, m authentication.Mutation, input authentication.PasswordPolicy) (authentication.PasswordPolicy, error) {
	if err := input.Validate(); err != nil {
		return authentication.PasswordPolicy{}, err
	}
	m.Action, m.Target = authentication.ActionPasswordPolicyUpdated, policyTarget(m.Environment)
	if err := p.repository.SetPasswordPolicy(ctx, m, input); err != nil {
		return authentication.PasswordPolicy{}, err
	}
	return p.PasswordPolicy(ctx, m.Environment)
}

func (p *PasswordPolicies) DeletePasswordPolicy(ctx context.Context, m authentication.Mutation) error {
	m.Action, m.Target = authentication.ActionPasswordPolicyDeleted, policyTarget(m.Environment)
	return p.repository.DeletePasswordPolicy(ctx, m)
}

func policyTarget(environment identity.EnvironmentID) string {
	return "/environments/" + environment.String() + "/password-policy"
}

func (p *PasswordPolicies) CheckPassword(ctx context.Context, environment identity.EnvironmentID, password string) error {
	policy, err := p.PasswordPolicy(ctx, environment)
	if err != nil {
		return err
	}
	return p.check(ctx, policy, password)
}

// check applies the composition rules, then the breach check. A breach
// service that fails or is slow lets the password through.
func (p *PasswordPolicies) check(ctx context.Context, policy authentication.PasswordPolicy, password string) error {
	if err := policy.Check(password); err != nil {
		return err
	}
	if !policy.BreachCheck || p.breaches == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, config.BreachCheckTimeout)
	defer cancel()
	breached, err := p.breaches.Breached(ctx, password)
	if err != nil {
		slog.WarnContext(ctx, "breached password check unavailable; password accepted", "err", err)
		return nil
	}
	if breached {
		return authentication.PasswordRejected(authentication.RuleBreached, policy.MinLength)
	}
	return nil
}

// policy is the environment's policy, the default when the service has no
// policy store (tests).
func (s *Service) policy(ctx context.Context, environment identity.EnvironmentID) (authentication.PasswordPolicy, error) {
	if s.policies == nil {
		return authentication.DefaultPasswordPolicy(), nil
	}
	return s.policies.PasswordPolicy(ctx, environment)
}

// newPassword checks and hashes the password replacing currentHash.
func (s *Service) newPassword(ctx context.Context, policy authentication.PasswordPolicy, currentHash, password string) (string, error) {
	var err error
	if s.policies != nil {
		err = s.policies.check(ctx, policy, password)
	} else {
		err = policy.Check(password)
	}
	if err != nil {
		return "", err
	}
	if currentHash != "" && s.passwords.Compare(currentHash, password) {
		return "", authentication.PasswordRejected(authentication.RuleReused, policy.MinLength)
	}
	return s.passwords.Hash(password)
}

// checkPassword settles a password sign-in attempt on a locked account row.
// A locked account answers like a wrong password and counts nothing. A
// wrong password is counted (locking the account per policy) and committed
// before the uniform 401; a right one clears the count within tx.
func (s *Service) checkPassword(ctx context.Context, tx authentication.Transaction, environment identity.EnvironmentID, policy authentication.PasswordPolicy, account authentication.PasswordAccount, matches bool) error {
	now := time.Now()
	if account.Locked(now) {
		return invalidCredentials()
	}
	if matches {
		if account.Failures > 0 || account.LockedUntil != nil {
			return tx.SetLoginFailures(ctx, account.ID, 0, nil)
		}
		return nil
	}
	failures := account.Failures + 1
	until := policy.LockedUntil(failures, now)
	if until != nil {
		m := authentication.Mutation{Environment: environment, Actor: account.ID.String(), Action: authentication.ActionUserLocked, Target: account.ID.String()}
		if err := tx.Audit(ctx, m); err != nil {
			return err
		}
	}
	if err := tx.SetLoginFailures(ctx, account.ID, failures, until); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return invalidCredentials()
}
