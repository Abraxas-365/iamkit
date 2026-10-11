// Package apikeysvc implements the API key use cases.
package apikeysvc

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository apikey.Repository
	secrets    apikey.Secrets
	now        func() time.Time
}

var _ apikey.Commands = (*Service)(nil)
var _ apikey.Queries = (*Service)(nil)

func New(repository apikey.Repository, secrets apikey.Secrets) *Service {
	return &Service{repository: repository, secrets: secrets, now: time.Now}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// disabled is the refusal of a kind the environment's policy turns off.
func disabled() error {
	e := errx.Forbidden("API keys of this kind are disabled for the environment")
	e.Code = "API_KEYS_DISABLED"
	return e
}

// refused names the requested permissions the effective set lacks.
func refused(requested, effective []string) error {
	var out []string
	for _, p := range requested {
		if !slices.Contains(effective, p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return errx.Business("permissions not allowed for this key: " + strings.Join(out, ", "))
}

// normalize trims, sorts and de-duplicates the requested permissions.
func normalize(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, strings.TrimSpace(p))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// authorize checks that the scope may create the owner kind the input names
// and that the input stays inside the scope.
func authorize(m apikey.Mutation, input apikey.NewAPIKey) error {
	switch {
	case m.IsSelf():
		if input.Owner.Type != apikey.OwnerUser || input.Owner.User != m.User {
			return errx.Forbidden("users create only their own API keys")
		}
		if input.Organization != m.Organization {
			return errx.Validation("organization_id must be the organization of the session")
		}
		if m.Application.IsZero() {
			return errx.Forbidden("a user access token is required")
		}
	case m.IsOrganization():
		if input.Owner.Type != apikey.OwnerOrganization {
			return errx.Forbidden("organization administrators create organization API keys")
		}
		if input.Organization != m.Organization {
			return errx.Validation("organization_id must be the administrator's organization")
		}
		if m.Granter.IsZero() {
			return errx.Forbidden("API keys are created by administrators with an account")
		}
	default:
		if input.Owner.Type == apikey.OwnerUser {
			return errx.Forbidden("user API keys are created by the users themselves")
		}
	}
	return nil
}

func (s *Service) Create(ctx context.Context, m apikey.Mutation, input apikey.NewAPIKey) (apikey.Issued, error) {
	if err := input.Validate(); err != nil {
		return apikey.Issued{}, err
	}
	if err := authorize(m, input); err != nil {
		return apikey.Issued{}, err
	}
	if m.IsSelf() {
		if err := apikey.FreshAuth(m.AuthTime, s.now()); err != nil {
			return apikey.Issued{}, err
		}
	}
	ttl, _ := input.TTL() // validated
	policy, err := s.repository.Policy(ctx, m.Environment)
	if err != nil {
		return apikey.Issued{}, err
	}
	limit := 0
	if input.Owner.Type != apikey.OwnerMachine {
		if !policy.Allows(input.Owner.Type) {
			return apikey.Issued{}, disabled()
		}
		if err = policy.CheckTTL(ttl); err != nil {
			return apikey.Issued{}, err
		}
		limit = policy.MaxPerOrganization
		if input.Owner.Type == apikey.OwnerUser {
			limit = policy.MaxPerUser
		}
	}
	input.Permissions = normalize(input.Permissions)
	if len(input.Permissions) > 0 {
		effective, err := s.repository.Reach(ctx, m.Environment, input)
		if err != nil {
			return apikey.Issued{}, err
		}
		if err = refused(input.Permissions, effective); err != nil {
			return apikey.Issued{}, err
		}
		if input.Owner.Type == apikey.OwnerOrganization && !m.Granter.IsZero() {
			held, err := s.repository.Held(ctx, m.Environment, input.Organization, m.Granter, input.Resource)
			if err != nil {
				return apikey.Issued{}, err
			}
			if err = refused(input.Permissions, held); err != nil {
				return apikey.Issued{}, err
			}
		}
	}
	raw, hash, err := s.secrets.Generate(identity.APIKeyPrefix)
	if err != nil {
		return apikey.Issued{}, err
	}
	key := apikey.APIKey{
		ID:              identity.NewAPIKeyID(),
		Environment:     m.Environment,
		Owner:           input.Owner,
		Organization:    input.Organization,
		Resource:        input.Resource,
		Name:            strings.TrimSpace(input.Name),
		Permissions:     input.Permissions,
		ObfuscatedValue: identity.ObfuscatedAPIKey(identity.APIKeyLast4(raw)),
		ExpiresAt:       s.now().Add(ttl).UTC().Truncate(time.Second),
	}
	if input.Owner.Type == apikey.OwnerMachine {
		application := input.Application
		key.Application = &application
	}
	m.Action = apikey.ActionCreate
	m.Target = apikey.Target(key.Owner.Type, key.Organization, key.ID)
	stored, err := s.repository.Create(ctx, m, key, hash, limit)
	if err != nil {
		return apikey.Issued{}, err
	}
	return apikey.Issued{APIKey: stored, Value: raw}, nil
}

func (s *Service) Revoke(ctx context.Context, m apikey.Mutation, id identity.APIKeyID) error {
	if id.IsZero() {
		return errx.NotFound("API key not found")
	}
	found, err := s.repository.Find(ctx, m.Scope, id)
	if err != nil {
		return err
	}
	m.Action = apikey.ActionRevoke
	m.Target = apikey.Target(found.Owner.Type, found.Organization, found.ID)
	return s.repository.Revoke(ctx, m, id)
}

func (s *Service) SavePolicy(ctx context.Context, m apikey.Mutation, policy apikey.Policy) (apikey.Policy, error) {
	if err := policy.Validate(); err != nil {
		return apikey.Policy{}, err
	}
	m.Action = apikey.ActionPolicyUpdate
	m.Target = m.Environment.String()
	return s.repository.SavePolicy(ctx, m, policy)
}

func (s *Service) List(ctx context.Context, scope apikey.Scope, filter apikey.Filter, page query.Pagination) (query.Paginated[apikey.APIKey], error) {
	if filter.OwnerType != "" && !filter.OwnerType.Valid() {
		return query.Paginated[apikey.APIKey]{}, errx.Validation("owner_type must be user, organization or machine")
	}
	switch filter.State {
	case "", apikey.StateActive, apikey.StateRevoked, apikey.StateExpired:
	default:
		return query.Paginated[apikey.APIKey]{}, errx.Validation("state must be active, revoked or expired")
	}
	return s.repository.List(ctx, scope, filter, page.Normalize())
}

func (s *Service) Find(ctx context.Context, scope apikey.Scope, id identity.APIKeyID) (apikey.APIKey, error) {
	if id.IsZero() {
		return apikey.APIKey{}, errx.NotFound("API key not found")
	}
	return s.repository.Find(ctx, scope, id)
}

func (s *Service) Policy(ctx context.Context, environment identity.EnvironmentID) (apikey.Policy, error) {
	return s.repository.Policy(ctx, environment)
}

func (s *Service) Options(ctx context.Context, scope apikey.Scope, granter identity.UserID, application identity.ApplicationID) (apikey.Options, error) {
	kind := apikey.OwnerOrganization
	if scope.IsSelf() {
		kind = apikey.OwnerUser
	} else if !scope.IsOrganization() {
		return apikey.Options{}, errx.Validation("options are for organization administrators and users")
	}
	policy, err := s.repository.Policy(ctx, scope.Environment)
	if err != nil {
		return apikey.Options{}, err
	}
	out := apikey.Options{Enabled: policy.Allows(kind), MaxTTLDays: policy.MaxTTLDays, Resources: []apikey.OptionResource{}}
	if !out.Enabled {
		return out, nil
	}
	resources, err := s.repository.OptionResources(ctx, scope, kind, granter, application)
	if err != nil {
		return apikey.Options{}, err
	}
	if resources != nil {
		out.Resources = resources
	}
	return out, nil
}
