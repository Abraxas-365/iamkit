package provsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository provisioning.Repository
	secrets    provisioning.Secrets
}

func New(repository provisioning.Repository, secrets provisioning.Secrets) *Service {
	return &Service{repository, secrets}
}
func (s *Service) Authenticate(ctx context.Context, raw string) (provisioning.Principal, error) {
	if !strings.HasPrefix(raw, "ik_scim_") {
		return provisioning.Principal{}, errx.Unauthorized("invalid credential")
	}
	return s.repository.Authenticate(ctx, s.secrets.Hash(raw))
}
func (s *Service) Find(ctx context.Context, p provisioning.Principal, id identity.UserID) (provisioning.User, error) {
	if id.IsZero() {
		return provisioning.User{}, errx.NotFound("user not found")
	}
	return s.repository.Find(ctx, p, id)
}
func (s *Service) List(ctx context.Context, p provisioning.Principal, f provisioning.Filter) ([]provisioning.User, int, error) {
	f = f.Clamped()
	switch f.Field {
	case "", "userName", "externalId", "emails.value":
	case "id":
		// id filters match only our own UUIDs; anything else matches nothing.
		if _, err := identity.ParseUserID(f.Value); err != nil {
			return []provisioning.User{}, 0, nil
		}
	default:
		return nil, 0, errx.Validation("unsupported filter").WithDetail("scimType", "invalidFilter")
	}
	return s.repository.List(ctx, p, f)
}
func (s *Service) Create(ctx context.Context, p provisioning.Principal, input provisioning.User) (provisioning.User, error) {
	email, err := identity.Email(input.Email)
	if err != nil {
		return input, err
	}
	input.Email = email
	if input.Name == "" {
		input.Name = email
	}
	if err := validManager(input.Manager); err != nil {
		return input, err
	}
	if input.Aliases, err = normalizeAliases(email, input.Aliases); err != nil {
		return input, err
	}
	input.ID = identity.NewUserID()
	input.ExternalSource = provisioning.AnchorClient
	if input.External == "" {
		// Without a directory anchor the identity is keyed by our own id, so
		// a later userName change does not orphan it.
		input.External, input.ExternalSource = input.ID.String(), provisioning.AnchorDerived
	}
	id, err := s.repository.Create(ctx, p, input)
	if err != nil {
		return input, err
	}
	return s.repository.Find(ctx, p, id)
}
func (s *Service) Update(ctx context.Context, p provisioning.Principal, id identity.UserID, input provisioning.Update) (provisioning.User, error) {
	if id.IsZero() {
		return provisioning.User{}, errx.NotFound("user not found")
	}
	if input.Manager != nil {
		if err := validManager(*input.Manager); err != nil {
			return provisioning.User{}, err
		}
	}
	primary := ""
	if input.Email != nil {
		email, err := identity.Email(*input.Email)
		if err != nil {
			return provisioning.User{}, errx.Validation("userName must be a valid email").WithDetail("scimType", "invalidValue")
		}
		input.Email, primary = &email, email
	}
	if input.External != nil && strings.TrimSpace(*input.External) == "" {
		input.External = nil
	}
	if input.Aliases != nil {
		aliases, err := normalizeAliases(primary, *input.Aliases)
		if err != nil {
			return provisioning.User{}, err
		}
		input.Aliases = &aliases
	}
	return s.repository.Update(ctx, p, id, input)
}
func (s *Service) Delete(ctx context.Context, p provisioning.Principal, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("user not found")
	}
	return s.repository.Deprovision(ctx, p, id)
}

func validManager(manager string) error {
	if manager == "" {
		return nil
	}
	if _, err := identity.ParseUserID(manager); err != nil {
		return errx.Validation("manager must reference a provisioned user id").WithDetail("scimType", "invalidValue")
	}
	return nil
}

// normalizeAliases lower-cases, validates and de-duplicates addresses and
// drops the primary one.
func normalizeAliases(primary string, list []provisioning.Email) ([]provisioning.Email, error) {
	out := []provisioning.Email{}
	seen := map[string]bool{primary: true}
	for _, alias := range list {
		email, err := identity.Email(alias.Value)
		if err != nil {
			return nil, errx.Validation("emails must contain valid addresses").WithDetail("scimType", "invalidValue")
		}
		if seen[email] {
			continue
		}
		seen[email] = true
		kind := strings.ToLower(strings.TrimSpace(alias.Type))
		if kind == "" || len(kind) > 32 {
			kind = "other"
		}
		out = append(out, provisioning.Email{Value: email, Type: kind})
	}
	return out, nil
}
