package usersvc

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository user.Repository
	passwords  user.PasswordHasher
	policy     user.PasswordPolicy // nil checks only the length
	schemas    user.SchemaValidator
	actions    user.Actions
	quota      user.Quota
}

// SetQuota enforces the environment's users limit on Create.
func (s *Service) SetQuota(q user.Quota) { s.quota = q }

func New(repository user.Repository, passwords user.PasswordHasher, schemas user.SchemaValidator) *Service {
	return &Service{repository: repository, passwords: passwords, schemas: schemas}
}

// SetPasswordPolicy makes new passwords follow the environment's policy.
func (s *Service) SetPasswordPolicy(p user.PasswordPolicy) { s.policy = p }

func (s *Service) Create(ctx context.Context, environment identity.EnvironmentID, input user.Create) (identity.UserID, error) {
	if err := input.Validate(); err != nil {
		return identity.UserID{}, err
	}
	if s.quota != nil {
		if err := s.quota.Admit(ctx, environment, usage.LimitUsers); err != nil {
			return identity.UserID{}, err
		}
	}
	input, err := s.beforeCreate(ctx, environment, input)
	if err != nil {
		return identity.UserID{}, err
	}
	if input.Kind == user.KindMachine {
		input.AvatarURL, _ = identity.AvatarURL(input.AvatarURL) // validated
		return s.repository.Create(ctx, environment, input, "")
	}
	input.Kind = user.KindHuman
	email, err := identity.Email(input.Email)
	if err != nil {
		return identity.UserID{}, errx.Validation("valid email required")
	}
	input.Email = email
	input.AvatarURL, _ = identity.AvatarURL(input.AvatarURL) // validated
	input.Username, _ = identity.Username(input.Username)
	var hash string
	if input.Password != "" {
		if err = s.checkPassword(ctx, environment, input.Password); err != nil {
			return identity.UserID{}, err
		}
		hash, err = s.passwords.Hash(input.Password)
		if err != nil {
			return identity.UserID{}, err
		}
	}
	input.Password = ""
	return s.repository.Create(ctx, environment, input, hash)
}

func (s *Service) checkPassword(ctx context.Context, environment identity.EnvironmentID, password string) error {
	if s.policy != nil {
		return s.policy.CheckPassword(ctx, environment, password)
	}
	if len(password) < config.PasswordMinLength {
		return errx.Validation("password must be 12-72 characters long")
	}
	return nil
}
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, filter user.Filter, page query.Pagination) (query.Paginated[user.User], error) {
	if err := filter.Validate(); err != nil {
		return query.Paginated[user.User]{}, err
	}
	return s.repository.List(ctx, environment, filter, page)
}
func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) (user.User, error) {
	if id.IsZero() {
		return user.User{}, errx.NotFound("resource not found")
	}
	return s.repository.Find(ctx, environment, id)
}
func (s *Service) Update(ctx context.Context, mutation user.Mutation, id identity.UserID, input user.Update) error {
	if id.IsZero() {
		return errx.Validation("invalid user update")
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return err
	}
	input, err := s.beforeUpdate(ctx, mutation.Environment, id, input)
	if err != nil {
		return err
	}
	if input.Phone != nil || input.PhoneVerified != nil || input.Username != nil || input.OTPEnabled != nil {
		current, err := s.repository.Find(ctx, mutation.Environment, id)
		if err != nil {
			return err
		}
		if current.Kind == user.KindMachine && ((input.Phone != nil && *input.Phone != "") || (input.PhoneVerified != nil && *input.PhoneVerified) || (input.Username != nil && *input.Username != "") || (input.OTPEnabled != nil && *input.OTPEnabled)) {
			return errx.Validation("machine users have no phone, username or second factor")
		}
	}
	return s.repository.Update(ctx, mutation, id, input)
}
func (s *Service) Deactivate(ctx context.Context, m user.Mutation, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	m.Action = user.ActionDeactivated
	return s.repository.SetActive(ctx, m, id, false)
}
func (s *Service) Reactivate(ctx context.Context, m user.Mutation, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	m.Action = user.ActionReactivated
	return s.repository.SetActive(ctx, m, id, true)
}
func (s *Service) Delete(ctx context.Context, m user.Mutation, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.Delete(ctx, m, id)
}
func (s *Service) Unlock(ctx context.Context, m user.Mutation, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	m.Action = user.ActionUnlocked
	return s.repository.Unlock(ctx, m, id)
}

func (s *Service) Metadata(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, key string) (json.RawMessage, error) {
	if err := identity.MetadataKey(key); err != nil {
		return nil, err
	}
	u, err := s.Find(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	value, ok := identity.MetadataValue(u.Metadata, key)
	if !ok {
		return nil, errx.NotFound("metadata key not found")
	}
	return value, nil
}

func (s *Service) SetMetadata(ctx context.Context, m user.Mutation, id identity.UserID, key string, value json.RawMessage) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	if err := identity.MetadataKey(key); err != nil {
		return err
	}
	m.Action = user.ActionMetadataSet
	return s.repository.EditMetadata(ctx, m, id, func(current json.RawMessage) (json.RawMessage, error) {
		return identity.SetMetadata(current, key, value)
	})
}

func (s *Service) DeleteMetadata(ctx context.Context, m user.Mutation, id identity.UserID, key string) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	if err := identity.MetadataKey(key); err != nil {
		return err
	}
	m.Action = user.ActionMetadataDeleted
	return s.repository.EditMetadata(ctx, m, id, func(current json.RawMessage) (json.RawMessage, error) {
		out, found, err := identity.DeleteMetadata(current, key)
		if err == nil && !found {
			err = errx.NotFound("metadata key not found")
		}
		return out, err
	})
}

// patchProfile merges patch into current (limited to allowed keys when
// not nil) and checks the result against schema.
func (s *Service) patchProfile(current, patch json.RawMessage, schema user.Schema, allowed []string) (json.RawMessage, error) {
	next, err := user.MergeProfile(current, patch, allowed)
	if err != nil {
		return nil, err
	}
	if schema.Version > 0 {
		if err = s.schemas.Validate(schema.Schema, next); err != nil {
			return nil, err
		}
	}
	return next, nil
}

func (s *Service) UpdateProfile(ctx context.Context, m user.Mutation, id identity.UserID, patch json.RawMessage) (json.RawMessage, error) {
	if id.IsZero() {
		return nil, errx.NotFound("resource not found")
	}
	m.Action = user.ActionProfileUpdated
	return s.repository.EditProfile(ctx, m, id, func(current json.RawMessage, schema user.Schema) (json.RawMessage, error) {
		return s.patchProfile(current, patch, schema, nil)
	})
}

func (s *Service) UpdateOwnProfile(ctx context.Context, m user.Mutation, id identity.UserID, patch json.RawMessage) (map[string]json.RawMessage, error) {
	var visible []string
	m.Action = user.ActionProfileUpdated
	profile, err := s.repository.EditProfile(ctx, m, id, func(current json.RawMessage, schema user.Schema) (json.RawMessage, error) {
		if schema.Version == 0 {
			return nil, errx.Forbidden("the environment has no user schema")
		}
		properties, err := user.Properties(schema.Schema)
		if err != nil {
			return nil, err
		}
		writable := []string{}
		for _, p := range properties {
			if p.Self != "" {
				visible = append(visible, p.Name)
			}
			if p.Self == user.SelfWrite {
				writable = append(writable, p.Name)
			}
		}
		return s.patchProfile(current, patch, schema, writable)
	})
	if err != nil {
		return nil, err
	}
	return user.PickProfile(profile, visible), nil
}

func (s *Service) Schema(ctx context.Context, environment identity.EnvironmentID) (user.Schema, error) {
	return s.repository.Schema(ctx, environment)
}

func (s *Service) SaveSchema(ctx context.Context, m user.Mutation, schema json.RawMessage) (user.SchemaSaved, error) {
	if len(schema) > identity.MetadataMaxSize*2 {
		return user.SchemaSaved{}, errx.Validation("schema must be at most 64 KiB")
	}
	if _, err := user.Properties(schema); err != nil {
		return user.SchemaSaved{}, err
	}
	if err := s.schemas.Check(schema); err != nil {
		return user.SchemaSaved{}, err
	}
	m.Action = user.ActionSchemaUpdated
	saved, err := s.repository.SaveSchema(ctx, m, schema)
	if err != nil {
		return user.SchemaSaved{}, err
	}
	profiles, err := s.repository.Profiles(ctx, m.Environment)
	if err != nil {
		return user.SchemaSaved{}, err
	}
	out := user.SchemaSaved{Schema: saved}
	for _, row := range profiles {
		if s.schemas.Validate(saved.Schema, row.Profile) != nil {
			out.NonConforming++
		}
	}
	return out, nil
}

func (s *Service) DeleteSchema(ctx context.Context, m user.Mutation) error {
	m.Action = user.ActionSchemaDeleted
	return s.repository.DeleteSchema(ctx, m)
}

// annotated returns the profile and schema properties of a user.
func (s *Service) annotated(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) (json.RawMessage, []user.Property, error) {
	schema, err := s.repository.Schema(ctx, environment)
	if err != nil || schema.Version == 0 {
		return nil, nil, err
	}
	properties, err := user.Properties(schema.Schema)
	if err != nil {
		return nil, nil, err
	}
	profile, err := s.repository.Profile(ctx, environment, id)
	return profile, properties, err
}

func (s *Service) OwnProfile(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) (map[string]json.RawMessage, error) {
	profile, properties, err := s.annotated(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for _, p := range properties {
		if p.Self != "" {
			keys = append(keys, p.Name)
		}
	}
	return user.PickProfile(profile, keys), nil
}

func (s *Service) Claims(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, scopes []string) (map[string]json.RawMessage, error) {
	profileScope, phoneScope := slices.Contains(scopes, "profile"), slices.Contains(scopes, "phone")
	out := map[string]json.RawMessage{}
	if !profileScope && !phoneScope {
		return out, nil
	}
	found, err := s.repository.Find(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	if phoneScope && found.Phone != "" {
		out["phone_number"], _ = json.Marshal(found.Phone)
		out["phone_number_verified"], _ = json.Marshal(found.PhoneVerified)
	}
	if !profileScope {
		return out, nil
	}
	profile, properties, err := s.annotated(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	if found.AvatarURL != "" {
		out["picture"], _ = json.Marshal(found.AvatarURL)
	}
	if found.Username != "" {
		out["preferred_username"], _ = json.Marshal(found.Username)
	}
	all := map[string]json.RawMessage{}
	_ = json.Unmarshal(profile, &all)
	for _, p := range properties {
		if value, ok := all[p.Name]; ok && p.Claim != "" {
			out[p.Claim] = value
		}
	}
	return out, nil
}

var _ user.Commands = (*Service)(nil)
var _ user.Queries = (*Service)(nil)
