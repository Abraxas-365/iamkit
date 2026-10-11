// Package auditlogsvc implements the app audit log use cases: the action
// catalog and the emit/read/prune of events.
package auditlogsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Actions manages the catalog of registered actions.
type Actions struct {
	repository auditlog.ActionRepository
	schemas    auditlog.SchemaValidator
}

func NewActions(repository auditlog.ActionRepository, schemas auditlog.SchemaValidator) *Actions {
	return &Actions{repository: repository, schemas: schemas}
}

var (
	_ auditlog.ActionCommands = (*Actions)(nil)
	_ auditlog.ActionQueries  = (*Actions)(nil)
)

// checkSchemas compiles every schema (remote references are refused).
func (s *Actions) checkSchemas(schema auditlog.Schema) error {
	for _, doc := range schema.Documents() {
		if err := s.schemas.Check(doc); err != nil {
			return err
		}
	}
	return nil
}

func (s *Actions) CreateAction(ctx context.Context, m auditlog.Mutation, input auditlog.ActionInput) (auditlog.Action, error) {
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return auditlog.Action{}, err
	}
	if err := s.checkSchemas(input.Schema); err != nil {
		return auditlog.Action{}, err
	}
	n, err := s.repository.CountActions(ctx, m.Environment)
	if err != nil {
		return auditlog.Action{}, err
	}
	if n >= auditlog.MaxActions {
		return auditlog.Action{}, errx.Business("an environment can register at most 500 audit log actions")
	}
	created := auditlog.Action{ID: identity.NewAuditActionID(), Environment: m.Environment, Name: input.Name,
		Description: input.Description, TargetTypes: input.TargetTypes, Schema: input.Schema, Version: 1}
	m.Target = created.ID.String()
	if err = s.repository.CreateAction(ctx, m, created); err != nil {
		return auditlog.Action{}, err
	}
	return s.repository.FindAction(ctx, m.Environment, created.ID)
}

func (s *Actions) UpdateAction(ctx context.Context, m auditlog.Mutation, id identity.AuditActionID, input auditlog.ActionUpdate) (auditlog.Action, error) {
	current, err := s.repository.FindAction(ctx, m.Environment, id)
	if err != nil {
		return auditlog.Action{}, err
	}
	next, rules, err := input.Apply(current)
	if err != nil {
		return auditlog.Action{}, err
	}
	if input.Schema != nil {
		if err = s.checkSchemas(next.Schema); err != nil {
			return auditlog.Action{}, err
		}
	}
	m.Target = id.String()
	if err = s.repository.UpdateAction(ctx, m, next, rules); err != nil {
		return auditlog.Action{}, err
	}
	return s.repository.FindAction(ctx, m.Environment, id)
}

func (s *Actions) DeleteAction(ctx context.Context, m auditlog.Mutation, id identity.AuditActionID) error {
	m.Target = id.String()
	return s.repository.DeleteAction(ctx, m, id)
}

func (s *Actions) ListActions(ctx context.Context, environment identity.EnvironmentID) ([]auditlog.Action, error) {
	return s.repository.ListActions(ctx, environment)
}

func (s *Actions) FindAction(ctx context.Context, environment identity.EnvironmentID, id identity.AuditActionID) (auditlog.Action, error) {
	return s.repository.FindAction(ctx, environment, id)
}
