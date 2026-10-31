// Package eventsvc reads and prunes the event log.
package eventsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository event.Repository
	retention  event.RetentionRepository
	ceilings   event.Ceilings
	now        func() time.Time
}

// New keeps events up to the deployment ceilings (IAMKIT_EVENT_RETENTION,
// IAMKIT_SECURITY_EVENT_RETENTION); environments may shorten them.
func New(repository event.Repository, retention event.RetentionRepository, ceilings event.Ceilings) *Service {
	return &Service{repository: repository, retention: retention, ceilings: ceilings, now: time.Now}
}

func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, filter event.Filter, limit int) (event.Page, error) {
	if err := filter.Validate(); err != nil {
		return event.Page{}, err
	}
	limit = event.Limit(limit)
	items, err := s.repository.List(ctx, environment, filter, limit)
	if err != nil {
		return event.Page{}, err
	}
	page := event.Page{Items: items}
	switch {
	case filter.After != nil:
		page.Next = *filter.After
		if len(items) > 0 {
			page.Next = items[len(items)-1].ID
		}
	case len(items) == limit:
		page.Next = items[len(items)-1].ID
	}
	return page, nil
}

func (s *Service) Export(ctx context.Context, environment identity.EnvironmentID, filter event.Filter, write func(event.Event) error) error {
	if filter.Before != 0 {
		return errx.Validation("export reads forward: use after, not before")
	}
	after := int64(0)
	if filter.After != nil {
		after = *filter.After
	}
	filter.After = &after
	if err := filter.Validate(); err != nil {
		return err
	}
	for {
		items, err := s.repository.List(ctx, environment, filter, event.ExportBatch)
		if err != nil {
			return err
		}
		for _, e := range items {
			if err := write(e); err != nil {
				return err
			}
		}
		if len(items) < event.ExportBatch {
			return nil
		}
		after = items[len(items)-1].ID
	}
}

// Prune deletes, for every environment and class, one batch of events
// older than the effective retention. A full batch asks for another round.
func (s *Service) Prune(ctx context.Context) (bool, error) {
	environments, err := s.repository.Environments(ctx)
	if err != nil {
		return false, err
	}
	now := s.now()
	more := false
	for _, e := range environments {
		for _, class := range event.Classes {
			n, err := s.repository.Prune(ctx, e.Environment, class, now.Add(-e.Policy.Effective(s.ceilings, class)), event.PruneBatch)
			if err != nil {
				return false, err
			}
			more = more || n >= event.PruneBatch
		}
	}
	return more, nil
}

func (s *Service) Retention(ctx context.Context, environment identity.EnvironmentID) (event.Retention, error) {
	policy, err := s.retention.Policy(ctx, environment)
	if err != nil {
		return event.Retention{}, err
	}
	return policy.Describe(s.ceilings), nil
}

func (s *Service) SetRetention(ctx context.Context, m event.Mutation, input event.RetentionPolicy) (event.Retention, error) {
	if m.Environment.IsZero() {
		return event.Retention{}, errx.Validation("environment_id is required")
	}
	if !m.Owner {
		return event.Retention{}, errx.Forbidden("only workspace owners may change the event retention")
	}
	if err := input.Validate(s.ceilings); err != nil {
		return event.Retention{}, err
	}
	if err := s.retention.SavePolicy(ctx, m, input); err != nil {
		return event.Retention{}, err
	}
	return input.Describe(s.ceilings), nil
}

var (
	_ event.Queries           = (*Service)(nil)
	_ event.Commands          = (*Service)(nil)
	_ event.RetentionQueries  = (*Service)(nil)
	_ event.RetentionCommands = (*Service)(nil)
)
