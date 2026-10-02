// Package eventsvc reads and prunes the event log.
package eventsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// pruneBatch bounds one pruning statement.
const pruneBatch = 5000

type Service struct {
	repository event.Repository
	retention  time.Duration
	now        func() time.Time
}

// New keeps events for retention (IAMKIT_EVENT_RETENTION).
func New(repository event.Repository, retention time.Duration) *Service {
	return &Service{repository: repository, retention: retention, now: time.Now}
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

func (s *Service) Prune(ctx context.Context) (bool, error) {
	n, err := s.repository.Prune(ctx, s.now().Add(-s.retention), pruneBatch)
	return n == pruneBatch, err
}

var (
	_ event.Queries  = (*Service)(nil)
	_ event.Commands = (*Service)(nil)
)
