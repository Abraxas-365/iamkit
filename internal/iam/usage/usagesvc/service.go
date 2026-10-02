// Package usagesvc enforces environment limits and keeps daily usage.
package usagesvc

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type key struct {
	environment identity.EnvironmentID
	day         time.Time
	metric      string
}

type cached struct {
	values  usage.Values
	expires time.Time
}

type Service struct {
	repository usage.Repository
	window     usage.Window
	deployment usage.Values
	now        func() time.Time

	mu      sync.Mutex
	pending map[key]int64
	limits  map[identity.EnvironmentID]cached
}

var (
	_ usage.Commands = (*Service)(nil)
	_ usage.Queries  = (*Service)(nil)
)

// New meters through repository; window counts per-minute limits;
// deployment holds IAMKIT_LIMITS.
func New(repository usage.Repository, window usage.Window, deployment usage.Values) *Service {
	if deployment == nil {
		deployment = usage.Values{}
	}
	return &Service{repository: repository, window: window, deployment: deployment, now: time.Now,
		pending: map[key]int64{}, limits: map[identity.EnvironmentID]cached{}}
}

func (s *Service) Limits(ctx context.Context, environment identity.EnvironmentID) (usage.Limits, error) {
	if environment.IsZero() {
		return usage.Limits{}, errx.Validation("environment_id is required")
	}
	stored, err := s.repository.Limits(ctx, environment)
	if err != nil {
		return usage.Limits{}, err
	}
	if stored.Values == nil {
		stored.Values = usage.Values{}
	}
	return usage.Limits{Deployment: s.deployment, Environment: stored.Values, Effective: s.deployment.Tighten(stored.Values), UpdatedAt: stored.UpdatedAt}, nil
}

func (s *Service) SetLimits(ctx context.Context, m usage.Mutation, input usage.Set) (usage.Limits, error) {
	if m.Environment.IsZero() {
		return usage.Limits{}, errx.Validation("environment_id is required")
	}
	if !m.Owner {
		return usage.Limits{}, errx.Forbidden("only workspace owners may change limits")
	}
	values := input.Values()
	if err := values.Validate(); err != nil {
		return usage.Limits{}, err
	}
	for name := range input {
		if _, ok := usage.Find(name); !ok {
			return usage.Limits{}, errx.Validation("unknown limit " + strconv.Quote(name))
		}
	}
	if err := s.repository.SaveLimits(ctx, m, values); err != nil {
		return usage.Limits{}, err
	}
	s.mu.Lock()
	delete(s.limits, m.Environment)
	s.mu.Unlock()
	return s.Limits(ctx, m.Environment)
}

// effective is the environment's effective limits, cached for
// config.UsageLimitCacheTTL (another replica's change applies within it).
func (s *Service) effective(ctx context.Context, environment identity.EnvironmentID) (usage.Values, error) {
	now := s.now()
	s.mu.Lock()
	c, ok := s.limits[environment]
	s.mu.Unlock()
	if ok && now.Before(c.expires) {
		return c.values, nil
	}
	stored, err := s.repository.Limits(ctx, environment)
	if err != nil {
		return nil, err
	}
	values := s.deployment.Tighten(stored.Values)
	s.mu.Lock()
	s.limits[environment] = cached{values: values, expires: now.Add(config.UsageLimitCacheTTL)}
	s.mu.Unlock()
	return values, nil
}

func (s *Service) Admit(ctx context.Context, environment identity.EnvironmentID, name string) error {
	limit, ok := usage.Find(name)
	if !ok {
		return errx.Internal("unknown limit " + name)
	}
	values, err := s.effective(ctx, environment)
	if err != nil {
		return err
	}
	max, limited := values.Max(name)
	if !limited {
		return nil
	}
	switch limit.Kind {
	case usage.KindTotal:
		n, err := s.repository.Total(ctx, environment, name)
		if err != nil {
			return err
		}
		if n >= max {
			return usage.ErrExceeded(limit, max)
		}
	case usage.KindDaily:
		day := usage.UTCDay(s.now())
		n, err := s.repository.Daily(ctx, environment, limit.Metric, day)
		if err != nil {
			return err
		}
		s.mu.Lock()
		n += s.pending[key{environment, day, limit.Metric}]
		s.mu.Unlock()
		if n >= max {
			return usage.ErrExceeded(limit, max)
		}
	case usage.KindPerMinute:
		within, err := s.window.Take(ctx, environment.String()+":"+name, max, time.Minute)
		if err != nil {
			// Fail open: a broken shared counter must not stop sign-ins.
			slog.WarnContext(ctx, "usage window unavailable", "limit", name, "err", err)
			return nil
		}
		if !within {
			return usage.ErrExceeded(limit, max)
		}
	}
	return nil
}

func (s *Service) Count(_ context.Context, environment identity.EnvironmentID, metric string, n int64) {
	if environment.IsZero() || n <= 0 {
		return
	}
	s.mu.Lock()
	s.pending[key{environment, usage.UTCDay(s.now()), metric}] += n
	s.mu.Unlock()
}

// Flush writes the pending counts; on failure they are kept for the next
// flush.
func (s *Service) Flush(ctx context.Context) error {
	s.mu.Lock()
	batch := s.pending
	s.pending = map[key]int64{}
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	increments := make([]usage.Increment, 0, len(batch))
	for k, n := range batch {
		increments = append(increments, usage.Increment{Environment: k.environment, Day: k.day, Metric: k.metric, Count: n})
	}
	if err := s.repository.Add(ctx, increments); err != nil {
		s.mu.Lock()
		for k, n := range batch {
			s.pending[k] += n
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Service) Rollup(ctx context.Context) (bool, error) {
	n, err := s.repository.Rollup(ctx, s.now().Add(-config.UsageRollupSettle), config.UsageRollupBatch)
	return n == config.UsageRollupBatch, err
}

func (s *Service) Prune(ctx context.Context) error {
	return s.repository.Prune(ctx, s.now().Add(-config.UsageRetention))
}

func (s *Service) Report(ctx context.Context, environment identity.EnvironmentID, days int) (usage.Report, error) {
	if environment.IsZero() {
		return usage.Report{}, errx.Validation("environment_id is required")
	}
	if days < 1 || days > usage.MaxDays {
		return usage.Report{}, errx.Validation("days must be between 1 and " + strconv.Itoa(usage.MaxDays))
	}
	today := usage.UTCDay(s.now())
	from := today.AddDate(0, 0, 1-days)
	stored, err := s.repository.Days(ctx, environment, from)
	if err != nil {
		return usage.Report{}, err
	}
	out := usage.Report{Days: make([]usage.Day, days), Totals: map[string]int64{}}
	index := map[string]int{}
	for i := range out.Days {
		day := from.AddDate(0, 0, i).Format(time.DateOnly)
		index[day] = i
		out.Days[i] = usage.Day{Day: day, Metrics: map[string]int64{}}
		for _, m := range usage.Metrics {
			out.Days[i].Metrics[m] = 0
		}
	}
	add := func(day time.Time, metric string, n int64) {
		if i, ok := index[day.Format(time.DateOnly)]; ok {
			out.Days[i].Metrics[metric] += n
			out.Totals[metric] += n
		}
	}
	for _, x := range stored {
		add(x.Day, x.Metric, x.Count)
	}
	s.mu.Lock()
	for k, n := range s.pending {
		if k.environment == environment {
			add(k.day, k.metric, n)
		}
	}
	s.mu.Unlock()
	for _, m := range usage.Metrics {
		out.Totals[m] += 0
	}
	values, err := s.effective(ctx, environment)
	if err != nil {
		return usage.Report{}, err
	}
	for _, limit := range usage.Catalog {
		if limit.Kind != usage.KindTotal {
			continue
		}
		n, err := s.repository.Total(ctx, environment, limit.Name)
		if err != nil {
			return usage.Report{}, err
		}
		total := usage.Total{Name: limit.Name, Count: n}
		if max, ok := values.Max(limit.Name); ok {
			total.Max = &max
		}
		out.Now = append(out.Now, total)
	}
	return out, nil
}
