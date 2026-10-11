// Package logstreamsvc manages log streams and delivers their outbox.
package logstreamsvc

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Dispatch tuning: streams served per round and how long a claim holds
// (longer than one send, so a live sender never loses its batch).
const (
	dispatchStreams = 50
	dispatchLease   = 2 * time.Minute
)

// secretUnopened is the outcome when a stream secret was sealed with a key
// the server no longer has.
const secretUnopened = "the stream secret cannot be opened"

// Service implements logstream.Commands, Queries and Dispatcher.
type Service struct {
	repository logstream.Repository
	sender     logstream.Sender
	cipher     logstream.Cipher
	secrets    logstream.Secrets
	now        func() time.Time
}

var (
	_ logstream.Commands   = (*Service)(nil)
	_ logstream.Queries    = (*Service)(nil)
	_ logstream.Dispatcher = (*Service)(nil)
)

func New(r logstream.Repository, sender logstream.Sender, cipher logstream.Cipher, secrets logstream.Secrets) *Service {
	return &Service{repository: r, sender: sender, cipher: cipher, secrets: secrets, now: time.Now}
}

// organization is the organization a stream created under m belongs to:
// the scope's, or (operators) the one the input names.
func organization(m logstream.Mutation, input logstream.Create) (identity.OrganizationID, error) {
	if !m.Only {
		return input.Organization, nil
	}
	if m.Organization.IsZero() {
		return identity.OrganizationID{}, errx.NotFound("organization not found")
	}
	if !input.Organization.IsZero() && input.Organization != m.Organization {
		return identity.OrganizationID{}, errx.Validation("organization_id must be the organization of the request")
	}
	return m.Organization, nil
}

// target is the audit target of a stream: its id, or for an organization's
// stream /organizations/<org>/log-streams/<id>, so the audit row (trigger
// audit_event_context) belongs to the organization and its administrators
// read it in …/admin/events.
func target(org identity.OrganizationID, stream identity.LogStreamID) string {
	if org.IsZero() {
		return stream.String()
	}
	return "/organizations/" + org.String() + "/log-streams/" + stream.String()
}

func streamTarget(current logstream.Stream, stream identity.LogStreamID) string {
	if current.Organization == nil {
		return stream.String()
	}
	return target(*current.Organization, stream)
}

func (s *Service) Create(ctx context.Context, m logstream.Mutation, input logstream.Create) (logstream.Created, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Config = input.Config.Normalize()
	if err := input.Validate(); err != nil {
		return logstream.Created{}, err
	}
	org, err := organization(m, input)
	if err != nil {
		return logstream.Created{}, err
	}
	if input.Sources == nil {
		input.Sources = logstream.DefaultSources(!org.IsZero())
	}
	if err := logstream.CheckSources(input.Sources, !org.IsZero()); err != nil {
		return logstream.Created{}, err
	}
	n, err := s.repository.CountStreams(ctx, m.Environment, org)
	if err != nil {
		return logstream.Created{}, err
	}
	limit := logstream.MaxStreams
	if !org.IsZero() {
		limit = logstream.MaxOrganizationStreams
	}
	if n >= limit {
		return logstream.Created{}, errx.Business(limitMessage(!org.IsZero(), limit))
	}
	plain := input.Secret
	if input.Destination == logstream.DestinationHTTPS {
		if plain, err = s.secrets.Generate(); err != nil {
			return logstream.Created{}, err
		}
	}
	sealed, err := s.cipher.Seal([]byte(plain))
	if err != nil {
		return logstream.Created{}, err
	}
	id := identity.NewLogStreamID()
	m.Target = target(org, id)
	if err := s.repository.CreateStream(ctx, m, id, org, input, sealed); err != nil {
		return logstream.Created{}, err
	}
	out := logstream.Created{ID: id}
	if input.Destination == logstream.DestinationHTTPS {
		out.Secret = plain
	}
	return out, nil
}

func limitMessage(org bool, limit int) string {
	if org {
		return "an organization can have at most " + strconv.Itoa(limit) + " log streams"
	}
	return "an environment can have at most " + strconv.Itoa(limit) + " log streams"
}

func (s *Service) Update(ctx context.Context, m logstream.Mutation, stream identity.LogStreamID, input logstream.Update) error {
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		input.Name = &name
	}
	if err := input.Validate(); err != nil {
		return err
	}
	current, err := s.repository.FindStream(ctx, m.Scope, stream)
	if err != nil {
		return err
	}
	if input.Config != nil {
		cfg := input.Config.Normalize()
		if err := cfg.Validate(current.Destination); err != nil {
			return err
		}
		if input.Secret == nil && current.Config.Redirects(current.Destination, cfg) {
			return errx.Validation("secret is required when the destination's host, bucket, region or key id changes")
		}
		input.Config = &cfg
	}
	if input.Sources != nil {
		if err := logstream.CheckSources(*input.Sources, current.Organization != nil); err != nil {
			return err
		}
	}
	var sealed *string
	if input.Secret != nil {
		if current.Destination == logstream.DestinationHTTPS {
			return errx.Validation("https streams sign with a generated secret; rotate it instead")
		}
		x, err := s.cipher.Seal([]byte(*input.Secret))
		if err != nil {
			return err
		}
		sealed = &x
	}
	m.Target = streamTarget(current, stream)
	return s.repository.UpdateStream(ctx, m, stream, input, sealed)
}

func (s *Service) Delete(ctx context.Context, m logstream.Mutation, stream identity.LogStreamID) error {
	current, err := s.repository.FindStream(ctx, m.Scope, stream)
	if err != nil {
		return err
	}
	m.Target = streamTarget(current, stream)
	return s.repository.DeleteStream(ctx, m, stream)
}

func (s *Service) RotateSecret(ctx context.Context, m logstream.Mutation, stream identity.LogStreamID) (logstream.Created, error) {
	current, err := s.repository.FindStream(ctx, m.Scope, stream)
	if err != nil {
		return logstream.Created{}, err
	}
	if current.Destination != logstream.DestinationHTTPS {
		return logstream.Created{}, errx.Validation("only https streams have a signing secret to rotate")
	}
	plain, err := s.secrets.Generate()
	if err != nil {
		return logstream.Created{}, err
	}
	sealed, err := s.cipher.Seal([]byte(plain))
	if err != nil {
		return logstream.Created{}, err
	}
	m.Target = streamTarget(current, stream)
	if err := s.repository.RotateSecret(ctx, m, stream, sealed, s.now().Add(config.EventWebhookSecretOverlap)); err != nil {
		return logstream.Created{}, err
	}
	return logstream.Created{ID: stream, Secret: plain}, nil
}

func (s *Service) RetryDelivery(ctx context.Context, m logstream.Mutation, stream identity.LogStreamID, delivery int64) error {
	if delivery <= 0 {
		return errx.NotFound("failed log stream delivery not found")
	}
	current, err := s.repository.FindStream(ctx, m.Scope, stream)
	if err != nil {
		return err
	}
	m.Target = streamTarget(current, stream)
	return s.repository.RetryDelivery(ctx, m, stream, delivery)
}

// open opens the stream's sealed secrets. Only https streams sign with
// several; a previous secret sealed with a key the server dropped is left
// out (rotating is how a secret is re-sealed under a new key).
func (s *Service) open(sealed []string) ([]string, error) {
	out := make([]string, 0, len(sealed))
	for i, x := range sealed {
		plain, err := s.cipher.Open(x)
		if err != nil && i > 0 {
			slog.Warn("previous log stream secret cannot be opened; signing with the current one", "error", err)
			continue
		}
		if err != nil {
			return nil, errx.Wrap(err, "open log stream secret", errx.TypeInternal)
		}
		out = append(out, string(plain))
	}
	return out, nil
}

func (s *Service) Test(ctx context.Context, scope logstream.Scope, stream identity.LogStreamID) (logstream.TestResult, error) {
	current, err := s.repository.FindStream(ctx, scope, stream)
	if err != nil {
		return logstream.TestResult{}, err
	}
	sealed, err := s.repository.StreamSecrets(ctx, scope, stream)
	if err != nil {
		return logstream.TestResult{}, err
	}
	secrets, err := s.open(sealed)
	if err != nil {
		slog.WarnContext(ctx, "log stream test: secret cannot be opened", "stream", stream, "error", err)
		return logstream.TestResult{Outcome: logstream.Outcome{Error: secretUnopened}}, nil
	}
	now := s.now().UTC()
	out := s.sender.Send(ctx, logstream.Outbound{Stream: stream, Environment: current.Environment, Destination: current.Destination,
		Config: current.Config, Secrets: secrets, At: now, Test: true, Records: []logstream.Record{logstream.TestRecord(current, now)}})
	return logstream.TestResult{Delivered: out.OK(), Outcome: out}, nil
}

func (s *Service) List(ctx context.Context, scope logstream.Scope) ([]logstream.Stream, error) {
	return s.repository.ListStreams(ctx, scope)
}

func (s *Service) Find(ctx context.Context, scope logstream.Scope, stream identity.LogStreamID) (logstream.Stream, error) {
	return s.repository.FindStream(ctx, scope, stream)
}

func (s *Service) ListDeliveries(ctx context.Context, scope logstream.Scope, stream identity.LogStreamID, filter logstream.DeliveryFilter, page query.Pagination) (query.Paginated[logstream.Delivery], error) {
	if err := filter.Validate(); err != nil {
		return query.Paginated[logstream.Delivery]{}, err
	}
	if _, err := s.repository.FindStream(ctx, scope, stream); err != nil {
		return query.Paginated[logstream.Delivery]{}, err
	}
	return s.repository.ListDeliveries(ctx, scope, stream, filter, page)
}

// DispatchRound claims each due stream's next batch and sends them
// concurrently; more reports a full claim or a stream whose batch
// finished (delivered or given up), whose next one may be due — otherwise
// a backlog would drain one batch per interval.
func (s *Service) DispatchRound(ctx context.Context) (bool, error) {
	due, err := s.repository.ClaimBatches(ctx, dispatchStreams, dispatchLease)
	if err != nil {
		return false, err
	}
	var wg sync.WaitGroup
	var advanced atomic.Bool
	for _, b := range due {
		wg.Add(1)
		go func(b logstream.Batch) {
			defer wg.Done()
			if s.deliver(ctx, b) {
				advanced.Store(true)
			}
		}(b)
	}
	wg.Wait()
	return len(due) == dispatchStreams || advanced.Load(), nil
}

// deliver sends one batch and records the outcome; it reports whether the
// batch finished, so the stream's next one can go.
func (s *Service) deliver(ctx context.Context, b logstream.Batch) bool {
	var out logstream.Outcome
	secrets, err := s.open(b.Sealed)
	if err != nil {
		out = logstream.Outcome{Error: secretUnopened}
	} else {
		out = s.sender.Send(ctx, logstream.Outbound{Stream: b.Stream, Environment: b.Environment, Destination: b.Destination,
			Config: b.Config, Secrets: secrets, Batch: b.ID, At: b.At, Records: b.Records})
	}
	finished := true
	if out.OK() {
		err = s.repository.Delivered(ctx, b.Stream, b.Rows, out)
	} else if ctx.Err() != nil {
		// Shutting down: the lease expires and another round retries.
		return false
	} else if wait, ok := event.DeliveryRetryAfter(b.Attempts, b.FirstAttempt, s.now(), config.EventWebhookRetryBase, config.EventWebhookRetryMax, config.EventWebhookRetryWindow); ok {
		slog.Warn("log stream delivery failed, will retry", "stream", b.Stream, "batch", b.ID, "attempt", b.Attempts, "error", out.Error)
		err = s.repository.RetryLater(ctx, b.Stream, b.Rows, out, wait)
		finished = false
	} else {
		slog.Warn("log stream delivery given up", "stream", b.Stream, "batch", b.ID, "attempts", b.Attempts, "error", out.Error)
		err = s.repository.GiveUp(ctx, b.Stream, b.Rows, out)
	}
	if err != nil {
		slog.Error("record log stream delivery", "stream", b.Stream, "batch", b.ID, "error", err)
		return false
	}
	return finished
}

// Maintain disables streams failing for config.EventWebhookDisableAfter
// and prunes old finished deliveries.
func (s *Service) Maintain(ctx context.Context) (bool, error) {
	n, err := s.repository.DisableFailing(ctx, s.now().Add(-config.EventWebhookDisableAfter))
	if err != nil {
		return false, err
	}
	if n > 0 {
		slog.Warn("log streams disabled after failing", "streams", n)
	}
	return false, s.repository.PruneDeliveries(ctx, s.now().Add(-config.LogStreamDeliveryRetention))
}

// Lag is how long the oldest due delivery has waited.
func (s *Service) Lag(ctx context.Context) (time.Duration, error) {
	return s.repository.DeliveryLag(ctx)
}
