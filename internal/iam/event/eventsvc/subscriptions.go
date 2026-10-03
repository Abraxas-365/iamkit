package eventsvc

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
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Dispatch tuning: subscriptions served per round and how long a claim
// holds (longer than one send, so a live sender never loses its row).
const (
	webhookBatch = 50
	webhookLease = time.Minute
)

// Subscriptions manages event webhook subscriptions and delivers their
// outbox.
type Subscriptions struct {
	repository event.SubscriptionRepository
	sender     event.Sender
	cipher     event.Cipher
	secrets    event.Secrets
	now        func() time.Time
}

var (
	_ event.SubscriptionCommands = (*Subscriptions)(nil)
	_ event.SubscriptionQueries  = (*Subscriptions)(nil)
	_ event.Dispatcher           = (*Subscriptions)(nil)
)

func NewSubscriptions(r event.SubscriptionRepository, sender event.Sender, cipher event.Cipher, secrets event.Secrets) *Subscriptions {
	return &Subscriptions{repository: r, sender: sender, cipher: cipher, secrets: secrets, now: time.Now}
}

// newSecret generates and seals a secret (422 ENCRYPTION_KEY_REQUIRED
// without IAMKIT_ENCRYPTION_KEY).
func (s *Subscriptions) newSecret() (plain, sealed string, err error) {
	plain, err = s.secrets.Generate()
	if err != nil {
		return "", "", err
	}
	sealed, err = s.cipher.Seal([]byte(plain))
	return plain, sealed, err
}

func (s *Subscriptions) CreateSubscription(ctx context.Context, m event.Mutation, input event.SubscriptionCreate) (event.SubscriptionSecret, error) {
	input.Name, input.URL = strings.TrimSpace(input.Name), strings.TrimSpace(input.URL)
	if input.Types == nil {
		input.Types = []string{}
	}
	if err := input.Validate(); err != nil {
		return event.SubscriptionSecret{}, err
	}
	n, err := s.repository.CountSubscriptions(ctx, m.Environment)
	if err != nil {
		return event.SubscriptionSecret{}, err
	}
	if n >= event.MaxSubscriptions {
		return event.SubscriptionSecret{}, errx.Business("an environment can have at most 25 webhook subscriptions")
	}
	plain, sealed, err := s.newSecret()
	if err != nil {
		return event.SubscriptionSecret{}, err
	}
	id := identity.NewSubscriptionID()
	m.Target = id.String()
	if err := s.repository.CreateSubscription(ctx, m, id, input, sealed); err != nil {
		return event.SubscriptionSecret{}, err
	}
	return event.SubscriptionSecret{ID: id, Secret: plain}, nil
}

func (s *Subscriptions) UpdateSubscription(ctx context.Context, m event.Mutation, subscription identity.SubscriptionID, input event.SubscriptionUpdate) error {
	if input.Name != nil {
		*input.Name = strings.TrimSpace(*input.Name)
	}
	if input.URL != nil {
		*input.URL = strings.TrimSpace(*input.URL)
	}
	if err := input.Validate(); err != nil {
		return err
	}
	m.Target = subscription.String()
	return s.repository.UpdateSubscription(ctx, m, subscription, input)
}

func (s *Subscriptions) DeleteSubscription(ctx context.Context, m event.Mutation, subscription identity.SubscriptionID) error {
	m.Target = subscription.String()
	return s.repository.DeleteSubscription(ctx, m, subscription)
}

func (s *Subscriptions) RotateSecret(ctx context.Context, m event.Mutation, subscription identity.SubscriptionID) (event.SubscriptionSecret, error) {
	plain, sealed, err := s.newSecret()
	if err != nil {
		return event.SubscriptionSecret{}, err
	}
	m.Target = subscription.String()
	if err := s.repository.RotateSecret(ctx, m, subscription, sealed, s.now().Add(config.EventWebhookSecretOverlap)); err != nil {
		return event.SubscriptionSecret{}, err
	}
	return event.SubscriptionSecret{ID: subscription, Secret: plain}, nil
}

func (s *Subscriptions) Replay(ctx context.Context, m event.Mutation, subscription identity.SubscriptionID, input event.Replay) (int, error) {
	if err := input.Validate(); err != nil {
		return 0, err
	}
	m.Target = subscription.String()
	return s.repository.Replay(ctx, m, subscription, input.From)
}

func (s *Subscriptions) RetryDelivery(ctx context.Context, m event.Mutation, subscription identity.SubscriptionID, delivery int64) error {
	if delivery <= 0 {
		return errx.NotFound("failed webhook delivery not found")
	}
	m.Target = subscription.String()
	return s.repository.RetryDelivery(ctx, m, subscription, delivery)
}

func (s *Subscriptions) TestSubscription(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID) (event.TestResult, error) {
	url, sealed, err := s.repository.SubscriptionSecrets(ctx, environment, subscription)
	if err != nil {
		return event.TestResult{}, err
	}
	secrets, err := s.open(sealed)
	if err != nil {
		return event.TestResult{}, err
	}
	e := event.Event{Environment: environment, Type: event.TestType, Actor: event.Actor{Kind: event.ActorSystem},
		Subject: event.Subject{Kind: "webhook", ID: subscription.String()}, Data: []byte(`{}`), OccurredAt: s.now().UTC()}
	out := s.sender.Send(ctx, event.Outbound{ID: "msg_test_" + strconv.FormatInt(s.now().UnixNano(), 36), URL: url, Secrets: secrets, Event: e})
	return event.TestResult{Delivered: out.OK(), Outcome: out}, nil
}

func (s *Subscriptions) open(sealed []string) ([]string, error) {
	out := make([]string, 0, len(sealed))
	for _, x := range sealed {
		plain, err := s.cipher.Open(x)
		if err != nil {
			return nil, errx.Wrap(err, "open webhook secret", errx.TypeInternal)
		}
		out = append(out, string(plain))
	}
	return out, nil
}

func (s *Subscriptions) ListSubscriptions(ctx context.Context, environment identity.EnvironmentID) ([]event.Subscription, error) {
	return s.repository.ListSubscriptions(ctx, environment)
}

func (s *Subscriptions) FindSubscription(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID) (event.Subscription, error) {
	return s.repository.FindSubscription(ctx, environment, subscription)
}

func (s *Subscriptions) ListDeliveries(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID, filter event.DeliveryFilter, page query.Pagination) (query.Paginated[event.Delivery], error) {
	if err := filter.Validate(); err != nil {
		return query.Paginated[event.Delivery]{}, err
	}
	if _, err := s.repository.FindSubscription(ctx, environment, subscription); err != nil {
		return query.Paginated[event.Delivery]{}, err
	}
	return s.repository.ListDeliveries(ctx, environment, subscription, filter, page)
}

// DispatchRound claims each due subscription's next delivery and sends
// them concurrently; more reports a full batch or a subscription whose
// head moved on (delivered or given up), whose next event may be due —
// otherwise a subscription would drain one event per interval.
func (s *Subscriptions) DispatchRound(ctx context.Context) (bool, error) {
	due, err := s.repository.ClaimDeliveries(ctx, webhookBatch, webhookLease)
	if err != nil {
		return false, err
	}
	var wg sync.WaitGroup
	var advanced atomic.Bool
	for _, m := range due {
		wg.Add(1)
		go func(m event.Message) {
			defer wg.Done()
			if s.deliver(ctx, m) {
				advanced.Store(true)
			}
		}(m)
	}
	wg.Wait()
	return len(due) == webhookBatch || advanced.Load(), nil
}

// deliver sends one delivery and records the outcome; it reports whether
// the delivery finished, so the subscription's next one can go.
func (s *Subscriptions) deliver(ctx context.Context, m event.Message) bool {
	var out event.Outcome
	if m.Event == nil {
		// Pruned before it could be delivered: nothing left to send.
		out = event.Outcome{Error: "the event was pruned before delivery"}
		if err := s.repository.GiveUp(ctx, m.Delivery, out); err != nil {
			slog.Error("record webhook delivery", "delivery", m.Delivery, "error", err)
			return false
		}
		return true
	}
	secrets, err := s.open(m.Secrets)
	if err != nil {
		out = event.Outcome{Error: "the subscription secret cannot be opened"}
	} else {
		out = s.sender.Send(ctx, event.Outbound{ID: "msg_" + strconv.FormatInt(m.Delivery, 10), URL: m.URL, Secrets: secrets, Event: *m.Event})
	}
	finished := true
	if out.OK() {
		err = s.repository.Delivered(ctx, m.Delivery, out)
	} else if ctx.Err() != nil {
		// Shutting down: the lease expires and another round retries.
		return false
	} else if wait, ok := event.DeliveryRetryAfter(m.Attempts, m.FirstAttempt, s.now(), config.EventWebhookRetryBase, config.EventWebhookRetryMax, config.EventWebhookRetryWindow); ok {
		slog.Warn("event webhook failed, will retry", "subscription", m.Subscription, "event", m.Event.ID, "attempt", m.Attempts, "error", out.Error)
		err = s.repository.RetryLater(ctx, m.Delivery, out, wait)
		finished = false
	} else {
		slog.Warn("event webhook given up", "subscription", m.Subscription, "event", m.Event.ID, "attempts", m.Attempts, "error", out.Error)
		err = s.repository.GiveUp(ctx, m.Delivery, out)
	}
	if err != nil {
		slog.Error("record webhook delivery", "delivery", m.Delivery, "error", err)
		return false
	}
	return finished
}

// Maintain disables subscriptions failing for
// config.EventWebhookDisableAfter and prunes old finished deliveries.
func (s *Subscriptions) Maintain(ctx context.Context) (bool, error) {
	n, err := s.repository.DisableFailing(ctx, s.now().Add(-config.EventWebhookDisableAfter))
	if err != nil {
		return false, err
	}
	if n > 0 {
		slog.Warn("event webhooks disabled after failing", "subscriptions", n)
	}
	return false, s.repository.PruneDeliveries(ctx, s.now().Add(-config.EventDeliveryRetention))
}

// Lag is how long the oldest due delivery has waited.
func (s *Subscriptions) Lag(ctx context.Context) (time.Duration, error) {
	return s.repository.DeliveryLag(ctx)
}
