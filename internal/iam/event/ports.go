package event

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Queries reads an environment's event log.
type Queries interface {
	// List returns up to limit events matching filter: oldest first after
	// filter.After (a feed cursor), else newest first.
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, limit int) (Page, error)
	// Export passes every event matching filter to write, oldest first
	// from filter.After (0 when nil), until write fails or the log ends.
	Export(ctx context.Context, environment identity.EnvironmentID, filter Filter, write func(Event) error) error
}

// Commands maintains the event log.
type Commands interface {
	// Prune deletes events older than the retention in batches; more asks
	// for another round.
	Prune(ctx context.Context) (more bool, err error)
}

// Repository persists and reads events (writers use eventpg in their own
// transactions).
type Repository interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, limit int) ([]Event, error)
	// Prune deletes at most batch events created before cutoff and returns
	// how many it deleted.
	Prune(ctx context.Context, cutoff time.Time, batch int) (int, error)
}

// SubscriptionCommands manages event webhook subscriptions.
type SubscriptionCommands interface {
	// CreateSubscription returns the signing secret, shown once.
	CreateSubscription(ctx context.Context, m Mutation, input SubscriptionCreate) (SubscriptionSecret, error)
	UpdateSubscription(ctx context.Context, m Mutation, subscription identity.SubscriptionID, input SubscriptionUpdate) error
	DeleteSubscription(ctx context.Context, m Mutation, subscription identity.SubscriptionID) error
	// RotateSecret issues a new secret; the old one keeps signing for
	// config.EventWebhookSecretOverlap.
	RotateSecret(ctx context.Context, m Mutation, subscription identity.SubscriptionID) (SubscriptionSecret, error)
	// Replay queues the matching events from input.From again and returns
	// how many.
	Replay(ctx context.Context, m Mutation, subscription identity.SubscriptionID, input Replay) (int, error)
	// RetryDelivery queues a failed delivery again.
	RetryDelivery(ctx context.Context, m Mutation, subscription identity.SubscriptionID, delivery int64) error
	// TestSubscription sends a synthetic webhook.test event now (not queued).
	TestSubscription(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID) (TestResult, error)
}

// SubscriptionQueries reads subscriptions and their delivery logs.
type SubscriptionQueries interface {
	ListSubscriptions(ctx context.Context, environment identity.EnvironmentID) ([]Subscription, error)
	FindSubscription(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID) (Subscription, error)
	ListDeliveries(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID, filter DeliveryFilter, page query.Pagination) (query.Paginated[Delivery], error)
}

// Dispatcher sends due deliveries (the event_webhook worker job; tests call
// it directly).
type Dispatcher interface {
	// DispatchRound sends one batch; more asks for another round at once.
	DispatchRound(ctx context.Context) (more bool, err error)
}

// SubscriptionRepository persists subscriptions and the delivery outbox.
type SubscriptionRepository interface {
	CountSubscriptions(ctx context.Context, environment identity.EnvironmentID) (int, error)
	CreateSubscription(ctx context.Context, m Mutation, subscription identity.SubscriptionID, input SubscriptionCreate, sealed string) error
	UpdateSubscription(ctx context.Context, m Mutation, subscription identity.SubscriptionID, input SubscriptionUpdate) error
	DeleteSubscription(ctx context.Context, m Mutation, subscription identity.SubscriptionID) error
	// RotateSecret stores sealed as the secret and keeps the current one
	// as previous until previousExpires.
	RotateSecret(ctx context.Context, m Mutation, subscription identity.SubscriptionID, sealed string, previousExpires time.Time) error
	ListSubscriptions(ctx context.Context, environment identity.EnvironmentID) ([]Subscription, error)
	FindSubscription(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID) (Subscription, error)
	// SubscriptionSecrets returns the sealed secrets that sign now.
	SubscriptionSecrets(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID) (url string, sealed []string, err error)
	Replay(ctx context.Context, m Mutation, subscription identity.SubscriptionID, from int64) (int, error)
	RetryDelivery(ctx context.Context, m Mutation, subscription identity.SubscriptionID, delivery int64) error
	ListDeliveries(ctx context.Context, environment identity.EnvironmentID, subscription identity.SubscriptionID, filter DeliveryFilter, page query.Pagination) (query.Paginated[Delivery], error)

	// ClaimDeliveries leases, for up to limit active subscriptions, the
	// oldest pending delivery when it is due (one per subscription, so
	// each receives its events in order) for lease.
	ClaimDeliveries(ctx context.Context, limit int, lease time.Duration) ([]Message, error)
	// Delivered records a success and clears the subscription's failure.
	Delivered(ctx context.Context, delivery int64, outcome Outcome) error
	// RetryLater records a failed attempt (starting the subscription's
	// failure clock) and schedules the next.
	RetryLater(ctx context.Context, delivery int64, outcome Outcome, wait time.Duration) error
	// GiveUp marks a delivery failed.
	GiveUp(ctx context.Context, delivery int64, outcome Outcome) error
	// DisableFailing disables (audited webhook.disabled) the active
	// subscriptions failing since before cutoff and returns how many.
	DisableFailing(ctx context.Context, cutoff time.Time) (int, error)
	// PruneDeliveries deletes finished deliveries older than cutoff.
	PruneDeliveries(ctx context.Context, cutoff time.Time) error
	// DeliveryLag is how long the oldest due delivery has waited.
	DeliveryLag(ctx context.Context) (time.Duration, error)
}

// Sender posts one signed webhook.
type Sender interface {
	Send(ctx context.Context, message Outbound) Outcome
}

// Cipher seals subscription secrets at rest.
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

// Secrets generates subscription secrets (whsec_ + base64 key).
type Secrets interface {
	Generate() (string, error)
}
