package logstream

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Commands manages log streams. Every method takes the scope of the
// caller (Mutation embeds it): an environment scope reaches every stream of
// the environment, an organization scope only that organization's, and a
// stream outside the scope is NotFound.
type Commands interface {
	// Create returns the https signing secret, shown once.
	Create(ctx context.Context, m Mutation, input Create) (Created, error)
	Update(ctx context.Context, m Mutation, stream identity.LogStreamID, input Update) error
	Delete(ctx context.Context, m Mutation, stream identity.LogStreamID) error
	// RotateSecret issues a new https signing secret; the old one keeps
	// signing for config.EventWebhookSecretOverlap.
	RotateSecret(ctx context.Context, m Mutation, stream identity.LogStreamID) (Created, error)
	// RetryDelivery queues a failed delivery (its whole batch) again.
	RetryDelivery(ctx context.Context, m Mutation, stream identity.LogStreamID, delivery int64) error
	// Test sends one synthetic record to the destination now (not queued).
	Test(ctx context.Context, scope Scope, stream identity.LogStreamID) (TestResult, error)
}

// Queries reads streams and their delivery logs.
type Queries interface {
	List(ctx context.Context, scope Scope) ([]Stream, error)
	Find(ctx context.Context, scope Scope, stream identity.LogStreamID) (Stream, error)
	ListDeliveries(ctx context.Context, scope Scope, stream identity.LogStreamID, filter DeliveryFilter, page query.Pagination) (query.Paginated[Delivery], error)
}

// Dispatcher sends due batches (the log_stream_delivery worker job; tests
// call it directly).
type Dispatcher interface {
	// DispatchRound sends one batch per due stream; more asks for another
	// round at once.
	DispatchRound(ctx context.Context) (more bool, err error)
}

// Repository persists streams and the delivery outbox (rows are queued by
// triggers on events and audit_log_events). Every method that takes a scope
// filters by it in SQL.
type Repository interface {
	// CountStreams counts the environment's own streams, or an
	// organization's when organization is set.
	CountStreams(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (int, error)
	CreateStream(ctx context.Context, m Mutation, stream identity.LogStreamID, organization identity.OrganizationID, input Create, sealed string) error
	// UpdateStream changes the fields that are set; sealed replaces the
	// secret. Active true clears the failure and makes queued rows due.
	UpdateStream(ctx context.Context, m Mutation, stream identity.LogStreamID, input Update, sealed *string) error
	DeleteStream(ctx context.Context, m Mutation, stream identity.LogStreamID) error
	// RotateSecret stores sealed as the secret and keeps the current one
	// as previous until previousExpires.
	RotateSecret(ctx context.Context, m Mutation, stream identity.LogStreamID, sealed string, previousExpires time.Time) error
	ListStreams(ctx context.Context, scope Scope) ([]Stream, error)
	FindStream(ctx context.Context, scope Scope, stream identity.LogStreamID) (Stream, error)
	// StreamSecrets returns the sealed secrets that sign now.
	StreamSecrets(ctx context.Context, scope Scope, stream identity.LogStreamID) ([]string, error)
	RetryDelivery(ctx context.Context, m Mutation, stream identity.LogStreamID, delivery int64) error
	ListDeliveries(ctx context.Context, scope Scope, stream identity.LogStreamID, filter DeliveryFilter, page query.Pagination) (query.Paginated[Delivery], error)

	// ClaimBatches leases, for up to limit active streams, the stream's
	// oldest pending batch when it is due (one per stream, so records go
	// out in order) for lease. A batch keeps its rows across retries;
	// records pruned before delivery are marked failed.
	ClaimBatches(ctx context.Context, limit int, lease time.Duration) ([]Batch, error)
	// Delivered records a success and clears the stream's failure.
	Delivered(ctx context.Context, stream identity.LogStreamID, rows []int64, outcome Outcome) error
	// RetryLater records a failed attempt (starting the stream's failure
	// clock) and schedules the next.
	RetryLater(ctx context.Context, stream identity.LogStreamID, rows []int64, outcome Outcome, wait time.Duration) error
	// GiveUp marks the batch failed.
	GiveUp(ctx context.Context, stream identity.LogStreamID, rows []int64, outcome Outcome) error
	// DisableFailing disables (event log_stream.disabled) the active streams
	// failing since before cutoff and returns how many.
	DisableFailing(ctx context.Context, cutoff time.Time) (int, error)
	// PruneDeliveries fails what waited on a disabled stream since before
	// cutoff (BacklogExpired) and deletes finished deliveries older than it.
	PruneDeliveries(ctx context.Context, cutoff time.Time) error
	// DeliveryLag is how long the oldest due delivery has waited.
	DeliveryLag(ctx context.Context) (time.Duration, error)
}

// Sender delivers one batch to one kind of destination.
type Sender interface {
	Send(ctx context.Context, batch Outbound) Outcome
}

// Cipher seals stream secrets at rest (implemented by cryptox.Sealer:
// without IAMKIT_ENCRYPTION_KEY it answers 422 ENCRYPTION_KEY_REQUIRED).
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

// Secrets generates https signing secrets (whsec_ + base64 key).
type Secrets interface {
	Generate() (string, error)
}
