package oauthsvc

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Dispatch tuning: rows claimed per round and how long a claim holds
// (longer than one send, so a live sender never loses its rows).
const (
	logoutBatch = 20
	logoutLease = 2 * time.Minute
	// logoutRetention keeps finished notifications visible to operators.
	logoutRetention = 7 * 24 * time.Hour
)

// Logouts delivers back-channel logout notifications from the outbox and
// serves their log to operators.
type Logouts struct {
	repository oauth.LogoutRepository
	sender     oauth.LogoutSender
}

var (
	_ oauth.LogoutCommands = (*Logouts)(nil)
	_ oauth.LogoutQueries  = (*Logouts)(nil)
	_ oauth.Dispatcher     = (*Logouts)(nil)
)

func NewLogouts(r oauth.LogoutRepository, s oauth.LogoutSender) *Logouts {
	return &Logouts{repository: r, sender: s}
}

// DispatchLogouts claims one batch of due notifications and sends them
// concurrently; a failed send is retried with backoff, then given up and
// audited.
func (l *Logouts) DispatchLogouts(ctx context.Context) (int, error) {
	due, err := l.repository.ClaimLogouts(ctx, logoutBatch, logoutLease)
	if err != nil {
		return 0, err
	}
	var wg sync.WaitGroup
	for _, n := range due {
		wg.Add(1)
		go func(n oauth.LogoutNotification) {
			defer wg.Done()
			l.deliver(ctx, n)
		}(n)
	}
	wg.Wait()
	return len(due), nil
}

func (l *Logouts) deliver(ctx context.Context, n oauth.LogoutNotification) {
	var err error
	if n.URI == "" {
		err = errx.Business("the client no longer has a back-channel logout URI")
	} else {
		err = l.sender.Send(ctx, n)
	}
	if err == nil {
		if err = l.repository.LogoutDelivered(ctx, n.ID); err != nil {
			slog.Error("record back-channel logout delivery", "notification", n.ID, "error", err)
		}
		return
	}
	if ctx.Err() != nil {
		// Shutting down: the lease expires and another round retries.
		return
	}
	reason := err.Error()
	if wait, ok := oauth.RetryAfter(n.Attempts); ok && n.URI != "" {
		slog.Warn("back-channel logout failed, will retry", "client", n.Client, "attempt", n.Attempts, "error", reason)
		err = l.repository.LogoutRetry(ctx, n.ID, wait, reason)
	} else {
		slog.Warn("back-channel logout given up", "client", n.Client, "attempts", n.Attempts, "error", reason)
		m := oauth.Mutation{Environment: n.Environment, Actor: n.Subject.String(), Action: oauth.ActionBackchannelFailed, Target: n.Client.String()}
		err = l.repository.LogoutFailed(ctx, m, n.ID, reason)
	}
	if err != nil {
		slog.Error("record back-channel logout failure", "notification", n.ID, "error", err)
	}
}

// DispatchRound sends one batch; more reports a full batch (call again).
func (l *Logouts) DispatchRound(ctx context.Context) (bool, error) {
	n, err := l.DispatchLogouts(ctx)
	return n == logoutBatch, err
}

// Prune deletes finished notifications past their retention.
func (l *Logouts) Prune(ctx context.Context) (bool, error) {
	return false, l.repository.PruneLogouts(ctx, logoutRetention)
}

// Lag is how long the oldest due notification has waited.
func (l *Logouts) Lag(ctx context.Context) (time.Duration, error) {
	return l.repository.LogoutLag(ctx)
}

func (l *Logouts) RetryLogout(ctx context.Context, m oauth.Mutation, notification int64) error {
	if notification <= 0 {
		return errx.NotFound("failed logout delivery not found")
	}
	return l.repository.RetryLogout(ctx, m, notification)
}

func (l *Logouts) LogoutDeliveries(ctx context.Context, environment identity.EnvironmentID, filter oauth.LogoutFilter, page query.Pagination) (query.Paginated[oauth.LogoutDelivery], error) {
	if err := filter.Validate(); err != nil {
		return query.Paginated[oauth.LogoutDelivery]{}, err
	}
	return l.repository.LogoutDeliveries(ctx, environment, filter, page)
}
