package usage

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Commands change limits and meter the environment.
type Commands interface {
	// SetLimits replaces the environment's limits (audited limits.updated).
	SetLimits(ctx context.Context, m Mutation, input Set) (Limits, error)
	// Admit checks one limit before the work it bounds: totals count what
	// exists (422), daily limits read today's usage (429) and per-minute
	// limits take one slot of the current minute (429). Unlimited is free.
	Admit(ctx context.Context, environment identity.EnvironmentID, limit string) error
	// Count adds n to today's metric. Counts are kept in memory and
	// written by Flush; it never fails.
	Count(ctx context.Context, environment identity.EnvironmentID, metric string, n int64)
	// Flush writes the counts kept in memory.
	Flush(ctx context.Context) error
	// Rollup adds a batch of settled events (sign-ins, created users) to
	// the daily usage; more asks for another batch at once.
	Rollup(ctx context.Context) (more bool, err error)
	// Prune removes daily usage older than config.UsageRetention.
	Prune(ctx context.Context) error
}

// Queries read limits and usage.
type Queries interface {
	Limits(ctx context.Context, environment identity.EnvironmentID) (Limits, error)
	// Report is the usage of the last days (1 to MaxDays, today included).
	Report(ctx context.Context, environment identity.EnvironmentID, days int) (Report, error)
}

// Repository stores limits and daily usage.
type Repository interface {
	Limits(ctx context.Context, environment identity.EnvironmentID) (Stored, error)
	SaveLimits(ctx context.Context, m Mutation, values Values) error
	// Total counts the rows a total limit bounds.
	Total(ctx context.Context, environment identity.EnvironmentID, limit string) (int64, error)
	// Daily is the stored count of a metric on a day.
	Daily(ctx context.Context, environment identity.EnvironmentID, metric string, day time.Time) (int64, error)
	// Days are the stored counts from a day on.
	Days(ctx context.Context, environment identity.EnvironmentID, from time.Time) ([]Increment, error)
	// Add adds the increments to the daily usage.
	Add(ctx context.Context, increments []Increment) error
	// Rollup adds up to batch events created before settled, after the
	// rollup cursor, and moves the cursor; it reports how many it read.
	Rollup(ctx context.Context, settled time.Time, batch int) (int, error)
	// Prune removes daily usage of days before before.
	Prune(ctx context.Context, before time.Time) error
}

// Window counts events in fixed one-minute windows (in memory, or shared
// by every replica).
type Window interface {
	// Take adds one event to key's current window and reports whether it
	// stays within max.
	Take(ctx context.Context, key string, max int64, window time.Duration) (bool, error)
}
