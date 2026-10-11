// Package riskpg persists risk policies, restrictions, sign-in attempts and
// users' known devices. Audited changes and risk events go through eventpg
// in the same transaction.
package riskpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func failure(err error) error {
	if err == nil {
		return nil
	}
	var e *errx.Error
	if errx.As(err, &e) {
		return err
	}
	return errx.Wrap(err, "persistence failed", errx.TypeInternal)
}

// Policies is the risk policy and restriction repository.
type Policies struct{ db *sqlx.DB }

func NewPolicies(db *sqlx.DB) *Policies { return &Policies{db} }

var _ risk.PolicyRepository = (*Policies)(nil)

type policyRow struct {
	IPVelocity          string    `db:"ip_velocity"`
	UserBruteForce      string    `db:"user_brute_force"`
	ImpossibleTravel    string    `db:"impossible_travel"`
	NewDevice           string    `db:"new_device"`
	StaleAccount        string    `db:"stale_account"`
	IPFailures          int       `db:"ip_failures_per_hour"`
	IPDistinctLogins    int       `db:"ip_distinct_logins_per_hour"`
	UserFailures        int       `db:"user_failures_per_hour"`
	StaleAfterDays      int       `db:"stale_after_days"`
	TravelSpeedKmh      int       `db:"travel_speed_kmh"`
	NotifyUser          bool      `db:"notify_user"`
	BlockIfUnverifiable bool      `db:"block_if_unverifiable"`
	UpdatedAt           time.Time `db:"updated_at"`
}

func (r *Policies) Policy(ctx context.Context, environment identity.EnvironmentID) (risk.Policy, error) {
	var row policyRow
	err := r.db.GetContext(ctx, &row, `SELECT ip_velocity, user_brute_force, impossible_travel, new_device, stale_account,
		ip_failures_per_hour, ip_distinct_logins_per_hour, user_failures_per_hour, stale_after_days, travel_speed_kmh,
		notify_user, block_if_unverifiable, updated_at FROM risk_policies WHERE environment_id = $1`, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return risk.Policy{}, errx.NotFound("no risk policy is saved")
	}
	if err != nil {
		return risk.Policy{}, failure(err)
	}
	updated := row.UpdatedAt
	return risk.Policy{
		Environment: environment,
		Actions: map[string]string{
			risk.IPVelocity: row.IPVelocity, risk.UserBruteForce: row.UserBruteForce, risk.ImpossibleTravel: row.ImpossibleTravel,
			risk.NewDevice: row.NewDevice, risk.StaleAccount: row.StaleAccount,
		},
		Thresholds: risk.Thresholds{IPFailuresPerHour: row.IPFailures, IPDistinctLoginsPerHour: row.IPDistinctLogins,
			UserFailuresPerHour: row.UserFailures, StaleAfterDays: row.StaleAfterDays, TravelSpeedKmh: row.TravelSpeedKmh},
		NotifyUser: row.NotifyUser, BlockIfUnverifiable: row.BlockIfUnverifiable, Saved: true, UpdatedAt: &updated,
	}, nil
}

func (r *Policies) SavePolicy(ctx context.Context, m risk.Mutation, p risk.Policy) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO risk_policies(environment_id, ip_velocity, user_brute_force, impossible_travel, new_device, stale_account,
			ip_failures_per_hour, ip_distinct_logins_per_hour, user_failures_per_hour, stale_after_days, travel_speed_kmh, notify_user, block_if_unverifiable)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (environment_id) DO UPDATE SET ip_velocity = EXCLUDED.ip_velocity, user_brute_force = EXCLUDED.user_brute_force,
			impossible_travel = EXCLUDED.impossible_travel, new_device = EXCLUDED.new_device, stale_account = EXCLUDED.stale_account,
			ip_failures_per_hour = EXCLUDED.ip_failures_per_hour, ip_distinct_logins_per_hour = EXCLUDED.ip_distinct_logins_per_hour,
			user_failures_per_hour = EXCLUDED.user_failures_per_hour, stale_after_days = EXCLUDED.stale_after_days,
			travel_speed_kmh = EXCLUDED.travel_speed_kmh, notify_user = EXCLUDED.notify_user,
			block_if_unverifiable = EXCLUDED.block_if_unverifiable, updated_at = now()`,
			m.Environment, p.Action(risk.IPVelocity), p.Action(risk.UserBruteForce), p.Action(risk.ImpossibleTravel), p.Action(risk.NewDevice), p.Action(risk.StaleAccount),
			p.Thresholds.IPFailuresPerHour, p.Thresholds.IPDistinctLoginsPerHour, p.Thresholds.UserFailuresPerHour, p.Thresholds.StaleAfterDays, p.Thresholds.TravelSpeedKmh,
			p.NotifyUser, p.BlockIfUnverifiable); err != nil {
			return failure(err)
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, risk.ActionPolicyUpdate, m.Environment.String())
	})
}

func (r *Policies) DeletePolicy(ctx context.Context, m risk.Mutation) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM risk_policies WHERE environment_id = $1`, m.Environment); err != nil {
			return failure(err)
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, risk.ActionPolicyDelete, m.Environment.String())
	})
}

type restrictionRow struct {
	ID          identity.RestrictionID `db:"id"`
	Environment identity.EnvironmentID `db:"environment_id"`
	Kind        string                 `db:"kind"`
	Value       string                 `db:"value"`
	Action      string                 `db:"action"`
	Note        string                 `db:"note"`
	CreatedAt   time.Time              `db:"created_at"`
}

func (r restrictionRow) toDomain() risk.Restriction {
	return risk.Restriction{ID: r.ID, Environment: r.Environment, Kind: r.Kind, Value: r.Value, Action: r.Action, Note: r.Note, CreatedAt: r.CreatedAt}
}

func (r *Policies) Restrictions(ctx context.Context, environment identity.EnvironmentID, filter risk.RestrictionFilter) ([]risk.Restriction, error) {
	var rows []restrictionRow
	if err := r.db.SelectContext(ctx, &rows, `SELECT id, environment_id, kind, value, action, note, created_at FROM risk_restrictions
		WHERE environment_id = $1 AND ($2 = '' OR kind = $2) AND ($3 = '' OR action = $3)
		ORDER BY created_at, id`, environment, filter.Kind, filter.Action); err != nil {
		return nil, failure(err)
	}
	out := make([]risk.Restriction, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return out, nil
}

func (r *Policies) CreateRestriction(ctx context.Context, m risk.Mutation, x risk.Restriction) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		// Serialize creates of one environment so the cap holds.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('risk_restrictions:' || $1::text, 0))`, m.Environment); err != nil {
			return failure(err)
		}
		var n int
		if err := tx.GetContext(ctx, &n, `SELECT count(*) FROM risk_restrictions WHERE environment_id = $1`, m.Environment); err != nil {
			return failure(err)
		}
		if n >= risk.MaxRestrictions {
			return risk.ErrTooManyRestrictions()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO risk_restrictions(id, environment_id, kind, value, action, note) VALUES($1,$2,$3,$4,$5,$6)`,
			x.ID, m.Environment, x.Kind, x.Value, x.Action, x.Note); err != nil {
			var pgErr *pq.Error
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return errx.Conflict("a restriction for this " + x.Kind + " already exists")
			}
			return failure(err)
		}
		return eventpg.AuditSubject(ctx, tx, m.Environment, m.Actor, risk.ActionRestrictionCreate, x.ID.String(), x.ID.String(),
			map[string]any{"kind": x.Kind, "value": x.Value, "action": x.Action})
	})
}

func (r *Policies) DeleteRestriction(ctx context.Context, m risk.Mutation, id identity.RestrictionID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var row restrictionRow
		err := tx.GetContext(ctx, &row, `DELETE FROM risk_restrictions WHERE id = $1 AND environment_id = $2
			RETURNING id, environment_id, kind, value, action, note, created_at`, id, m.Environment)
		if errors.Is(err, sql.ErrNoRows) {
			return errx.NotFound("restriction not found")
		}
		if err != nil {
			return failure(err)
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, risk.ActionRestrictionDelete, id.String(),
			map[string]any{"kind": row.Kind, "value": row.Value, "action": row.Action})
	})
}
