package riskpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Attempts is the sign-in attempt, device and counting repository.
type Attempts struct{ db *sqlx.DB }

func NewAttempts(db *sqlx.DB) *Attempts { return &Attempts{db} }

var _ risk.AttemptRepository = (*Attempts)(nil)

type attemptRow struct {
	ID           identity.SignInAttemptID `db:"id"`
	Environment  identity.EnvironmentID   `db:"environment_id"`
	User         *identity.UserID         `db:"user_id"`
	Organization *identity.OrganizationID `db:"organization_id"`
	IP           sql.NullString           `db:"ip"`
	UserAgent    sql.NullString           `db:"user_agent"`
	Country      sql.NullString           `db:"country"`
	Latitude     *float64                 `db:"latitude"`
	Longitude    *float64                 `db:"longitude"`
	Device       bool                     `db:"device"`
	Method       string                   `db:"method"`
	Surface      string                   `db:"surface"`
	Outcome      string                   `db:"outcome"`
	Reason       string                   `db:"reason"`
	Detections   pq.StringArray           `db:"detections"`
	Action       string                   `db:"action"`
	Captcha      string                   `db:"captcha"`
	CreatedAt    time.Time                `db:"created_at"`
}

const attemptColumns = `id, environment_id, user_id, organization_id, host(ip) AS ip, user_agent, country, latitude, longitude,
	device_hash IS NOT NULL AS device, method, surface, outcome, reason, detections, action, captcha, created_at`

func (r attemptRow) toDomain() risk.Attempt {
	a := risk.Attempt{ID: r.ID, Environment: r.Environment, User: r.User, Organization: r.Organization,
		IP: r.IP.String, UserAgent: r.UserAgent.String, Country: r.Country.String, Latitude: r.Latitude, Longitude: r.Longitude,
		Device: r.Device, Method: r.Method, Surface: r.Surface, Outcome: r.Outcome, Reason: r.Reason,
		Detections: []string(r.Detections), Action: r.Action, Captcha: r.Captcha, CreatedAt: r.CreatedAt}
	if a.Detections == nil {
		a.Detections = []string{}
	}
	return a
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (r *Attempts) Record(ctx context.Context, a risk.Attempt, loginHash, deviceHash []byte) error {
	if a.Detections == nil {
		a.Detections = []string{}
	}
	if a.Action == "" {
		a.Action = risk.ActionNone
	}
	created := any(nil)
	if !a.CreatedAt.IsZero() {
		created = a.CreatedAt
	}
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sign_in_attempts(id, environment_id, user_id, organization_id, login_hash, ip, user_agent, country,
			latitude, longitude, device_hash, method, surface, outcome, reason, detections, action, captcha, created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,COALESCE($19, clock_timestamp()))`,
			a.ID, a.Environment, a.User, a.Organization, nullBytes(loginHash), nullable(a.IP), nullable(a.UserAgent), nullable(a.Country),
			a.Latitude, a.Longitude, nullBytes(deviceHash), a.Method, a.Surface, a.Outcome, a.Reason, pq.StringArray(a.Detections), a.Action, a.Captcha, created); err != nil {
			return failure(err)
		}
		if a.Outcome == risk.OutcomeSuccess && a.User != nil && len(deviceHash) > 0 {
			if err := touchDevice(ctx, tx, a, deviceHash); err != nil {
				return err
			}
		}
		return emit(ctx, tx, a)
	})
}

func touchDevice(ctx context.Context, tx *sqlx.Tx, a risk.Attempt, deviceHash []byte) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_devices(environment_id, user_id, device_hash, last_ip, last_country, user_agent)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (environment_id, user_id, device_hash) DO UPDATE
		SET last_seen_at = now(), last_ip = EXCLUDED.last_ip, last_country = EXCLUDED.last_country, user_agent = EXCLUDED.user_agent`,
		a.Environment, *a.User, deviceHash, nullable(a.IP), nullable(a.Country), nullable(a.UserAgent)); err != nil {
		return failure(err)
	}
	// Past the cap the least recently seen devices go.
	_, err := tx.ExecContext(ctx, `DELETE FROM user_devices WHERE environment_id = $1 AND user_id = $2 AND device_hash NOT IN (
			SELECT device_hash FROM user_devices WHERE environment_id = $1 AND user_id = $2
			ORDER BY last_seen_at DESC, first_seen_at DESC LIMIT $3)`, a.Environment, *a.User, config.MaxUserDevices)
	return failure(err)
}

// emit writes risk.detected for detections that act (log or stronger) and
// sign_in.blocked for refused attempts. The actor is the request's (none
// at sign-in: the system).
func emit(ctx context.Context, tx *sqlx.Tx, a risk.Attempt) error {
	subject := event.Subject{Kind: "sign_in_attempt", ID: a.ID.String()}
	data := func() map[string]any {
		d := map[string]any{"detections": a.Detections, "action": a.Action, "outcome": a.Outcome, "method": a.Method, "surface": a.Surface}
		if a.User != nil {
			d["user_id"] = a.User.String()
		}
		if a.Organization != nil {
			d["organization_id"] = a.Organization.String()
		}
		if a.IP != "" {
			d["ip"] = a.IP
		}
		if a.Country != "" {
			d["country"] = a.Country
		}
		return d
	}
	if len(a.Detections) > 0 && risk.Weight(a.Action) >= risk.Weight(risk.ActionLog) {
		if err := eventpg.Record(ctx, tx, a.Environment, event.RiskDetected, subject, data()); err != nil {
			return err
		}
	}
	if a.Outcome == risk.OutcomeBlocked {
		// One sign_in.blocked per address and reason per
		// config.SignInBlockedEventInterval: a refused flood still records
		// every attempt but never floods events and webhooks.
		if a.IP != "" {
			var seen bool
			if err := tx.GetContext(ctx, &seen, `SELECT EXISTS (SELECT 1 FROM sign_in_attempts WHERE environment_id = $1 AND ip = $2
				AND outcome = $3 AND reason = $4 AND id <> $5 AND created_at > clock_timestamp() - make_interval(secs => $6))`,
				a.Environment, a.IP, risk.OutcomeBlocked, a.Reason, a.ID, config.SignInBlockedEventInterval.Seconds()); err != nil {
				return failure(err)
			}
			if seen {
				return nil
			}
		}
		d := data()
		d["reason"] = a.Reason
		if err := eventpg.Record(ctx, tx, a.Environment, event.SignInBlocked, subject, d); err != nil {
			return err
		}
	}
	return nil
}

func (r *Attempts) Attempts(ctx context.Context, environment identity.EnvironmentID, f risk.AttemptFilter) ([]risk.Attempt, error) {
	var before any
	if f.Before != nil {
		before = *f.Before
	}
	var user any
	if f.User != nil {
		user = *f.User
	}
	var rows []attemptRow
	// Keyset on (created_at, id): ids are random, so the cursor row's time
	// anchors the page.
	err := r.db.SelectContext(ctx, &rows, `SELECT `+attemptColumns+` FROM sign_in_attempts a
		WHERE environment_id = $1
		  AND ($2::uuid IS NULL OR user_id = $2)
		  AND ($3 = '' OR host(ip) = $3)
		  AND ($4 = '' OR outcome = $4)
		  AND ($5 = '' OR $5 = ANY(detections))
		  AND ($6 = '' OR country = $6)
		  AND ($7::uuid IS NULL OR (created_at, id) < (SELECT created_at, id FROM sign_in_attempts WHERE id = $7 AND environment_id = $1))
		ORDER BY created_at DESC, id DESC LIMIT $8`,
		environment, user, f.IP, f.Outcome, f.Detection, f.Country, before, f.Limit)
	if err != nil {
		return nil, failure(err)
	}
	out := make([]risk.Attempt, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return out, nil
}

func (r *Attempts) Attempt(ctx context.Context, environment identity.EnvironmentID, id identity.SignInAttemptID) (risk.Attempt, error) {
	var row attemptRow
	err := r.db.GetContext(ctx, &row, `SELECT `+attemptColumns+` FROM sign_in_attempts WHERE id = $1 AND environment_id = $2`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return risk.Attempt{}, errx.NotFound("sign-in attempt not found")
	}
	if err != nil {
		return risk.Attempt{}, failure(err)
	}
	return row.toDomain(), nil
}

func (r *Attempts) Devices(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]risk.Device, error) {
	var rows []struct {
		First   time.Time      `db:"first_seen_at"`
		Last    time.Time      `db:"last_seen_at"`
		IP      sql.NullString `db:"ip"`
		Country sql.NullString `db:"last_country"`
		Agent   sql.NullString `db:"user_agent"`
	}
	if err := r.db.SelectContext(ctx, &rows, `SELECT first_seen_at, last_seen_at, host(last_ip) AS ip, last_country, user_agent FROM user_devices
		WHERE environment_id = $1 AND user_id = $2 ORDER BY last_seen_at DESC, first_seen_at DESC`, environment, user); err != nil {
		return nil, failure(err)
	}
	out := make([]risk.Device, len(rows))
	for i, d := range rows {
		out[i] = risk.Device{FirstSeenAt: d.First, LastSeenAt: d.Last, LastIP: d.IP.String, LastCountry: d.Country.String, UserAgent: d.Agent.String}
	}
	return out, nil
}

func (r *Attempts) Counts(ctx context.Context, environment identity.EnvironmentID, loginHash []byte, ip string, since time.Time) (risk.Counts, error) {
	var out risk.Counts
	if len(loginHash) > 0 {
		if err := r.db.GetContext(ctx, &out.UserFailures1h, `SELECT count(*) FROM sign_in_attempts
			WHERE environment_id = $1 AND login_hash = $2 AND outcome = 'failure' AND created_at >= $3`, environment, loginHash, since); err != nil {
			return out, failure(err)
		}
	}
	if ip != "" {
		var row struct {
			Failures int `db:"failures"`
			Logins   int `db:"logins"`
		}
		if err := r.db.GetContext(ctx, &row, `SELECT count(*) AS failures, count(DISTINCT login_hash) AS logins FROM sign_in_attempts
			WHERE environment_id = $1 AND ip = $2::inet AND outcome = 'failure' AND created_at >= $3`, environment, ip, since); err != nil {
			return out, failure(err)
		}
		out.IPFailures1h, out.IPDistinctLogins1h = row.Failures, row.Logins
	}
	return out, nil
}

func (r *Attempts) KnownDevice(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, deviceHash []byte) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM user_devices WHERE environment_id = $1 AND user_id = $2 AND device_hash = $3)`,
		environment, user, deviceHash)
	return ok, failure(err)
}

func (r *Attempts) LastLocated(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (risk.Last, bool, error) {
	var row struct {
		At      time.Time      `db:"created_at"`
		Lat     float64        `db:"latitude"`
		Lon     float64        `db:"longitude"`
		Country sql.NullString `db:"country"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT created_at, latitude, longitude, country FROM sign_in_attempts
		WHERE environment_id = $1 AND user_id = $2 AND outcome = 'success' AND latitude IS NOT NULL AND longitude IS NOT NULL
		ORDER BY created_at DESC LIMIT 1`, environment, user)
	if errors.Is(err, sql.ErrNoRows) {
		return risk.Last{}, false, nil
	}
	if err != nil {
		return risk.Last{}, false, failure(err)
	}
	return risk.Last{At: row.At, Latitude: row.Lat, Longitude: row.Lon, Country: row.Country.String}, true, nil
}

func (r *Attempts) LastSignedIn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (*time.Time, error) {
	var at *time.Time
	err := r.db.GetContext(ctx, &at, `SELECT last_signed_in_at FROM users WHERE environment_id = $1 AND id = $2`, environment, user)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return at, failure(err)
}

func (r *Attempts) Prune(ctx context.Context, before time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sign_in_attempts WHERE created_at < $1`, before)
	if err != nil {
		return 0, failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, failure(err)
	}
	// Devices are personal data too: forget those not seen for
	// config.UserDeviceRetention.
	if _, err := r.db.ExecContext(ctx, `DELETE FROM user_devices WHERE last_seen_at < $1`, time.Now().Add(-config.UserDeviceRetention)); err != nil {
		return int(n), failure(err)
	}
	return int(n), nil
}
