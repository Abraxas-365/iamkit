package riskpg

import (
	"context"
	"database/sql"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Captchas implements risk.CaptchaRepository.
type Captchas struct{ db *sqlx.DB }

func NewCaptchas(db *sqlx.DB) *Captchas { return &Captchas{db} }

var _ risk.CaptchaRepository = (*Captchas)(nil)

func captchaFailure(err error, what string) error {
	if err == nil {
		return nil
	}
	var e *errx.Error
	if errx.As(err, &e) {
		return err
	}
	return errx.Wrap(err, what, errx.TypeInternal)
}

func (r *Captchas) Captcha(ctx context.Context, environment identity.EnvironmentID) (risk.CaptchaConfig, string, error) {
	var row struct {
		Environment identity.EnvironmentID `db:"environment_id"`
		Provider    string                 `db:"provider"`
		SiteKey     string                 `db:"site_key"`
		Sealed      string                 `db:"secret_sealed"`
		Hosted      bool                   `db:"hosted"`
		Headless    bool                   `db:"headless"`
		Hostnames   pq.StringArray         `db:"hostnames"`
		UpdatedAt   time.Time              `db:"updated_at"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT environment_id, provider, site_key, secret_sealed, hosted, headless, hostnames, updated_at
		FROM captcha_configs WHERE environment_id=$1`, environment)
	if err == sql.ErrNoRows {
		return risk.CaptchaConfig{}, "", errx.NotFound("no CAPTCHA is configured")
	}
	if err != nil {
		return risk.CaptchaConfig{}, "", captchaFailure(err, "read CAPTCHA configuration")
	}
	hosts := []string(row.Hostnames)
	if hosts == nil {
		hosts = []string{}
	}
	return risk.CaptchaConfig{Environment: row.Environment, Provider: row.Provider, SiteKey: row.SiteKey, HasSecret: row.Sealed != "",
		Hosted: row.Hosted, Headless: row.Headless, Hostnames: hosts, UpdatedAt: row.UpdatedAt}, row.Sealed, nil
}

func (r *Captchas) SaveCaptcha(ctx context.Context, m risk.Mutation, config risk.CaptchaConfig, sealed string) error {
	hosts := config.Hostnames
	if hosts == nil {
		hosts = []string{}
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return captchaFailure(err, "save CAPTCHA configuration")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO captcha_configs (environment_id, provider, site_key, secret_sealed, hosted, headless, hostnames)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (environment_id) DO UPDATE SET provider=$2, site_key=$3, secret_sealed=$4, hosted=$5, headless=$6,
			hostnames=$7, updated_at=now()`,
		m.Environment, config.Provider, config.SiteKey, sealed, config.Hosted, config.Headless, pq.Array(hosts)); err != nil {
		return captchaFailure(err, "save CAPTCHA configuration")
	}
	if err = eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return err
	}
	return captchaFailure(tx.Commit(), "save CAPTCHA configuration")
}

func (r *Captchas) DeleteCaptcha(ctx context.Context, m risk.Mutation) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return captchaFailure(err, "delete CAPTCHA configuration")
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM captcha_configs WHERE environment_id=$1`, m.Environment)
	if err != nil {
		return captchaFailure(err, "delete CAPTCHA configuration")
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("no CAPTCHA is configured")
	}
	if err = eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return err
	}
	return captchaFailure(tx.Commit(), "delete CAPTCHA configuration")
}

func (r *Captchas) SavePass(ctx context.Context, environment identity.EnvironmentID, ticket []byte, expires time.Time, uses int) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO hosted_captcha_passes (ticket_hash, environment_id, expires_at, uses_left) VALUES ($1,$2,$3,$4)
		ON CONFLICT (ticket_hash) DO UPDATE SET expires_at=$3, uses_left=$4 WHERE hosted_captcha_passes.environment_id=$2`, ticket, environment, expires, uses)
	return captchaFailure(err, "save CAPTCHA pass")
}

func (r *Captchas) Pass(ctx context.Context, environment identity.EnvironmentID, ticket []byte, now time.Time) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS (SELECT 1 FROM hosted_captcha_passes WHERE ticket_hash=$1 AND environment_id=$2 AND expires_at > $3 AND uses_left > 0)`,
		ticket, environment, now)
	return ok, captchaFailure(err, "read CAPTCHA pass")
}

// UsePass spends one use of a live pass in one statement, so concurrent
// posts never spend more than it holds.
func (r *Captchas) UsePass(ctx context.Context, environment identity.EnvironmentID, ticket []byte, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE hosted_captcha_passes SET uses_left = uses_left - 1
		WHERE ticket_hash=$1 AND environment_id=$2 AND expires_at > $3 AND uses_left > 0`, ticket, environment, now)
	if err != nil {
		return false, captchaFailure(err, "use CAPTCHA pass")
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// PrunePasses deletes the passes that expired before now.
func (r *Captchas) PrunePasses(ctx context.Context, now time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM hosted_captcha_passes WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, captchaFailure(err, "prune CAPTCHA passes")
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
