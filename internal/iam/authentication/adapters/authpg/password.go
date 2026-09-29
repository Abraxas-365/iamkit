package authpg

import (
	"context"
	"database/sql"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// PasswordPolicyRepository implements authentication.PasswordPolicyRepository.
type PasswordPolicyRepository struct{ db *sqlx.DB }

func NewPasswordPolicyRepository(db *sqlx.DB) *PasswordPolicyRepository {
	return &PasswordPolicyRepository{db}
}

const policyColumns = `min_length,require_upper,require_lower,require_digit,require_symbol,max_age_days,lockout_threshold,lockout_minutes,breach_check,updated_at`

func (r *PasswordPolicyRepository) GetPasswordPolicy(ctx context.Context, environment identity.EnvironmentID) (authentication.PasswordPolicy, error) {
	var p authentication.PasswordPolicy
	err := r.db.GetContext(ctx, &p, `SELECT `+policyColumns+` FROM password_policies WHERE environment_id=$1`, environment)
	if err == sql.ErrNoRows {
		return p, errx.NotFound("password policy not found")
	}
	if err != nil {
		return p, errx.Wrap(err, "read password policy", errx.TypeInternal)
	}
	p.Custom = true
	return p, nil
}

func (r *PasswordPolicyRepository) SetPasswordPolicy(ctx context.Context, m authentication.Mutation, p authentication.PasswordPolicy) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "save password policy", errx.TypeInternal)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO password_policies (environment_id,min_length,require_upper,require_lower,require_digit,require_symbol,max_age_days,lockout_threshold,lockout_minutes,breach_check,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
		ON CONFLICT (environment_id) DO UPDATE SET min_length=$2,require_upper=$3,require_lower=$4,require_digit=$5,require_symbol=$6,
			max_age_days=$7,lockout_threshold=$8,lockout_minutes=$9,breach_check=$10,updated_at=now()`,
		m.Environment, p.MinLength, p.RequireUpper, p.RequireLower, p.RequireDigit, p.RequireSymbol,
		p.MaxAgeDays, p.LockoutThreshold, p.LockoutMinutes, p.BreachCheck)
	if err != nil {
		return errx.Wrap(err, "save password policy", errx.TypeInternal)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "save password policy")
}

func (r *PasswordPolicyRepository) DeletePasswordPolicy(ctx context.Context, m authentication.Mutation) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "delete password policy", errx.TypeInternal)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM password_policies WHERE environment_id=$1`, m.Environment)
	if err != nil {
		return errx.Wrap(err, "delete password policy", errx.TypeInternal)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("password policy not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "delete password policy")
}

var _ authentication.PasswordPolicyRepository = (*PasswordPolicyRepository)(nil)
