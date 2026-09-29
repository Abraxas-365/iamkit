package authpg

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
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

func (r *PasswordPolicyRepository) GetOrganizationPasswordPolicy(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (authentication.PasswordRequirements, error) {
	var rows []authentication.PasswordRequirements
	err := r.db.SelectContext(ctx, &rows, `SELECT coalesce(p.min_length,0) AS min_length, coalesce(p.require_upper,false) AS require_upper,
		coalesce(p.require_lower,false) AS require_lower, coalesce(p.require_digit,false) AS require_digit,
		coalesce(p.require_symbol,false) AS require_symbol, coalesce(p.max_age_days,0) AS max_age_days,
		coalesce(p.breach_check,false) AS breach_check, p.updated_at FROM organizations o
		LEFT JOIN organization_password_policies p ON p.organization_id=o.id AND p.environment_id=o.environment_id
		WHERE o.environment_id=$1 AND o.id=$2`, environment, organization)
	if err != nil {
		return authentication.PasswordRequirements{}, errx.Wrap(err, "read organization password policy", errx.TypeInternal)
	}
	if len(rows) == 0 {
		return authentication.PasswordRequirements{}, errx.NotFound("organization not found")
	}
	out := rows[0]
	out.Custom = out.UpdatedAt != nil
	return out, nil
}

func (r *PasswordPolicyRepository) SetOrganizationPasswordPolicy(ctx context.Context, m authentication.Mutation, organization identity.OrganizationID, p authentication.PasswordRequirements) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "save organization password policy", errx.TypeInternal)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO organization_password_policies (organization_id,environment_id,min_length,require_upper,require_lower,require_digit,require_symbol,max_age_days,breach_check,updated_at)
		SELECT id,environment_id,$3,$4,$5,$6,$7,$8,$9,now() FROM organizations WHERE environment_id=$1 AND id=$2
		ON CONFLICT (organization_id) DO UPDATE SET min_length=$3,require_upper=$4,require_lower=$5,require_digit=$6,require_symbol=$7,
			max_age_days=$8,breach_check=$9,updated_at=now()`,
		m.Environment, organization, p.MinLength, p.RequireUpper, p.RequireLower, p.RequireDigit, p.RequireSymbol, p.MaxAgeDays, p.BreachCheck)
	if err != nil {
		return errx.Wrap(err, "save organization password policy", errx.TypeInternal)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("organization not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "save organization password policy")
}

func (r *PasswordPolicyRepository) DeleteOrganizationPasswordPolicy(ctx context.Context, m authentication.Mutation, organization identity.OrganizationID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "delete organization password policy", errx.TypeInternal)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM organization_password_policies WHERE environment_id=$1 AND organization_id=$2`, m.Environment, organization)
	if err != nil {
		return errx.Wrap(err, "delete organization password policy", errx.TypeInternal)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("organization password policy not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "delete organization password policy")
}

// memberRequirements selects the requirements of the active organizations
// whose active members include user $2.
const memberRequirements = `SELECT p.min_length,p.require_upper,p.require_lower,p.require_digit,p.require_symbol,p.max_age_days,p.breach_check,p.updated_at
	FROM organization_password_policies p
	JOIN organizations o ON o.id=p.organization_id AND o.environment_id=p.environment_id AND o.active
	JOIN memberships m ON m.organization_id=p.organization_id AND m.environment_id=p.environment_id AND m.active
	WHERE p.environment_id=$1 AND m.user_id=$2`

func (r *PasswordPolicyRepository) MemberRequirements(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]authentication.PasswordRequirements, error) {
	out := []authentication.PasswordRequirements{}
	err := r.db.SelectContext(ctx, &out, memberRequirements, environment, user)
	if err != nil {
		return nil, errx.Wrap(err, "read member password requirements", errx.TypeInternal)
	}
	return out, nil
}

func (r *PasswordPolicyRepository) ChallengeRequirements(ctx context.Context, environment identity.EnvironmentID, challenge identity.ChallengeID) ([]authentication.PasswordRequirements, error) {
	var user identity.UserID
	err := r.db.GetContext(ctx, &user, `SELECT user_id FROM identity_challenges WHERE id=$1 AND environment_id=$2`, challenge, environment)
	if err == sql.ErrNoRows {
		return []authentication.PasswordRequirements{}, nil
	}
	if err != nil {
		return nil, errx.Wrap(err, "read member password requirements", errx.TypeInternal)
	}
	return r.MemberRequirements(ctx, environment, user)
}

// SignInPolicyRepository implements authentication.SignInPolicyRepository.
type SignInPolicyRepository struct{ db *sqlx.DB }

func NewSignInPolicyRepository(db *sqlx.DB) *SignInPolicyRepository {
	return &SignInPolicyRepository{db}
}

const signInColumns = `allow_password,allow_email_code,allow_social,allow_passkey,allow_password_reset,mfa_required,mfa_for_federated,allow_signup,signup_organization_id,signup_group_id,updated_at`

func (r *SignInPolicyRepository) GetSignInPolicy(ctx context.Context, environment identity.EnvironmentID) (authentication.SignInPolicy, error) {
	var row struct {
		authentication.SignInPolicy
		Factors pq.StringArray `db:"allowed_factors"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT `+signInColumns+`,allowed_factors FROM sign_in_policies WHERE environment_id=$1`, environment)
	p := row.SignInPolicy
	if err == sql.ErrNoRows {
		return p, errx.NotFound("sign-in policy not found")
	}
	if err != nil {
		return p, errx.Wrap(err, "read sign-in policy", errx.TypeInternal)
	}
	p.AllowedFactors = []string(row.Factors)
	p.Custom = true
	return p, nil
}

func (r *SignInPolicyRepository) SetSignInPolicy(ctx context.Context, m authentication.Mutation, p authentication.SignInPolicy) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "save sign-in policy", errx.TypeInternal)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sign_in_policies (environment_id,allow_password,allow_email_code,allow_social,allow_password_reset,mfa_required,mfa_for_federated,
			allow_signup,signup_organization_id,signup_group_id,allowed_factors,allow_passkey,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
		ON CONFLICT (environment_id) DO UPDATE SET allow_password=$2,allow_email_code=$3,allow_social=$4,allow_password_reset=$5,
			mfa_required=$6,mfa_for_federated=$7,allow_signup=$8,signup_organization_id=$9,signup_group_id=$10,allowed_factors=$11,allow_passkey=$12,updated_at=now()`,
		m.Environment, p.AllowPassword, p.AllowEmailCode, p.AllowSocial, p.AllowPasswordReset, p.MFARequired, p.MFAForFederated,
		p.AllowSignup, p.SignupOrganization, p.SignupGroup, pq.Array(p.AllowedFactors), p.PasskeyAllowed())
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23503" {
		// The sign-up organization or group is not the environment's.
		if strings.Contains(pg.Constraint, "group") {
			return errx.Validation("signup_group_id must be a group of the sign-up organization")
		}
		return errx.Validation("signup_organization_id must be an organization of the environment")
	}
	if err != nil {
		return errx.Wrap(err, "save sign-in policy", errx.TypeInternal)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "save sign-in policy")
}

func (r *SignInPolicyRepository) DeleteSignInPolicy(ctx context.Context, m authentication.Mutation) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "delete sign-in policy", errx.TypeInternal)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM sign_in_policies WHERE environment_id=$1`, m.Environment)
	if err != nil {
		return errx.Wrap(err, "delete sign-in policy", errx.TypeInternal)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("sign-in policy not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "delete sign-in policy")
}

var _ authentication.SignInPolicyRepository = (*SignInPolicyRepository)(nil)

func (r *SignInPolicyRepository) SignupTarget(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, group identity.GroupID) (bool, bool, error) {
	var row struct {
		Organization bool `db:"organization"`
		Group        bool `db:"grp"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT
		EXISTS(SELECT 1 FROM organizations WHERE id=$2 AND environment_id=$1 AND active) AS organization,
		($3::uuid IS NULL OR EXISTS(SELECT 1 FROM groups WHERE id=$3 AND environment_id=$1 AND organization_id=$2 AND connection_id IS NULL)) AS grp`,
		environment, organization, group)
	if err != nil {
		return false, false, errx.Wrap(err, "read sign-up organization", errx.TypeInternal)
	}
	return row.Organization, row.Group, nil
}
