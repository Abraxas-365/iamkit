// Package mfapg persists second factors, recovery codes and pending
// multi-factor logins in PostgreSQL.
package mfapg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ mfa.Repository = (*Repository)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "mfa persistence failed", errx.TypeInternal)
}

const factorColumns = `id,kind,name,confirmed_at,last_used_at,created_at,secret_sealed,last_step,coalesce(data->>'phone','') AS phone,code_hash,code_expires_at,code_sent_at,code_attempts,codes_sent,codes_window,data,passkey`

func (r *Repository) Begin(ctx context.Context) (mfa.Transaction, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err)
	}
	return &Transaction{tx: tx}, nil
}

func (r *Repository) Summary(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Summary, error) {
	var exists bool
	if err := r.db.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND environment_id=$2)`, user, environment); err != nil {
		return mfa.Summary{}, failure(err)
	}
	if !exists {
		return mfa.Summary{}, errx.NotFound("user not found")
	}
	out := mfa.Summary{Factors: []mfa.Factor{}}
	if err := r.db.SelectContext(ctx, &out.Factors, `SELECT `+factorColumns+` FROM user_factors WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at`, environment, user); err != nil {
		return mfa.Summary{}, failure(err)
	}
	var lock mfa.Lock
	err := r.db.GetContext(ctx, &lock, `SELECT failed_attempts,locked_until FROM user_mfa_state WHERE environment_id=$1 AND user_id=$2`, environment, user)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return mfa.Summary{}, failure(err)
	}
	out.LockedUntil = lock.LockedUntil
	for i := range out.Factors {
		if out.Factors[i].Active() {
			out.Factors[i].LockedUntil = lock.LockedUntil
		}
	}
	err = r.db.GetContext(ctx, &out.RecoveryCodes, `SELECT count(*) FROM recovery_codes WHERE environment_id=$1 AND user_id=$2 AND used_at IS NULL`, environment, user)
	return out, failure(err)
}

func (r *Repository) Policy(ctx context.Context, b authentication.Context, user identity.UserID) (mfa.Policy, error) {
	var row struct {
		Active            pq.StringArray `db:"active"`
		Allowed           pq.StringArray `db:"allowed"`
		Required          bool           `db:"required"`
		RequiredFederated bool           `db:"required_federated"`
		Found             bool           `db:"found"`
	}
	// The environment's sign-in policy requires for every organization and
	// lists the factors allowed; an organization narrows that list. A zero
	// organization reads the environment's rules only.
	err := r.db.GetContext(ctx, &row, `SELECT
		coalesce((SELECT array_agg(DISTINCT f.kind) FROM user_factors f WHERE f.environment_id=e.id AND f.user_id=$3 AND f.confirmed_at IS NOT NULL), '{}') AS active,
		ARRAY(SELECT unnest(coalesce(p.allowed_factors,'{totp,webauthn}'::text[]))
			INTERSECT SELECT unnest(coalesce(o.allowed_factors,'{totp,email,sms,webauthn}'::text[]))) AS allowed,
		coalesce(o.mfa_required,false) OR coalesce(p.mfa_required,false) AS required,
		coalesce(o.mfa_for_federated,false) OR coalesce(p.mfa_for_federated,false) AS required_federated,
		$2::uuid IS NULL OR o.id IS NOT NULL AS found
		FROM environments e
		LEFT JOIN sign_in_policies p ON p.environment_id=e.id
		LEFT JOIN organizations o ON o.id=$2 AND o.environment_id=e.id
		WHERE e.id=$1`, b.EnvironmentID, b.OrganizationID, user)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !row.Found) {
		return mfa.Policy{}, errx.Unauthorized("invalid credentials or access token")
	}
	if err != nil {
		return mfa.Policy{}, failure(err)
	}
	return mfa.Policy{Active: []string(row.Active), Allowed: []string(row.Allowed), Required: row.Required, RequiredFederated: row.RequiredFederated}, nil
}

func (r *Repository) Allowed(ctx context.Context, environment identity.EnvironmentID) ([]string, error) {
	var out pq.StringArray
	err := r.db.GetContext(ctx, &out, `SELECT coalesce((SELECT allowed_factors FROM sign_in_policies WHERE environment_id=$1),'{totp,webauthn}'::text[])`, environment)
	return []string(out), failure(err)
}

// Account names the user after the environment's hosted login branding, or
// the environment.
func (r *Repository) Account(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Account, error) {
	var out mfa.Account
	err := r.db.GetContext(ctx, &out, `SELECT coalesce(u.email,'') AS email, coalesce(nullif(s.display_name,''), e.name) AS issuer
		FROM users u JOIN environments e ON e.id=u.environment_id
		LEFT JOIN login_settings s ON s.environment_id=u.environment_id
		WHERE u.id=$1 AND u.environment_id=$2 AND u.active`, user, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Account{}, errx.NotFound("user not found")
	}
	return out, failure(err)
}

func (r *Repository) SaveUnconfirmed(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, sealed string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var active bool
	err = tx.GetContext(ctx, &active, `SELECT confirmed_at IS NOT NULL FROM user_factors WHERE environment_id=$1 AND user_id=$2 AND kind='totp' FOR UPDATE`, environment, user)
	switch {
	case err == nil && active:
		return errx.Conflict("an authenticator is already enrolled; remove it first")
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_factors WHERE environment_id=$1 AND user_id=$2 AND kind='totp' AND confirmed_at IS NULL`, environment, user); err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_factors(id,environment_id,user_id,kind,secret_sealed) VALUES($1,$2,$3,'totp',$4)`, factor, environment, user, sealed); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errx.Conflict("an authenticator enrollment is already in progress")
		}
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return errx.NotFound("user not found")
		}
		return failure(err)
	}
	return failure(tx.Commit())
}

// SavePending stores a pending login and sweeps expired ones.
func (r *Repository) SavePending(ctx context.Context, hash []byte, p mfa.Pending) error {
	_, err := r.db.ExecContext(ctx, `WITH sweep AS (DELETE FROM mfa_logins WHERE expires_at<now())
		INSERT INTO mfa_logins(token_hash,environment_id,organization_id,application_id,resource_id,user_id,amr,enroll,expires_at,password_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		hash, p.Boundary.EnvironmentID, p.Boundary.OrganizationID, p.Boundary.ApplicationID, p.Boundary.ResourceID, p.User, pq.StringArray(p.AMR), p.Enroll, p.Expires, p.PasswordHash)
	return failure(err)
}

// Transaction counts wrong second-factor answers, recorded as a metric
// once it commits.
type Transaction struct {
	tx       *sqlx.Tx
	failures int
}

var _ mfa.Transaction = (*Transaction)(nil)

func (t *Transaction) Factors(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]mfa.Factor, error) {
	out := []mfa.Factor{}
	err := t.tx.SelectContext(ctx, &out, `SELECT `+factorColumns+` FROM user_factors WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at FOR UPDATE`, environment, user)
	return out, failure(err)
}

func (t *Transaction) Lock(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Lock, error) {
	var out mfa.Lock
	err := t.tx.GetContext(ctx, &out, `SELECT failed_attempts,locked_until FROM user_mfa_state WHERE environment_id=$1 AND user_id=$2 FOR UPDATE`, environment, user)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Lock{}, nil
	}
	return out, failure(err)
}

func (t *Transaction) SetLock(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, lock mfa.Lock) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO user_mfa_state(environment_id,user_id,failed_attempts,locked_until) VALUES($1,$2,$3,$4)
		ON CONFLICT (environment_id,user_id) DO UPDATE SET failed_attempts=EXCLUDED.failed_attempts, locked_until=EXCLUDED.locked_until`,
		environment, user, lock.Failures, lock.LockedUntil)
	if err == nil && lock.Failures > 0 {
		t.failures++
	}
	return failure(err)
}

func (t *Transaction) UseStep(ctx context.Context, factor identity.FactorID, step int64) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET last_step=$2, last_used_at=now() WHERE id=$1`, factor, step)
	return failure(err)
}

func (t *Transaction) Confirm(ctx context.Context, factor identity.FactorID, step int64) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET confirmed_at=now(), last_step=$2, last_used_at=now() WHERE id=$1`, factor, step)
	return failure(err)
}

func (t *Transaction) DeleteFactor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM user_factors WHERE environment_id=$1 AND user_id=$2 AND id=$3`, environment, user, factor)
	return failure(err)
}

// SaveCodeFactor inserts the factor, or refreshes the user's unconfirmed
// one of that kind (new number, new enrollment window, no live code). An
// active one is left alone: the upsert returns no row.
func (t *Transaction) SaveCodeFactor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, kind, phone string) (mfa.Factor, error) {
	data := `{}`
	if phone != "" {
		b, err := json.Marshal(map[string]string{"phone": phone})
		if err != nil {
			return mfa.Factor{}, failure(err)
		}
		data = string(b)
	}
	var out mfa.Factor
	err := t.tx.GetContext(ctx, &out, `INSERT INTO user_factors(id,environment_id,user_id,kind,data) VALUES($1,$2,$3,$4,$5::jsonb)
		ON CONFLICT (environment_id,user_id,kind) WHERE kind IN ('totp','email','sms')
		DO UPDATE SET data=EXCLUDED.data, created_at=now(), code_hash=NULL, code_expires_at=NULL, code_attempts=0
		WHERE user_factors.confirmed_at IS NULL
		RETURNING `+factorColumns, factor, environment, user, kind, data)
	var pqErr *pq.Error
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return mfa.Factor{}, errx.Conflict("an " + kind + " factor is already enrolled; remove it first")
	case errors.As(err, &pqErr) && pqErr.Code == "23503":
		return mfa.Factor{}, errx.NotFound("user not found")
	}
	return out, failure(err)
}

func (t *Transaction) SetCode(ctx context.Context, factor identity.FactorID, code mfa.Code) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET code_hash=$2, code_expires_at=$3, code_sent_at=$4, code_attempts=0, codes_sent=$5, codes_window=$6 WHERE id=$1`,
		factor, code.Hash, code.Expires, code.Sent, code.Count, code.Window)
	return failure(err)
}

func (t *Transaction) UseCode(ctx context.Context, factor identity.FactorID) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET code_hash=NULL, code_expires_at=NULL, code_attempts=0, last_used_at=now() WHERE id=$1`, factor)
	return failure(err)
}

func (t *Transaction) FailCode(ctx context.Context, factor identity.FactorID, limit int) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET code_attempts=code_attempts+1,
		code_hash=CASE WHEN code_attempts+1>=$2 THEN NULL ELSE code_hash END,
		code_expires_at=CASE WHEN code_attempts+1>=$2 THEN NULL ELSE code_expires_at END
		WHERE id=$1`, factor, limit)
	return failure(err)
}

// ConfirmCode activates the factor; a confirmed SMS number becomes the
// user's verified phone.
func (t *Transaction) ConfirmCode(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID) error {
	var phone string
	err := t.tx.GetContext(ctx, &phone, `UPDATE user_factors SET confirmed_at=now(), last_used_at=now(), code_hash=NULL, code_expires_at=NULL, code_attempts=0
		WHERE id=$1 AND environment_id=$2 AND user_id=$3 RETURNING coalesce(data->>'phone','')`, factor, environment, user)
	if err != nil {
		return failure(err)
	}
	if phone == "" {
		return nil
	}
	_, err = t.tx.ExecContext(ctx, `UPDATE users SET phone=$3, phone_verified=true WHERE id=$1 AND environment_id=$2`, user, environment, phone)
	return failure(err)
}

func (t *Transaction) UseRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, hash []byte) (bool, error) {
	res, err := t.tx.ExecContext(ctx, `UPDATE recovery_codes SET used_at=now() WHERE environment_id=$1 AND user_id=$2 AND code_hash=$3 AND used_at IS NULL`, environment, user, hash)
	if err != nil {
		return false, failure(err)
	}
	n, err := res.RowsAffected()
	return n == 1, failure(err)
}

func (t *Transaction) ReplaceRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, hashes [][]byte) error {
	if _, err := t.tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE environment_id=$1 AND user_id=$2`, environment, user); err != nil {
		return failure(err)
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO recovery_codes(environment_id,user_id,code_hash) SELECT $1,$2,unnest($3::bytea[])`, environment, user, pq.ByteaArray(hashes))
	return failure(err)
}

func (t *Transaction) DeleteFactors(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (bool, error) {
	res, err := t.tx.ExecContext(ctx, `DELETE FROM user_factors WHERE environment_id=$1 AND user_id=$2`, environment, user)
	if err != nil {
		return false, failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, failure(err)
	}
	codes, err := t.tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE environment_id=$1 AND user_id=$2`, environment, user)
	if err != nil {
		return false, failure(err)
	}
	m, err := codes.RowsAffected()
	if err != nil {
		return false, failure(err)
	}
	if _, err = t.tx.ExecContext(ctx, `DELETE FROM user_mfa_state WHERE environment_id=$1 AND user_id=$2`, environment, user); err != nil {
		return false, failure(err)
	}
	return n+m > 0, nil
}

func (t *Transaction) Pending(ctx context.Context, hash []byte) (mfa.Pending, error) {
	var row struct {
		Environment  identity.EnvironmentID  `db:"environment_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Application  identity.ApplicationID  `db:"application_id"`
		Resource     identity.ResourceID     `db:"resource_id"`
		User         identity.UserID         `db:"user_id"`
		AMR          pq.StringArray          `db:"amr"`
		Enroll       bool                    `db:"enroll"`
		Attempts     int                     `db:"attempts"`
		Expires      time.Time               `db:"expires_at"`
		PasswordHash string                  `db:"password_hash"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT environment_id,organization_id,application_id,resource_id,user_id,amr,enroll,attempts,expires_at,password_hash FROM mfa_logins WHERE token_hash=$1 AND expires_at>now() FOR UPDATE`, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Pending{}, errx.Unauthorized("sign in again")
	}
	if err != nil {
		return mfa.Pending{}, failure(err)
	}
	return mfa.Pending{Boundary: authentication.Context{EnvironmentID: row.Environment, OrganizationID: row.Organization, ApplicationID: row.Application, ResourceID: row.Resource}, User: row.User, AMR: []string(row.AMR), Enroll: row.Enroll, Attempts: row.Attempts, Expires: row.Expires, PasswordHash: row.PasswordHash}, nil
}

func (t *Transaction) FailPending(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE mfa_logins SET attempts=attempts+1 WHERE token_hash=$1`, hash)
	return failure(err)
}

func (t *Transaction) DeletePending(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM mfa_logins WHERE token_hash=$1`, hash)
	return failure(err)
}

func (t *Transaction) Audit(ctx context.Context, m mfa.Mutation) error {
	return failure(eventpg.Audit(ctx, t.tx, m.Environment, m.Actor, m.Action, m.Target))
}

func (t *Transaction) SaveWebAuthn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, f mfa.Factor, c mfa.Credential) error {
	data, err := json.Marshal(c)
	if err != nil {
		return failure(err)
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO user_factors(id,environment_id,user_id,kind,name,data,credential_id,passkey,confirmed_at,created_at)
		VALUES($1,$2,$3,'webauthn',$4,$5::jsonb,$6,$7,$8,$8)`, f.ID, environment, user, f.Name, data, c.ID, f.Passkey, f.Confirmed)
	var pqErr *pq.Error
	switch {
	case errors.As(err, &pqErr) && pqErr.Code == "23505":
		return errx.Conflict("this security key is already registered")
	case errors.As(err, &pqErr) && pqErr.Code == "23503":
		return errx.NotFound("user not found")
	}
	return failure(err)
}

func (t *Transaction) UseWebAuthn(ctx context.Context, factor identity.FactorID, c mfa.Credential) error {
	data, err := json.Marshal(c)
	if err != nil {
		return failure(err)
	}
	_, err = t.tx.ExecContext(ctx, `UPDATE user_factors SET data=$2::jsonb, last_used_at=now() WHERE id=$1`, factor, data)
	return failure(err)
}

func (t *Transaction) TakeCeremony(ctx context.Context, hash []byte, environment identity.EnvironmentID, purpose string) (mfa.Ceremony, bool, error) {
	var row struct {
		User    *identity.UserID `db:"user_id"`
		Data    []byte           `db:"data"`
		Expires time.Time        `db:"expires_at"`
	}
	err := t.tx.GetContext(ctx, &row, `DELETE FROM webauthn_sessions WHERE id_hash=$1 AND environment_id=$2 AND purpose=$3 RETURNING user_id,data,expires_at`, hash, environment, purpose)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Ceremony{}, false, nil
	}
	if err != nil {
		return mfa.Ceremony{}, false, failure(err)
	}
	var data ceremonyData
	if err = json.Unmarshal(row.Data, &data); err != nil {
		return mfa.Ceremony{}, false, failure(err)
	}
	out := mfa.Ceremony{Environment: environment, Purpose: purpose, State: data.State, Name: data.Name, Passkey: data.Passkey, Expires: row.Expires}
	if row.User != nil {
		out.User = *row.User
	}
	return out, row.Expires.After(time.Now()), nil
}

// ceremonyData is webauthn_sessions.data.
type ceremonyData struct {
	State   json.RawMessage `json:"state"`
	Name    string          `json:"name,omitempty"`
	Passkey bool            `json:"passkey,omitempty"`
}

func (r *Repository) SaveCeremony(ctx context.Context, hash []byte, c mfa.Ceremony) error {
	data, err := json.Marshal(ceremonyData{State: c.State, Name: c.Name, Passkey: c.Passkey})
	if err != nil {
		return failure(err)
	}
	var user *identity.UserID
	if !c.User.IsZero() {
		user = &c.User
	}
	_, err = r.db.ExecContext(ctx, `WITH sweep AS (DELETE FROM webauthn_sessions WHERE expires_at<now())
		INSERT INTO webauthn_sessions(id_hash,environment_id,user_id,purpose,data,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`,
		hash, c.Environment, user, c.Purpose, data, c.Expires)
	return failure(err)
}

func (r *Repository) RenameFactor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, name string) (mfa.Factor, error) {
	var out mfa.Factor
	err := r.db.GetContext(ctx, &out, `UPDATE user_factors SET name=$4 WHERE environment_id=$1 AND user_id=$2 AND id=$3 AND kind='webauthn' RETURNING `+factorColumns, environment, user, factor, name)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Factor{}, errx.NotFound("security key not found")
	}
	return out, failure(err)
}

func (t *Transaction) Commit() error {
	if err := t.tx.Commit(); err != nil {
		return failure(err)
	}
	for range t.failures {
		telemetry.MFAFailure(context.Background())
	}
	return nil
}
func (t *Transaction) Rollback() error {
	err := t.tx.Rollback()
	if errors.Is(err, sql.ErrTxDone) {
		return nil
	}
	return failure(err)
}
