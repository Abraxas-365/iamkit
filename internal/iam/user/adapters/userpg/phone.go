package userpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var _ user.PhoneRepository = (*Repository)(nil)

func (r *Repository) EditPhoneVerification(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, edit func(current user.PhoneVerification) (user.PhoneVerification, error)) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "phone verification")
	}
	defer tx.Rollback()
	var kind string
	err = tx.GetContext(ctx, &kind, `SELECT kind FROM users WHERE environment_id=$1 AND id=$2 FOR UPDATE`, environment, id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && kind != string(user.KindHuman)) {
		return errx.NotFound("user not found")
	}
	if err != nil {
		return failure(err, "phone verification")
	}
	var current user.PhoneVerification
	err = tx.GetContext(ctx, &current, `SELECT phone,code_hash,expires_at,sent_at,attempts,codes_sent,codes_window FROM phone_verifications WHERE user_id=$1 AND environment_id=$2`, id, environment)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return failure(err, "phone verification")
	}
	next, err := edit(current)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO phone_verifications(user_id,environment_id,phone,code_hash,expires_at,sent_at,attempts,codes_sent,codes_window) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (user_id) DO UPDATE SET phone=EXCLUDED.phone,code_hash=EXCLUDED.code_hash,expires_at=EXCLUDED.expires_at,sent_at=EXCLUDED.sent_at,attempts=EXCLUDED.attempts,codes_sent=EXCLUDED.codes_sent,codes_window=EXCLUDED.codes_window`,
		id, environment, next.Phone, next.CodeHash, next.Expires, next.Sent, next.Attempts, next.CodesSent, next.CodesWindow)
	if err != nil {
		return failure(err, "phone verification")
	}
	return failure(tx.Commit(), "commit phone verification")
}

func (r *Repository) ConfirmPhone(ctx context.Context, m user.Mutation, id identity.UserID, codeHash []byte) (bool, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return false, failure(err, "confirm phone")
	}
	defer tx.Rollback()
	var phone string
	err = tx.GetContext(ctx, &phone, `UPDATE phone_verifications SET code_hash=NULL,expires_at=NULL,attempts=0
		WHERE user_id=$1 AND environment_id=$2 AND code_hash=$3 AND expires_at>now() RETURNING phone`, id, m.Environment, codeHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, failure(err, "confirm phone")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET phone=$3,phone_verified=true WHERE environment_id=$1 AND id=$2`, m.Environment, id, phone); err != nil {
		return false, failure(err, "confirm phone")
	}
	if err = audit(ctx, tx, m); err != nil {
		return false, failure(err, "audit phone")
	}
	return true, failure(tx.Commit(), "commit phone")
}

func (r *Repository) FailPhoneCode(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, limit int) error {
	_, err := r.db.ExecContext(ctx, `UPDATE phone_verifications SET attempts=attempts+1,
		code_hash=CASE WHEN attempts+1>=$3 THEN NULL ELSE code_hash END,
		expires_at=CASE WHEN attempts+1>=$3 THEN NULL ELSE expires_at END
		WHERE user_id=$1 AND environment_id=$2 AND code_hash IS NOT NULL`, id, environment, limit)
	return failure(err, "phone verification")
}

func (r *Repository) RemovePhone(ctx context.Context, m user.Mutation, id identity.UserID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "remove phone")
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET phone='',phone_verified=false WHERE environment_id=$1 AND id=$2`, m.Environment, id)
	if err != nil {
		return failure(err, "remove phone")
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return errx.NotFound("user not found")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE phone_verifications SET code_hash=NULL,expires_at=NULL WHERE user_id=$1 AND environment_id=$2`, id, m.Environment); err != nil {
		return failure(err, "remove phone")
	}
	if err = audit(ctx, tx, m); err != nil {
		return failure(err, "audit phone")
	}
	return failure(tx.Commit(), "commit phone")
}
