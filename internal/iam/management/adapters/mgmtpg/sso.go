package mgmtpg

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

var _ management.SSORepository = (*Repository)(nil)

// memberOrder picks one workspace for an operator who belongs to several
// (joined as m and w): the oldest workspace, the same for password and single
// sign-on.
const memberOrder = `w.created_at, m.workspace_id`

type principalRow struct {
	Workspace identity.WorkspaceID `db:"workspace_id"`
	Operator  identity.OperatorID  `db:"operator_id"`
	Role      string               `db:"role"`
}

func (p principalRow) principal() management.Principal {
	return management.Principal{WorkspaceID: p.Workspace, OperatorID: p.Operator, Role: p.Role}
}

func (r *Repository) SaveSSOState(ctx context.Context, hash []byte, s management.SSOState, expires time.Time) error {
	// Sign-ins that were never finished are pruned as new ones start.
	if _, err := r.db.ExecContext(ctx, `DELETE FROM operator_sso_states WHERE expires_at<now()`); err != nil {
		return failure(err)
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO operator_sso_states(secret_hash,provider,binding_hash,nonce,verifier,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, hash, s.Provider, s.Binding, s.Nonce, s.Verifier, expires)
	return failure(err)
}

func (r *Repository) ConsumeSSOState(ctx context.Context, stateHash, bindingHash []byte) (management.SSOState, error) {
	var out management.SSOState
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return out, failure(err)
	}
	defer tx.Rollback()
	var row struct {
		Provider string `db:"provider"`
		Binding  []byte `db:"binding_hash"`
		Nonce    string `db:"nonce"`
		Verifier string `db:"verifier"`
	}
	err = tx.GetContext(ctx, &row, `SELECT provider,binding_hash,nonce,verifier FROM operator_sso_states WHERE secret_hash=$1 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, stateHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, failure(err)
	}
	if errors.Is(err, sql.ErrNoRows) || subtle.ConstantTimeCompare(row.Binding, bindingHash) != 1 {
		return out, management.ErrSSOExpired()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operator_sso_states SET consumed_at=now() WHERE secret_hash=$1`, stateHash); err != nil {
		return out, failure(err)
	}
	out = management.SSOState{Provider: row.Provider, Binding: row.Binding, Nonce: row.Nonce, Verifier: row.Verifier}
	return out, failure(tx.Commit())
}

func (r *Repository) LinkedOperator(ctx context.Context, issuer, subject string) (management.Principal, bool, error) {
	var row struct {
		principalRow
		Active sql.NullBool `db:"active"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT i.operator_id, m.workspace_id, m.role, m.active FROM operator_identities i LEFT JOIN workspace_members m ON m.operator_id=i.operator_id LEFT JOIN workspaces w ON w.id=m.workspace_id WHERE i.issuer=$1 AND i.subject=$2 ORDER BY m.active DESC NULLS LAST, `+memberOrder+` LIMIT 1`, issuer, subject)
	if errors.Is(err, sql.ErrNoRows) {
		return management.Principal{}, false, nil
	}
	if err != nil {
		return management.Principal{}, false, failure(err)
	}
	// A linked identity of a disabled operator never falls back to linking
	// by email.
	if !row.Active.Bool {
		return management.Principal{}, true, management.ErrSSONotAuthorized("linked operator is disabled")
	}
	return row.principal(), true, nil
}

func (r *Repository) LinkOperator(ctx context.Context, issuer, subject, provider, email string) (management.Principal, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return management.Principal{}, failure(err)
	}
	defer tx.Rollback()
	var row principalRow
	err = tx.GetContext(ctx, &row, `SELECT m.workspace_id, m.operator_id, m.role FROM operators o JOIN workspace_members m ON m.operator_id=o.id JOIN workspaces w ON w.id=m.workspace_id WHERE o.email=$1 AND m.active ORDER BY `+memberOrder+` LIMIT 1 FOR UPDATE OF o`, email)
	if errors.Is(err, sql.ErrNoRows) {
		return management.Principal{}, management.ErrSSONotAuthorized("no active operator has the email")
	}
	if err != nil {
		return management.Principal{}, failure(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO operator_identities(issuer,subject,operator_id,provider,email,last_login_at) VALUES($1,$2,$3,$4,$5,now())`, issuer, subject, row.Operator, provider, email)
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		if pg.Constraint == "operator_identities_pkey" {
			// A concurrent sign-in with the same identity linked it first;
			// the next attempt matches it by subject.
			return management.Principal{}, management.ErrSSONotAuthorized("identity was linked by a concurrent sign-in")
		}
		// The operator already has another identity of this issuer (a
		// reassigned mailbox or a recreated provider account); an owner
		// resets the operator's identities to allow the new one.
		return management.Principal{}, management.ErrSSONotAuthorized("operator already has another identity of this issuer")
	}
	if err != nil {
		return management.Principal{}, failure(err)
	}
	return row.principal(), failure(tx.Commit())
}

func (r *Repository) TouchIdentity(ctx context.Context, issuer, subject string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE operator_identities SET last_login_at=now() WHERE issuer=$1 AND subject=$2`, issuer, subject)
	return failure(err)
}

func (r *Repository) member(ctx context.Context, q sqlGetter, workspace identity.WorkspaceID, operator identity.OperatorID) error {
	var member bool
	if err := q.GetContext(ctx, &member, `SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=$1 AND operator_id=$2)`, workspace, operator); err != nil {
		return failure(err)
	}
	if !member {
		return errx.NotFound("resource not found")
	}
	return nil
}

type sqlGetter interface {
	GetContext(ctx context.Context, dest any, query string, args ...any) error
}

func (r *Repository) Identities(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID) ([]management.OperatorIdentity, error) {
	if err := r.member(ctx, r.db, workspace, operator); err != nil {
		return nil, err
	}
	out := []management.OperatorIdentity{}
	err := r.db.SelectContext(ctx, &out, `SELECT provider, issuer, email, created_at, last_login_at FROM operator_identities WHERE operator_id=$1 ORDER BY created_at`, operator)
	return out, failure(err)
}

func (r *Repository) UnlinkIdentities(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if err = r.member(ctx, tx, workspace, operator); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM operator_identities WHERE operator_id=$1`, operator); err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operator_sessions SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2 AND revoked_at IS NULL`, workspace, operator); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
