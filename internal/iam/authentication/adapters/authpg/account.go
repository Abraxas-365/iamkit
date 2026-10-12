package authpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

// AccountPassword locks the active human user's password state by id.
func (t *Transaction) AccountPassword(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.PasswordAccount, error) {
	var row authentication.PasswordAccount
	err := t.tx.GetContext(ctx, &row, `SELECT id,email,password_hash,failed_logins,locked_until,password_changed_at,password_change_required FROM users WHERE environment_id=$1 AND id=$2 AND active AND kind='human' FOR UPDATE`, environment, user)
	return row, credentialError(err)
}

// ChangeOwnPassword stores the hash the user chose for themselves. The
// session triggers would end every session of the user, the current one
// too, so the statement runs with iamkit.password_rehash on (migration 009:
// the triggers skip it) and the other sessions and the unused emailed codes
// end explicitly here; session.revoked events name the user as actor and
// the reason password_changed.
func (t *Transaction) ChangeOwnPassword(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, current identity.SessionID, hash string) (int, error) {
	for _, set := range [][2]string{{"iamkit.session_actor", user.String()}, {"iamkit.session_reason", "password_changed"}, {"iamkit.password_rehash", "on"}} {
		if _, err := t.tx.ExecContext(ctx, `SELECT set_config($1,$2,true)`, set[0], set[1]); err != nil {
			return 0, failure(err)
		}
	}
	res, err := t.tx.ExecContext(ctx, `UPDATE users SET password_hash=$3,password_changed_at=now(),password_change_required=false,failed_logins=0,locked_until=NULL WHERE id=$1 AND environment_id=$2 AND active AND kind='human'`, user, environment, hash)
	if err != nil {
		return 0, failure(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, errx.Unauthorized("invalid credentials or access token")
	}
	if _, err = t.tx.ExecContext(ctx, `SELECT set_config('iamkit.password_rehash','off',true)`); err != nil {
		return 0, failure(err)
	}
	if _, err = t.tx.ExecContext(ctx, `UPDATE identity_challenges SET consumed_at=now() WHERE environment_id=$1 AND user_id=$2 AND consumed_at IS NULL`, environment, user); err != nil {
		return 0, failure(err)
	}
	var ended []sql.NullString
	err = t.tx.SelectContext(ctx, &ended, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND user_id=$2 AND revoked_at IS NULL AND COALESCE(parent_session_id,id)<>`+currentRoot2+` RETURNING parent_session_id::text`, environment, user, current)
	if err != nil {
		return 0, failure(err)
	}
	// Token-exchange children are not counted: the user sees sessions.
	roots := 0
	for _, parent := range ended {
		if !parent.Valid {
			roots++
		}
	}
	err = eventpg.Emit(ctx, t.tx, environment, user.String(), event.UserPasswordChanged, event.Subject{Kind: "user", ID: user.String()},
		map[string]any{"method": authentication.PasswordMethodSelfService, "sessions_revoked": roots})
	return roots, err
}

// currentRoot2 is the root session of $3 (itself, or the parent of a
// token-exchange child).
const currentRoot2 = `COALESCE((SELECT c.parent_session_id FROM sessions c WHERE c.id=$3), $3::uuid)`

// SwitchSession opens a copy of the live session `from` in organization
// `to` and ends `from` (and the sessions it spawned by token exchange) with
// the reason organization_switch, then records user.organization_switched.
// The copy keeps application, resource, expiry, amr, authenticated_at and
// the client information; it is no impersonated, OAuth client or
// token-exchange session (the statement finds no row for those).
func (t *Transaction) SwitchSession(ctx context.Context, from identity.SessionID, to authentication.Context, user identity.UserID, session identity.SessionID) error {
	for _, set := range [][2]string{{"iamkit.session_actor", user.String()}, {"iamkit.session_reason", "organization_switch"}} {
		if _, err := t.tx.ExecContext(ctx, `SELECT set_config($1,$2,true)`, set[0], set[1]); err != nil {
			return failure(err)
		}
	}
	var previous identity.OrganizationID
	err := t.tx.GetContext(ctx, &previous, `SELECT organization_id FROM sessions WHERE id=$1 AND environment_id=$2 AND user_id=$3 AND application_id=$4 AND resource_id=$5 AND revoked_at IS NULL AND expires_at>now() AND actor_id IS NULL AND actor_account_id IS NULL AND oauth_client_id IS NULL AND parent_session_id IS NULL FOR UPDATE`,
		from, to.EnvironmentID, user, to.ApplicationID, to.ResourceID)
	if errors.Is(err, sql.ErrNoRows) {
		return errx.Unauthorized("invalid refresh token")
	}
	if err != nil {
		return failure(err)
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,amr,authenticated_at,ip_address,user_agent,country,risk_detections)
		SELECT $2,environment_id,$3,user_id,application_id,resource_id,expires_at,amr,authenticated_at,ip_address,user_agent,country,risk_detections FROM sessions WHERE id=$1`, from, session, to.OrganizationID)
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code.Class() == "23" {
			return errx.Forbidden("you do not have access to this application in that organization")
		}
		return failure(err)
	}
	// Single logout follows the copy: the identity provider's LogoutRequest
	// (federation_sessions) and the SAML applications' (saml_idp_sessions)
	// still reach it, and ending `from` notifies no application.
	if _, err = t.tx.ExecContext(ctx, `INSERT INTO federation_sessions(session_id,environment_id,connection_id,name_id,name_id_format,session_index,created_at)
		SELECT $2,environment_id,connection_id,name_id,name_id_format,session_index,created_at FROM federation_sessions WHERE session_id=$1 AND environment_id=$3`, from, session, to.EnvironmentID); err != nil {
		return failure(err)
	}
	if _, err = t.tx.ExecContext(ctx, `INSERT INTO saml_idp_sessions(session_id,service_provider_id,environment_id,name_id,created_at)
		SELECT $2,service_provider_id,environment_id,name_id,created_at FROM saml_idp_sessions WHERE session_id=$1 AND environment_id=$3`, from, session, to.EnvironmentID); err != nil {
		return failure(err)
	}
	if _, err = t.tx.ExecContext(ctx, `SELECT set_config('iamkit.saml_logout_skip','on',true)`); err != nil {
		return failure(err)
	}
	if _, err = t.tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND (id=$2 OR parent_session_id=$2) AND revoked_at IS NULL`, to.EnvironmentID, from); err != nil {
		return failure(err)
	}
	if _, err = t.tx.ExecContext(ctx, `SELECT set_config('iamkit.saml_logout_skip','',true)`); err != nil {
		return failure(err)
	}
	return eventpg.Emit(ctx, t.tx, to.EnvironmentID, user.String(), event.UserOrganizationSwitched, event.Subject{Kind: "user", ID: user.String()},
		map[string]any{"from": previous.String(), "to": to.OrganizationID.String(), "organization_id": to.OrganizationID.String(), "session_id": session.String(), "previous_session_id": from.String(), "application_id": to.ApplicationID.String()})
}
