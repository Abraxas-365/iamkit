package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

const deviceColumns = `d.device_hash,d.client_id,d.environment_id,d.scope,d.status,d.interval_seconds,d.last_poll_at,d.session_id,d.user_id,d.organization_id,d.expires_at,d.created_at`

func (r *Repository) CreateDevice(ctx context.Context, client *oauth.Client, deviceHash, userHash []byte, scope string, interval, ttl time.Duration) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO oauth_device_codes(device_hash,user_hash,environment_id,client_id,scope,interval_seconds,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+make_interval(secs => $7))`, deviceHash, userHash, client.Environment, client.ID, scope, int(interval/time.Second), ttl.Seconds())
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		return errx.Conflict("user code taken")
	}
	return failure(err)
}

// PendingDevice finds a pending, unexpired device of a live client (its
// application name for the confirmation page).
func (r *Repository) PendingDevice(ctx context.Context, userHash []byte) (oauth.Device, error) {
	var row oauth.Device
	err := r.db.GetContext(ctx, &row, `SELECT `+deviceColumns+`,a.name AS application_name FROM oauth_device_codes d JOIN oauth_clients c ON c.id=d.client_id AND c.environment_id=d.environment_id AND c.active JOIN applications a ON a.id=c.application_id AND a.environment_id=c.environment_id AND a.active WHERE d.user_hash=$1 AND d.status='pending' AND d.expires_at>now()`, userHash)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.Device{}, errx.NotFound("device code not found")
	}
	return row, failure(err)
}

// SaveDeviceTicket opens an authorization ticket for a device; it lives as
// long as an authorize ticket.
func (r *Repository) SaveDeviceTicket(ctx context.Context, ticketHash, bindingHash []byte, client *oauth.Client, deviceHash []byte) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO oauth_authorizations(secret_hash,environment_id,client_id,binding_hash,request_form,expires_at,device_hash) SELECT $1,$2,$3,$4,'',LEAST(d.expires_at, now()+make_interval(secs => $6)),$5 FROM oauth_device_codes d WHERE d.device_hash=$5 AND d.status='pending'`, ticketHash, client.Environment, client.ID, bindingHash, deviceHash, ticketTTL())
	return failure(err)
}

func (r *Repository) DenyDevice(ctx context.Context, userHash []byte) error {
	res, err := r.db.ExecContext(ctx, `UPDATE oauth_device_codes SET status='denied' WHERE user_hash=$1 AND status='pending' AND expires_at>now()`, userHash)
	if err != nil {
		return failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound("device code not found")
	}
	return nil
}

// PollDevice serializes polls of one device (row lock) so a device code
// is redeemed once and slow_down sees the previous poll.
func (r *Repository) PollDevice(ctx context.Context, client *oauth.Client, deviceHash []byte, poll func(oauth.Device) (oauth.Device, error)) (oauth.Device, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return oauth.Device{}, failure(err)
	}
	defer tx.Rollback()
	var row oauth.Device
	err = tx.GetContext(ctx, &row, `SELECT `+deviceColumns+` FROM oauth_device_codes d WHERE d.device_hash=$1 AND d.client_id=$2 AND d.environment_id=$3 FOR UPDATE`, deviceHash, client.ID, client.Environment)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.Device{}, oauth.DeviceError(oauth.DeviceInvalidGrant)
	}
	if err != nil {
		return oauth.Device{}, failure(err)
	}
	next, outcome := poll(row)
	if _, err = tx.ExecContext(ctx, `UPDATE oauth_device_codes SET status=$2, interval_seconds=$3, last_poll_at=$4 WHERE device_hash=$1`, deviceHash, next.Status, next.Interval, next.LastPoll); err != nil {
		return oauth.Device{}, failure(err)
	}
	if err = tx.Commit(); err != nil {
		return oauth.Device{}, failure(err)
	}
	return next, outcome
}

func (r *Repository) SessionInfo(ctx context.Context, session identity.SessionID) (oauth.SessionInfo, error) {
	var row struct {
		Expires       time.Time      `db:"expires_at"`
		Authenticated time.Time      `db:"authenticated_at"`
		AMR           pq.StringArray `db:"amr"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT expires_at,authenticated_at,amr FROM sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>now()`, session)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.SessionInfo{}, oauth.DeviceError(oauth.DeviceInvalidGrant)
	}
	return oauth.SessionInfo{Expires: row.Expires, Authenticated: row.Authenticated, AMR: []string(row.AMR)}, failure(err)
}

// ApproveDevice records the login on the device's pending row, in the
// ticket's transaction, with its audit event.
func (t *authorization) ApproveDevice(ctx context.Context, environment identity.EnvironmentID, device []byte, login oauth.Login) error {
	res, err := t.tx.ExecContext(ctx, `UPDATE oauth_device_codes SET status='approved', session_id=$2, user_id=$3, organization_id=$4 WHERE device_hash=$1 AND status='pending' AND expires_at>now()`, device, login.Session, login.User, login.Organization)
	if err != nil {
		return failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.Unauthorized("the device authorization expired")
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,'oauth.device_approved',$3)`, environment, login.User, login.Session.String())
	return failure(err)
}
