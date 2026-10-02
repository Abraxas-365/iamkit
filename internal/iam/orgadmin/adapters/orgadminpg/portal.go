package orgadminpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Portal persists the hosted organization admin portal: an application
// linked to the IAM resource and the environment's 'org_admin' system
// OAuth client.
type Portal struct{ db *sqlx.DB }

var _ orgadmin.PortalRepository = (*Portal)(nil)

func NewPortal(db *sqlx.DB) *Portal { return &Portal{db: db} }

type portalRow struct {
	Client      identity.ClientID      `db:"id"`
	Application identity.ApplicationID `db:"application_id"`
	Active      bool                   `db:"active"`
}

func portal(ctx context.Context, q sqlx.QueryerContext, environment identity.EnvironmentID, lock bool) (portalRow, bool, error) {
	var row portalRow
	statement := `SELECT id,application_id,active FROM oauth_clients WHERE environment_id=$1 AND system=$2`
	if lock {
		statement += ` FOR UPDATE`
	}
	err := sqlx.GetContext(ctx, q, &row, statement, environment, orgadmin.SystemClient)
	if errors.Is(err, sql.ErrNoRows) {
		return row, false, nil
	}
	return row, err == nil, failure(err)
}

func (r *Portal) Portal(ctx context.Context, environment identity.EnvironmentID) (orgadmin.Portal, error) {
	row, found, err := portal(ctx, r.db, environment, false)
	if err != nil || !found {
		return orgadmin.Portal{}, err
	}
	return orgadmin.Portal{Enabled: row.Active, Client: row.Client, Application: row.Application}, nil
}

func (r *Portal) EnablePortal(ctx context.Context, m orgadmin.PortalMutation, application identity.ApplicationID, client identity.ClientID, redirects orgadmin.PortalRedirects) (orgadmin.Portal, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return orgadmin.Portal{}, failure(err)
	}
	defer tx.Rollback()
	// One enable at a time per environment: the unique index would refuse
	// a second system client, the lock turns that race into a wait.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('org_admin_portal:' || $1::text))`, m.Environment); err != nil {
		return orgadmin.Portal{}, failure(err)
	}
	row, found, err := portal(ctx, tx, m.Environment, true)
	if err != nil {
		return orgadmin.Portal{}, err
	}
	callback, signedOut := pq.StringArray{redirects.Callback}, pq.StringArray{redirects.SignedOut}
	if found {
		if _, err = tx.ExecContext(ctx, `UPDATE applications SET active=true WHERE environment_id=$1 AND id=$2`, m.Environment, row.Application); err != nil {
			return orgadmin.Portal{}, failure(err)
		}
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET active=true,redirect_uris=$3,post_logout_redirect_uris=$4 WHERE environment_id=$1 AND id=$2`, m.Environment, row.Client, callback, signedOut); err != nil {
			return orgadmin.Portal{}, failure(err)
		}
		application, client = row.Application, row.Client
	} else {
		var resource identity.ResourceID
		if err = tx.GetContext(ctx, &resource, `SELECT id FROM resources WHERE environment_id=$1 AND prefix='iam'`, m.Environment); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return orgadmin.Portal{}, errx.NotFound("the environment has no IAM resource")
			}
			return orgadmin.Portal{}, failure(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO applications(id,environment_id,name) VALUES($1,$2,$3)`, application, m.Environment, orgadmin.PortalApplication); err != nil {
			return orgadmin.Portal{}, failure(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO application_resources(environment_id,application_id,resource_id) VALUES($1,$2,$3)`, m.Environment, application, resource); err != nil {
			return orgadmin.Portal{}, failure(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,post_logout_redirect_uris,public,hosted_login,token_endpoint_auth_method,grant_types,system) VALUES($1,$2,$3,$4,$5,$6,true,true,'none','{authorization_code,refresh_token}',$7)`, client, m.Environment, application, resource, callback, signedOut, orgadmin.SystemClient); err != nil {
			return orgadmin.Portal{}, failure(err)
		}
	}
	if err = audit(ctx, tx, m, client); err != nil {
		return orgadmin.Portal{}, err
	}
	if err = tx.Commit(); err != nil {
		return orgadmin.Portal{}, failure(err)
	}
	return orgadmin.Portal{Enabled: true, Client: client, Application: application}, nil
}

func (r *Portal) DisablePortal(ctx context.Context, m orgadmin.PortalMutation) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	row, found, err := portal(ctx, tx, m.Environment, true)
	if err != nil {
		return err
	}
	if !found {
		return errx.NotFound("the organization admin portal is not enabled")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET active=false WHERE environment_id=$1 AND id=$2`, m.Environment, row.Client); err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE applications SET active=false WHERE environment_id=$1 AND id=$2`, m.Environment, row.Application); err != nil {
		return failure(err)
	}
	// Sessions of the portal's application end: tokens stop validating at
	// once (their application is inactive) and refresh tokens die with them.
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND application_id=$2 AND revoked_at IS NULL`, m.Environment, row.Application); err != nil {
		return failure(err)
	}
	if err = audit(ctx, tx, m, row.Client); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func audit(ctx context.Context, tx *sqlx.Tx, m orgadmin.PortalMutation, client identity.ClientID) error {
	target := m.Target
	if target == "" {
		target = client.String()
	}
	return failure(eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, target))
}
