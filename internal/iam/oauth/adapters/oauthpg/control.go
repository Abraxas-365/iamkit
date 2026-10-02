package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "OAuth persistence failed", errx.TypeInternal)
}
func lookup(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return errx.Unauthorized("invalid OAuth credential")
	}
	return failure(err)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("invalid application/resource binding")
	}
	return failure(err)
}
func (r *Repository) Environment(ctx context.Context, id identity.ClientID) (identity.EnvironmentID, error) {
	var environment identity.EnvironmentID
	err := r.db.GetContext(ctx, &environment, `SELECT environment_id FROM oauth_clients WHERE id=$1 AND active`, id)
	return environment, lookup(err)
}
func (r *Repository) AccessTokenClient(ctx context.Context, key string) (identity.EnvironmentID, identity.ClientID, error) {
	var row struct {
		Environment identity.EnvironmentID `db:"environment_id"`
		Client      identity.ClientID      `db:"client_id"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT environment_id,client_id FROM oauth_requests WHERE kind='access' AND signature_hash=$1 AND active AND expires_at>clock_timestamp() LIMIT 1`, key)
	return row.Environment, row.Client, lookup(err)
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID, input oauth.Registration, hash []byte) error {
	auth := input.ClientAuth
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public,secret_hash,hosted_login,post_logout_redirect_uris,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks,jwks_uri,access_token_format,backchannel_logout_uri,backchannel_logout_session_required,grant_types,allowed_origins) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, id, environment, input.Application, input.Resource, pq.StringArray(nonNil(input.Redirects)), input.Public, hash, input.HostedLogin, pq.StringArray(nonNil(input.PostLogoutRedirects)), auth.Method, auth.SigningAlg, auth.StoredJWKS(), auth.JWKSURI, input.AccessTokenFormat, input.BackchannelLogoutURI, input.BackchannelLogoutSessionRequired, pq.StringArray(input.Grants()), pq.StringArray(nonNil(input.AllowedOrigins))); err != nil {
			return conflict(err)
		}
		return eventpg.Record(ctx, tx, environment, event.OAuthClientCreated, event.Subject{Kind: "oauth_client", ID: id.String()},
			map[string]any{"application_id": input.Application.String(), "resource_id": input.Resource.String()})
	})
}
func (r *Repository) Update(ctx context.Context, m oauth.Mutation, id identity.ClientID, input oauth.ClientUpdate, auth *identity.ClientAuth) error {
	var redirects any
	if input.Redirects != nil {
		redirects = pq.StringArray(*input.Redirects)
	}
	var postLogout any
	if input.PostLogoutRedirects != nil {
		postLogout = pq.StringArray(nonNil(*input.PostLogoutRedirects))
	}
	var grants any
	if input.GrantTypes != nil {
		grants = pq.StringArray(*input.GrantTypes)
	}
	var origins any
	if input.AllowedOrigins != nil {
		origins = pq.StringArray(nonNil(*input.AllowedOrigins))
	}
	if auth != nil {
		return r.audited(ctx, m, `UPDATE oauth_clients SET hosted_login=COALESCE($3,hosted_login), redirect_uris=COALESCE($4,redirect_uris), post_logout_redirect_uris=COALESCE($5,post_logout_redirect_uris), access_token_format=COALESCE($6,access_token_format), backchannel_logout_uri=COALESCE($11,backchannel_logout_uri), backchannel_logout_session_required=COALESCE($12,backchannel_logout_session_required), grant_types=COALESCE($13,grant_types), allowed_origins=COALESCE($14,allowed_origins), token_endpoint_auth_method=$7, token_endpoint_auth_signing_alg=$8, jwks=$9, jwks_uri=$10 WHERE environment_id=$1 AND id=$2 AND active`, m.Environment, id, input.HostedLogin, redirects, postLogout, input.AccessTokenFormat, auth.Method, auth.SigningAlg, auth.StoredJWKS(), auth.JWKSURI, input.BackchannelLogoutURI, input.BackchannelLogoutSessionRequired, grants, origins)
	}
	return r.audited(ctx, m, `UPDATE oauth_clients SET hosted_login=COALESCE($3,hosted_login), redirect_uris=COALESCE($4,redirect_uris), post_logout_redirect_uris=COALESCE($5,post_logout_redirect_uris), access_token_format=COALESCE($6,access_token_format), backchannel_logout_uri=COALESCE($7,backchannel_logout_uri), backchannel_logout_session_required=COALESCE($8,backchannel_logout_session_required), grant_types=COALESCE($9,grant_types), allowed_origins=COALESCE($10,allowed_origins) WHERE environment_id=$1 AND id=$2 AND active`, m.Environment, id, input.HostedLogin, redirects, postLogout, input.AccessTokenFormat, input.BackchannelLogoutURI, input.BackchannelLogoutSessionRequired, grants, origins)
}
func (r *Repository) Disable(ctx context.Context, m oauth.Mutation, id identity.ClientID) error {
	return r.audited(ctx, m, `UPDATE oauth_clients SET active=false WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}

// audited runs a single-client change together with its audit event.
func (r *Repository) audited(ctx context.Context, m oauth.Mutation, statement string, args ...any) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	if err = eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, filter oauth.ClientFilter, page query.Pagination) (query.Paginated[oauth.ClientView], error) {
	base := `FROM oauth_clients oc JOIN applications a ON a.id=oc.application_id JOIN resources res ON res.id=oc.resource_id WHERE oc.environment_id=$1`
	args := []any{environment}
	n := 1
	if !filter.Application.IsZero() {
		n++
		base += fmt.Sprintf(" AND oc.application_id=$%d", n)
		args = append(args, filter.Application)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (a.name ILIKE $%d OR res.name ILIKE $%d)", n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[oauth.ClientView]{}, failure(err)
	}
	rows := []clientViewRow{}
	sel := fmt.Sprintf("SELECT %s %s ORDER BY a.name LIMIT %d OFFSET %d", clientColumns, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &rows, sel, args...); err != nil {
		return query.Paginated[oauth.ClientView]{}, failure(err)
	}
	out := make([]oauth.ClientView, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.view())
	}
	return query.NewPaginated(out, total, page), nil
}
func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID) (oauth.ClientView, error) {
	var row clientViewRow
	err := r.db.GetContext(ctx, &row, "SELECT "+clientColumns+` FROM oauth_clients oc JOIN applications a ON a.id=oc.application_id JOIN resources res ON res.id=oc.resource_id WHERE oc.environment_id=$1 AND oc.id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.ClientView{}, errx.NotFound("OAuth client not found")
	}
	if err != nil {
		return oauth.ClientView{}, failure(err)
	}
	return row.view(), nil
}

func (r *Repository) OriginAllowed(ctx context.Context, origin string) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM oauth_clients oc JOIN applications a ON a.id=oc.application_id AND a.environment_id=oc.environment_id WHERE oc.allowed_origins @> ARRAY[$1]::text[] AND oc.active AND a.active)`, origin)
	return ok, failure(err)
}

const clientColumns = "oc.id, oc.application_id, a.name AS application_name, oc.resource_id, res.name AS resource_name, oc.redirect_uris, oc.post_logout_redirect_uris, oc.public, oc.hosted_login, oc.active, oc.token_endpoint_auth_method, oc.token_endpoint_auth_signing_alg, oc.jwks, oc.jwks_uri, oc.access_token_format, oc.backchannel_logout_uri, oc.backchannel_logout_session_required, oc.grant_types, oc.allowed_origins, coalesce(oc.system,'') AS system"

type clientViewRow struct {
	ID              identity.ClientID      `db:"id"`
	Application     identity.ApplicationID `db:"application_id"`
	ApplicationName string                 `db:"application_name"`
	Resource        identity.ResourceID    `db:"resource_id"`
	ResourceName    string                 `db:"resource_name"`
	Redirects       pq.StringArray         `db:"redirect_uris"`
	PostLogout      pq.StringArray         `db:"post_logout_redirect_uris"`
	Public          bool                   `db:"public"`
	HostedLogin     bool                   `db:"hosted_login"`
	Active          bool                   `db:"active"`
	TokenFormat     string                 `db:"access_token_format"`
	Backchannel     string                 `db:"backchannel_logout_uri"`
	SessionRequired bool                   `db:"backchannel_logout_session_required"`
	Grants          pq.StringArray         `db:"grant_types"`
	Origins         pq.StringArray         `db:"allowed_origins"`
	System          string                 `db:"system"`
	authRow
}

func (row clientViewRow) view() oauth.ClientView {
	return oauth.ClientView{ID: row.ID, Application: row.Application, ApplicationName: row.ApplicationName, Resource: row.Resource, ResourceName: row.ResourceName, Redirects: []string(row.Redirects), PostLogoutRedirects: nonNil([]string(row.PostLogout)), Public: row.Public, HostedLogin: row.HostedLogin, Active: row.Active, AccessTokenFormat: row.TokenFormat, BackchannelLogoutURI: row.Backchannel, BackchannelLogoutSessionRequired: row.SessionRequired, GrantTypes: nonNil([]string(row.Grants)), AllowedOrigins: nonNil([]string(row.Origins)), System: row.System, ClientAuth: row.auth()}
}

// authRow scans the token endpoint authentication columns.
type authRow struct {
	Method     string  `db:"token_endpoint_auth_method"`
	SigningAlg string  `db:"token_endpoint_auth_signing_alg"`
	JWKS       *[]byte `db:"jwks"`
	JWKSURI    string  `db:"jwks_uri"`
}

func (row clientViewRow) auth() identity.ClientAuth {
	out := row.authRow.auth()
	if row.Public {
		out.Method = identity.AuthNone
	}
	return out
}
func (row authRow) auth() identity.ClientAuth {
	out := identity.ClientAuth{Method: row.Method, SigningAlg: row.SigningAlg, JWKSURI: row.JWKSURI}
	if row.JWKS != nil {
		out.JWKS = *row.JWKS
	}
	return out
}
func (r *Repository) SaveTicket(ctx context.Context, hash, binding []byte, client *oauth.Client, form string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO oauth_authorizations(secret_hash,environment_id,client_id,binding_hash,request_form,expires_at) VALUES($1,$2,$3,$4,$5,now()+make_interval(secs => $6))`, hash, client.Environment, client.ID, binding, form, ticketTTL())
	return failure(err)
}

// ticketTTL is the authorization ticket lifetime in seconds.
func ticketTTL() float64 { return config.OAuthAuthorizationTicketTTL.Seconds() }
func (r *Repository) PendingTicket(ctx context.Context, hash []byte) (oauth.Ticket, error) {
	var row oauth.Ticket
	err := r.db.GetContext(ctx, &row, `SELECT client_id,binding_hash,request_form,requested_at,device_hash FROM oauth_authorizations WHERE secret_hash=$1 AND expires_at>now() AND consumed_at IS NULL`, hash)
	return row, lookup(err)
}

type authorization struct{ tx *sqlx.Tx }

func (r *Repository) Begin(ctx context.Context) (oauth.Authorization, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err)
	}
	return &authorization{tx}, nil
}
func (t *authorization) Ticket(ctx context.Context, hash []byte) (oauth.Ticket, error) {
	var row oauth.Ticket
	err := t.tx.GetContext(ctx, &row, `SELECT client_id,binding_hash,request_form,requested_at,device_hash FROM oauth_authorizations WHERE secret_hash=$1 AND expires_at>now() AND consumed_at IS NULL FOR UPDATE`, hash)
	return row, lookup(err)
}
func (t *authorization) Session(ctx context.Context, id identity.SessionID) (oauth.SessionInfo, error) {
	var row struct {
		Expires       time.Time      `db:"expires_at"`
		Authenticated time.Time      `db:"authenticated_at"`
		AMR           pq.StringArray `db:"amr"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT expires_at,authenticated_at,amr FROM sessions WHERE id=$1 AND revoked_at IS NULL`, id)
	return oauth.SessionInfo{Expires: row.Expires, Authenticated: row.Authenticated, AMR: []string(row.AMR)}, lookup(err)
}
func (t *authorization) Bind(ctx context.Context, session identity.SessionID, client identity.ClientID) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE sessions SET oauth_client_id=$2 WHERE id=$1 AND oauth_client_id IS NULL`, session, client)
	return failure(err)
}
func (t *authorization) Consume(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE oauth_authorizations SET consumed_at=now() WHERE secret_hash=$1`, hash)
	return failure(err)
}
func (t *authorization) Commit() error   { return failure(t.tx.Commit()) }
func (t *authorization) Rollback() error { return failure(t.tx.Rollback()) }
func (r *Repository) Access(ctx context.Context, client *oauth.Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error) {
	var live bool
	err := r.db.GetContext(ctx, &live, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND environment_id=$2 AND user_id=$3 AND organization_id=$4 AND application_id=$5 AND resource_id=$6 AND revoked_at IS NULL AND expires_at>now())`, session, client.Environment, subject, organization, client.Application, client.Resource)
	if err != nil {
		return authentication.Access{}, failure(err)
	}
	if !live {
		return authentication.Access{}, errx.Unauthorized("session revoked")
	}
	return authpg.Resolve(ctx, r.db, authentication.Context{EnvironmentID: client.Environment, OrganizationID: organization, ApplicationID: client.Application, ResourceID: client.Resource}, subject)
}

// EndSession revokes one live session of the user and audits it in the
// same transaction.
func (r *Repository) EndSession(ctx context.Context, m oauth.Mutation, user identity.UserID, session identity.SessionID) (bool, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return false, failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND environment_id=$2 AND user_id=$3 AND revoked_at IS NULL`, session, m.Environment, user)
	if err != nil {
		return false, failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, failure(err)
	}
	if n == 0 {
		return false, nil
	}
	if err = eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return false, failure(err)
	}
	return true, failure(tx.Commit())
}

// nonNil keeps empty lists as [] (JSON and text[] alike).
func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

var _ oauth.Repository = (*Repository)(nil)
