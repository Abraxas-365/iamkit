package fedpg

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "federation persistence failed", errx.TypeInternal)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		if pg.Constraint == "federation_connections_enforced" {
			return errx.Conflict("the organization already has an enforced SSO connection")
		}
		return errx.Conflict("conflicting or out-of-bound federation connection")
	}
	return failure(err)
}

// connectionRow maps nullable columns onto federation.Connection.
type connectionRow struct {
	ID           identity.ConnectionID   `db:"id"`
	Environment  identity.EnvironmentID  `db:"environment_id"`
	Organization identity.OrganizationID `db:"organization_id"`
	Name         string                  `db:"name"`
	Issuer       string                  `db:"issuer"`
	Client       string                  `db:"client_id"`
	SecretEnv    sql.NullString          `db:"secret_env"`
	Sealed       sql.NullString          `db:"secret_sealed"`
	JIT          bool                    `db:"jit_provisioning"`
	JITGroup     identity.GroupID        `db:"jit_group_id"`
	Enforcement  string                  `db:"enforcement"`
}

func (r connectionRow) connection() federation.Connection {
	return federation.Connection{ID: r.ID, Environment: r.Environment, Organization: r.Organization, Name: r.Name, Issuer: r.Issuer, Client: r.Client, SecretEnv: r.SecretEnv.String, Sealed: r.Sealed.String, JIT: r.JIT, JITGroup: r.JITGroup, Enforcement: r.Enforcement}
}

func null(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func audit(ctx context.Context, tx *sqlx.Tx, m federation.Mutation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	return failure(err)
}

func (r *Repository) Create(ctx context.Context, m federation.Mutation, c federation.Connection) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO federation_connections(id,environment_id,organization_id,name,issuer,client_id,secret_env,secret_sealed,jit_provisioning,jit_group_id,enforcement) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		c.ID, c.Environment, c.Organization, c.Name, c.Issuer, c.Client, null(c.SecretEnv), null(c.Sealed), c.JIT, c.JITGroup, c.Enforcement); err != nil {
		return conflict(err)
	}
	m.Target += "/" + c.ID.String()
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

// Update rewrites the mutable settings of an active connection. When the
// secret changes, the legacy reference is cleared in the same statement.
func (r *Repository) Update(ctx context.Context, m federation.Mutation, c federation.Connection) error {
	return r.mutate(ctx, m, `UPDATE federation_connections SET name=$3,secret_env=$4,secret_sealed=$5,jit_provisioning=$6,jit_group_id=$7,enforcement=$8 WHERE id=$1 AND environment_id=$2 AND active`,
		c.ID, c.Environment, c.Name, null(c.SecretEnv), null(c.Sealed), c.JIT, c.JITGroup, c.Enforcement)
}

const connectionColumns = `id,environment_id,organization_id,name,issuer,client_id,secret_env,secret_sealed,jit_provisioning,jit_group_id,enforcement`

func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.Connection, error) {
	var row connectionRow
	err := r.db.GetContext(ctx, &row, `SELECT `+connectionColumns+` FROM federation_connections WHERE id=$1 AND environment_id=$2 AND active`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.Connection{}, errx.NotFound("resource not found")
	}
	return row.connection(), failure(err)
}
func (r *Repository) SaveState(ctx context.Context, hash []byte, s federation.State) error {
	var continuation *string
	if s.Continuation != "" {
		continuation = &s.Continuation
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO federation_states(secret_hash,connection_id,environment_id,organization_id,application_id,resource_id,binding_hash,nonce,verifier,continuation,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+make_interval(secs => $11))`, hash, s.Connection, s.Boundary.EnvironmentID, s.Boundary.OrganizationID, s.Boundary.ApplicationID, s.Boundary.ResourceID, s.Binding, s.Nonce, s.Verifier, continuation, config.FederationStateTTL.Seconds())
	return conflict(err)
}
func (r *Repository) ConsumeState(ctx context.Context, hash, binding []byte) (federation.State, error) {
	var out federation.State
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return out, failure(err)
	}
	defer tx.Rollback()
	var row struct {
		Connection   identity.ConnectionID   `db:"connection_id"`
		Environment  identity.EnvironmentID  `db:"environment_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Application  identity.ApplicationID  `db:"application_id"`
		Resource     identity.ResourceID     `db:"resource_id"`
		Binding      []byte                  `db:"binding_hash"`
		Nonce        string                  `db:"nonce"`
		Verifier     string                  `db:"verifier"`
		Continuation sql.NullString          `db:"continuation"`
	}
	err = tx.GetContext(ctx, &row, `SELECT connection_id,environment_id,organization_id,application_id,resource_id,binding_hash,nonce,verifier,continuation FROM federation_states WHERE secret_hash=$1 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, failure(err)
	}
	if errors.Is(err, sql.ErrNoRows) || subtle.ConstantTimeCompare(row.Binding, binding) != 1 {
		return out, errx.Unauthorized("invalid federation state or browser binding")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE federation_states SET consumed_at=now(), continuation=NULL WHERE secret_hash=$1`, hash); err != nil {
		return out, failure(err)
	}
	out = federation.State{Connection: row.Connection, Boundary: authentication.Context{EnvironmentID: row.Environment, OrganizationID: row.Organization, ApplicationID: row.Application, ResourceID: row.Resource}, Binding: row.Binding, Nonce: row.Nonce, Verifier: row.Verifier, Continuation: row.Continuation.String}
	return out, failure(tx.Commit())
}
func (r *Repository) LinkedUser(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, subject string) (authentication.Transaction, identity.UserID, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, identity.UserID{}, failure(err)
	}
	var user identity.UserID
	err = tx.GetContext(ctx, &user, `SELECT u.id FROM external_identities x JOIN users u ON u.id=x.user_id AND u.environment_id=x.environment_id WHERE x.connection_id=$1 AND x.environment_id=$2 AND x.subject=$3 AND u.active FOR UPDATE OF u`, connection, environment, subject)
	if err != nil {
		tx.Rollback()
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, identity.UserID{}, failure(err)
		}
		return nil, identity.UserID{}, nil
	}
	return authpg.Wrap(tx), user, nil
}
func (r *Repository) mutate(ctx context.Context, m federation.Mutation, query string, args ...any) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return conflict(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}
func (r *Repository) Link(ctx context.Context, m federation.Mutation, connection identity.ConnectionID, user identity.UserID, subject string) error {
	return r.mutate(ctx, m, `INSERT INTO external_identities(connection_id,environment_id,user_id,subject) VALUES($1,$2,$3,$4)`, connection, m.Environment, user, subject)
}
func (r *Repository) Disable(ctx context.Context, m federation.Mutation, id identity.ConnectionID) error {
	return r.mutate(ctx, m, `UPDATE federation_connections SET active=false WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, filter federation.ConnectionFilter, page query.Pagination) (query.Paginated[federation.ConnectionView], error) {
	base := `FROM federation_connections c WHERE c.environment_id=$1`
	args := []any{environment}
	n := 1
	if !filter.Organization.IsZero() {
		n++
		base += fmt.Sprintf(" AND c.organization_id=$%d", n)
		args = append(args, filter.Organization)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (c.name ILIKE $%d OR c.issuer ILIKE $%d)", n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[federation.ConnectionView]{}, failure(err)
	}
	out := []federation.ConnectionView{}
	sel := fmt.Sprintf(`SELECT c.id, c.organization_id, c.name, c.issuer, c.client_id, c.active, c.jit_provisioning, c.enforcement,
		(SELECT COUNT(*) FROM external_identities x WHERE x.connection_id=c.id) AS linked
		%s ORDER BY c.name LIMIT %d OFFSET %d`, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &out, sel, args...); err != nil {
		return query.Paginated[federation.ConnectionView]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}
func (r *Repository) FindDetail(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.ConnectionDetail, error) {
	var out federation.ConnectionDetail
	err := r.db.GetContext(ctx, &out, `SELECT c.id, c.organization_id, c.name, c.issuer, c.client_id, COALESCE(c.secret_env,'') AS secret_env,
		CASE WHEN c.secret_sealed IS NULL THEN 'env' ELSE 'sealed' END AS secret_source,
		c.active, c.jit_provisioning, c.jit_group_id, c.enforcement, c.created_at,
		(SELECT COUNT(*) FROM external_identities x WHERE x.connection_id=c.id) AS linked
		FROM federation_connections c WHERE c.id=$1 AND c.environment_id=$2`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.ConnectionDetail{}, errx.NotFound("federation connection not found")
	}
	return out, failure(err)
}
func (r *Repository) Identities(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID, page query.Pagination) (query.Paginated[federation.ExternalIdentityView], error) {
	base := `FROM external_identities x JOIN users u ON u.id=x.user_id AND u.environment_id=x.environment_id WHERE x.connection_id=$1 AND x.environment_id=$2`
	args := []any{connectionID, environment}
	n := 2
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (x.subject ILIKE $%d OR u.name ILIKE $%d OR u.email ILIKE $%d)", n, n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[federation.ExternalIdentityView]{}, failure(err)
	}
	rows := []federation.ExternalIdentityView{}
	sel := fmt.Sprintf("SELECT x.connection_id, x.subject, x.user_id, u.name AS user_name, u.email AS user_email, x.origin, x.created_at %s ORDER BY u.name LIMIT %d OFFSET %d", base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &rows, sel, args...); err != nil {
		return query.Paginated[federation.ExternalIdentityView]{}, failure(err)
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) Unlink(ctx context.Context, m federation.Mutation, connectionID identity.ConnectionID, userID identity.UserID) error {
	return r.mutate(ctx, m, `DELETE FROM external_identities WHERE connection_id=$1 AND environment_id=$2 AND user_id=$3`, connectionID, m.Environment, userID)
}

var _ federation.Repository = (*Repository)(nil)
