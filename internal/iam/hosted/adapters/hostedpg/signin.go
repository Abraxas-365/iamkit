package hostedpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/lib/pq"
)

// signInRow is a row of client_sign_in.
type signInRow struct {
	Environment     identity.EnvironmentID `db:"environment_id"`
	Client          identity.ClientID      `db:"client_id"`
	Password        bool                   `db:"password"`
	EmailCode       bool                   `db:"email_code"`
	OrganizationSSO bool                   `db:"organization_sso"`
	AllConnections  bool                   `db:"all_connections"`
	Connections     pq.StringArray         `db:"connections"`
	Signup          bool                   `db:"signup"`
	Passkey         bool                   `db:"passkey"`
	UpdatedAt       time.Time              `db:"updated_at"`
}

func (r signInRow) signIn() (hosted.SignIn, error) {
	out := hosted.SignIn{Environment: r.Environment, Client: r.Client, Password: r.Password, EmailCode: r.EmailCode, OrganizationSSO: r.OrganizationSSO,
		AllConnections: r.AllConnections, Connections: make([]identity.ConnectionID, 0, len(r.Connections)), Signup: r.Signup, Passkey: r.Passkey, Custom: true, UpdatedAt: &r.UpdatedAt}
	for _, raw := range r.Connections {
		id, err := identity.ParseConnectionID(raw)
		if err != nil {
			return hosted.SignIn{}, errx.Wrap(err, "stored sign-in connection is invalid", errx.TypeInternal)
		}
		out.Connections = append(out.Connections, id)
	}
	return out, nil
}

const signInColumns = `environment_id,client_id,password,email_code,organization_sso,all_connections,connections::text[] AS connections,signup,passkey,updated_at`

func (r *Repository) SignIn(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (hosted.SignIn, bool, error) {
	var row signInRow
	err := r.db.GetContext(ctx, &row, `SELECT `+signInColumns+` FROM client_sign_in WHERE environment_id=$1 AND client_id=$2`, environment, client)
	if errors.Is(err, sql.ErrNoRows) {
		return hosted.SignIn{}, false, nil
	}
	if err != nil {
		return hosted.SignIn{}, false, failure(err)
	}
	out, err := row.signIn()
	return out, err == nil, err
}

func (r *Repository) ListSignIn(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[hosted.SignIn], error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM client_sign_in WHERE environment_id=$1`, environment); err != nil {
		return query.Paginated[hosted.SignIn]{}, failure(err)
	}
	rows := []signInRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+signInColumns+` FROM client_sign_in WHERE environment_id=$1 ORDER BY updated_at DESC, client_id LIMIT $2 OFFSET $3`, environment, page.Limit, page.Offset); err != nil {
		return query.Paginated[hosted.SignIn]{}, failure(err)
	}
	items := make([]hosted.SignIn, 0, len(rows))
	for _, row := range rows {
		s, err := row.signIn()
		if err != nil {
			return query.Paginated[hosted.SignIn]{}, err
		}
		items = append(items, s)
	}
	return query.Paginated[hosted.SignIn]{Items: items, Page: query.Page{Total: total, Limit: page.Limit, Offset: page.Offset}}, nil
}

func (r *Repository) SaveSignIn(ctx context.Context, m hosted.Mutation, client identity.ClientID, input hosted.SignIn) (hosted.SignIn, error) {
	connections := make([]string, 0, len(input.Connections))
	for _, c := range input.Connections {
		connections = append(connections, c.String())
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return hosted.SignIn{}, failure(err)
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE id=$1 AND environment_id=$2)`, client, m.Environment); err != nil {
		return hosted.SignIn{}, failure(err)
	}
	if !exists {
		return hosted.SignIn{}, errx.NotFound("oauth client not found")
	}
	var row signInRow
	err = tx.GetContext(ctx, &row, `INSERT INTO client_sign_in(client_id,environment_id,password,email_code,organization_sso,all_connections,connections,signup,passkey) VALUES($1,$2,$3,$4,$5,$6,$7::uuid[],$8,$9)
		ON CONFLICT (client_id) DO UPDATE SET password=EXCLUDED.password, email_code=EXCLUDED.email_code, organization_sso=EXCLUDED.organization_sso,
			all_connections=EXCLUDED.all_connections, connections=EXCLUDED.connections, signup=EXCLUDED.signup, passkey=EXCLUDED.passkey, updated_at=now()
		RETURNING `+signInColumns, client, m.Environment, input.Password, input.EmailCode, input.OrganizationSSO, input.AllConnections, pq.Array(connections), input.Signup, input.Passkey)
	if err != nil {
		return hosted.SignIn{}, failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return hosted.SignIn{}, err
	}
	if err = tx.Commit(); err != nil {
		return hosted.SignIn{}, failure(err)
	}
	return row.signIn()
}

func (r *Repository) DeleteSignIn(ctx context.Context, m hosted.Mutation, client identity.ClientID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM client_sign_in WHERE client_id=$1 AND environment_id=$2`, client, m.Environment)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return failure(err)
	} else if n == 0 {
		return errx.NotFound("client offers every sign-in method")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}
