package hostedpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

const textColumns = `environment_id, client_id, organization_id, locale, texts, updated_at`

// textRow is a hosted_texts row.
type textRow struct {
	Environment  identity.EnvironmentID   `db:"environment_id"`
	Client       *identity.ClientID       `db:"client_id"`
	Organization *identity.OrganizationID `db:"organization_id"`
	Locale       string                   `db:"locale"`
	Texts        []byte                   `db:"texts"`
	UpdatedAt    time.Time                `db:"updated_at"`
}

func (r textRow) texts() (hosted.Texts, error) {
	out := hosted.Texts{Environment: r.Environment, Client: r.Client, Organization: r.Organization, Locale: r.Locale, UpdatedAt: &r.UpdatedAt}
	if err := json.Unmarshal(r.Texts, &out.Messages); err != nil {
		return hosted.Texts{}, errx.Wrap(err, "decode hosted texts", errx.TypeInternal)
	}
	return out, nil
}

// scopeArgs are the nullable client and organization of a scope.
func scopeArgs(scope hosted.TextScope) (any, any) {
	var client, organization any
	if !scope.Client.IsZero() {
		client = scope.Client
	}
	if !scope.Organization.IsZero() {
		organization = scope.Organization
	}
	return client, organization
}

func (r *Repository) Texts(ctx context.Context, environment identity.EnvironmentID, scope hosted.TextScope, locale string) (hosted.Texts, error) {
	client, organization := scopeArgs(scope)
	var row textRow
	err := r.db.GetContext(ctx, &row, `SELECT `+textColumns+` FROM hosted_texts
		WHERE environment_id=$1 AND client_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND locale=$4`,
		environment, client, organization, locale)
	if errors.Is(err, sql.ErrNoRows) {
		return hosted.Texts{}, errx.NotFound("no custom texts")
	}
	if err != nil {
		return hosted.Texts{}, failure(err)
	}
	return row.texts()
}

func (r *Repository) ListTexts(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[hosted.Texts], error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM hosted_texts WHERE environment_id=$1`, environment); err != nil {
		return query.Paginated[hosted.Texts]{}, failure(err)
	}
	var rows []textRow
	err := r.db.SelectContext(ctx, &rows, `SELECT `+textColumns+` FROM hosted_texts WHERE environment_id=$1
		ORDER BY client_id NULLS FIRST, organization_id NULLS FIRST, locale LIMIT $2 OFFSET $3`, environment, page.Limit, page.Offset)
	if err != nil {
		return query.Paginated[hosted.Texts]{}, failure(err)
	}
	items := make([]hosted.Texts, 0, len(rows))
	for _, row := range rows {
		t, err := row.texts()
		if err != nil {
			return query.Paginated[hosted.Texts]{}, err
		}
		items = append(items, t)
	}
	return query.Paginated[hosted.Texts]{Items: items, Page: query.Page{Total: total, Limit: page.Limit, Offset: page.Offset}}, nil
}

func (r *Repository) ScopeTexts(ctx context.Context, environment identity.EnvironmentID, scope hosted.TextScope, locale string) ([]hosted.Texts, error) {
	client, organization := scopeArgs(scope)
	var rows []textRow
	err := r.db.SelectContext(ctx, &rows, `SELECT `+textColumns+` FROM hosted_texts
		WHERE environment_id=$1 AND locale=$4 AND (
			(client_id IS NULL AND organization_id IS NULL)
			OR (client_id = $2::uuid AND organization_id IS NULL)
			OR (organization_id = $3::uuid AND client_id IS NULL))`,
		environment, client, organization, locale)
	if err != nil {
		return nil, failure(err)
	}
	out := make([]hosted.Texts, 0, len(rows))
	for _, row := range rows {
		t, err := row.texts()
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (r *Repository) SaveTexts(ctx context.Context, m hosted.Mutation, input hosted.Texts) (hosted.Texts, error) {
	encoded, err := json.Marshal(input.Messages)
	if err != nil {
		return hosted.Texts{}, errx.Wrap(err, "encode hosted texts", errx.TypeInternal)
	}
	client, organization := scopeArgs(input.Target())
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return hosted.Texts{}, failure(err)
	}
	defer tx.Rollback()
	if err = textOwner(ctx, tx, m.Environment, input.Target()); err != nil {
		return hosted.Texts{}, err
	}
	var row textRow
	err = tx.GetContext(ctx, &row, `INSERT INTO hosted_texts(environment_id, client_id, organization_id, locale, texts) VALUES($1,$2::uuid,$3::uuid,$4,$5)
		ON CONFLICT (environment_id, COALESCE(client_id, '00000000-0000-0000-0000-000000000000'), COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'), locale)
		DO UPDATE SET texts=EXCLUDED.texts, updated_at=now()
		RETURNING `+textColumns, m.Environment, client, organization, input.Locale, encoded)
	if err != nil {
		return hosted.Texts{}, failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return hosted.Texts{}, err
	}
	if err = tx.Commit(); err != nil {
		return hosted.Texts{}, failure(err)
	}
	return row.texts()
}

func (r *Repository) DeleteTexts(ctx context.Context, m hosted.Mutation, scope hosted.TextScope, locale string) error {
	client, organization := scopeArgs(scope)
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM hosted_texts
		WHERE environment_id=$1 AND client_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND locale=$4`,
		m.Environment, client, organization, locale)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return failure(err)
	} else if n == 0 {
		return errx.NotFound("no custom texts in " + locale)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

// textOwner checks the scope's client or organization belongs to the
// environment.
func (r *Repository) Owner(ctx context.Context, environment identity.EnvironmentID, scope hosted.TextScope) error {
	return textOwner(ctx, r.db, environment, scope)
}

func textOwner(ctx context.Context, tx interface {
	GetContext(ctx context.Context, dest any, query string, args ...any) error
}, environment identity.EnvironmentID, scope hosted.TextScope) error {
	var exists bool
	switch {
	case !scope.Client.IsZero():
		if err := tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE id=$1 AND environment_id=$2)`, scope.Client, environment); err != nil {
			return failure(err)
		}
		if !exists {
			return errx.NotFound("oauth client not found")
		}
	case !scope.Organization.IsZero():
		if err := tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND environment_id=$2)`, scope.Organization, environment); err != nil {
			return failure(err)
		}
		if !exists {
			return errx.NotFound("organization not found")
		}
	}
	return nil
}
