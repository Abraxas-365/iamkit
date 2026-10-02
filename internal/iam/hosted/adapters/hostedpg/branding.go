package hostedpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// style is a branding row of login_settings or client_login_settings.
type style struct {
	Environment identity.EnvironmentID `db:"environment_id"`
	Client      *identity.ClientID     `db:"client_id"`
	DisplayName string                 `db:"display_name"`
	LogoURL     string                 `db:"logo_url"`
	AccentColor string                 `db:"accent_color"`
	Theme       []byte                 `db:"theme"`
	Locale      *string                `db:"locale"`
	Languages   pq.StringArray         `db:"languages"`
	Legal       []byte                 `db:"legal"`
	UpdatedAt   *time.Time             `db:"updated_at"`
}

func (s style) settings() (hosted.Settings, error) {
	out := hosted.Settings{Environment: s.Environment, Client: s.Client, DisplayName: s.DisplayName, LogoURL: s.LogoURL, AccentColor: s.AccentColor, Locale: s.Locale, Languages: []string(s.Languages), UpdatedAt: s.UpdatedAt}
	if out.Languages == nil {
		out.Languages = []string{}
	}
	out.Legal = &hosted.Legal{}
	if len(s.Legal) > 0 {
		if err := json.Unmarshal(s.Legal, out.Legal); err != nil {
			return hosted.Settings{}, errx.Wrap(err, "decode hosted legal links", errx.TypeInternal)
		}
	}
	if len(s.Theme) > 0 {
		if err := json.Unmarshal(s.Theme, &out.Theme); err != nil {
			return hosted.Settings{}, errx.Wrap(err, "decode hosted theme", errx.TypeInternal)
		}
	}
	return out, nil
}

func theme(s hosted.Settings) ([]byte, error) {
	out, err := json.Marshal(s.Theme)
	if err != nil {
		return nil, errx.Wrap(err, "encode hosted theme", errx.TypeInternal)
	}
	return out, nil
}

const (
	defaultColumns = `environment_id,NULL::uuid AS client_id,display_name,logo_url,accent_color,theme,locale,languages,legal,updated_at`
	clientColumns  = `environment_id,client_id,display_name,logo_url,accent_color,theme,locale,'{}'::text[] AS languages,legal,updated_at`
)

// legal encodes optional legal links (nil keeps the stored ones).
func legal(in *hosted.Legal) (any, error) {
	if in == nil {
		return nil, nil
	}
	out, err := json.Marshal(in)
	if err != nil {
		return nil, errx.Wrap(err, "encode hosted legal links", errx.TypeInternal)
	}
	return string(out), nil
}

// languages encodes an optional language list (nil keeps the stored one).
func languages(in []string) any {
	if in == nil {
		return nil
	}
	return pq.StringArray(in)
}

func (r *Repository) Settings(ctx context.Context, environment identity.EnvironmentID) (hosted.Settings, error) {
	var row style
	err := r.db.GetContext(ctx, &row, `SELECT `+defaultColumns+` FROM login_settings WHERE environment_id=$1`, environment)
	if errors.Is(err, sql.ErrNoRows) {
		unset := ""
		return hosted.Settings{Environment: environment, Locale: &unset, Languages: []string{}, Legal: &hosted.Legal{}}, nil
	}
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	return row.settings()
}

func (r *Repository) SaveSettings(ctx context.Context, m hosted.Mutation, input hosted.Settings) (hosted.Settings, error) {
	encoded, err := theme(input)
	if err != nil {
		return hosted.Settings{}, err
	}
	links, err := legal(input.Legal)
	if err != nil {
		return hosted.Settings{}, err
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	defer tx.Rollback()
	var row style
	err = tx.GetContext(ctx, &row, `INSERT INTO login_settings(environment_id,display_name,logo_url,accent_color,theme,locale,languages,legal) VALUES($1,$2,$3,$4,$5,COALESCE($6,''),COALESCE($7::text[],'{}'),COALESCE($8::jsonb,'{}'))
		ON CONFLICT (environment_id) DO UPDATE SET display_name=EXCLUDED.display_name, logo_url=EXCLUDED.logo_url, accent_color=EXCLUDED.accent_color, theme=EXCLUDED.theme, locale=COALESCE($6,login_settings.locale), languages=COALESCE($7::text[],login_settings.languages), legal=COALESCE($8::jsonb,login_settings.legal), updated_at=now()
		RETURNING `+defaultColumns, m.Environment, input.DisplayName, input.LogoURL, input.AccentColor, encoded, input.Locale, languages(input.Languages), links)
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return hosted.Settings{}, err
	}
	if err = tx.Commit(); err != nil {
		return hosted.Settings{}, failure(err)
	}
	return row.settings()
}

func (r *Repository) ClientSettings(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (hosted.Settings, error) {
	var row style
	err := r.db.GetContext(ctx, &row, `SELECT `+clientColumns+` FROM client_login_settings WHERE environment_id=$1 AND client_id=$2`, environment, client)
	if errors.Is(err, sql.ErrNoRows) {
		return hosted.Settings{}, errx.NotFound("client uses the environment branding")
	}
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	return row.settings()
}

func (r *Repository) ListClientSettings(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[hosted.Settings], error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM client_login_settings WHERE environment_id=$1`, environment); err != nil {
		return query.Paginated[hosted.Settings]{}, failure(err)
	}
	rows := []style{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+clientColumns+` FROM client_login_settings WHERE environment_id=$1 ORDER BY updated_at DESC, client_id LIMIT $2 OFFSET $3`, environment, page.Limit, page.Offset); err != nil {
		return query.Paginated[hosted.Settings]{}, failure(err)
	}
	items := make([]hosted.Settings, 0, len(rows))
	for _, row := range rows {
		s, err := row.settings()
		if err != nil {
			return query.Paginated[hosted.Settings]{}, err
		}
		items = append(items, s)
	}
	return query.Paginated[hosted.Settings]{Items: items, Page: query.Page{Total: total, Limit: page.Limit, Offset: page.Offset}}, nil
}

func (r *Repository) SaveClientSettings(ctx context.Context, m hosted.Mutation, client identity.ClientID, input hosted.Settings) (hosted.Settings, error) {
	encoded, err := theme(input)
	if err != nil {
		return hosted.Settings{}, err
	}
	links, err := legal(input.Legal)
	if err != nil {
		return hosted.Settings{}, err
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE id=$1 AND environment_id=$2)`, client, m.Environment); err != nil {
		return hosted.Settings{}, failure(err)
	}
	if !exists {
		return hosted.Settings{}, errx.NotFound("oauth client not found")
	}
	var row style
	err = tx.GetContext(ctx, &row, `INSERT INTO client_login_settings(client_id,environment_id,display_name,logo_url,accent_color,theme,locale,legal) VALUES($1,$2,$3,$4,$5,$6,COALESCE($7,''),COALESCE($8::jsonb,'{}'))
		ON CONFLICT (client_id) DO UPDATE SET display_name=EXCLUDED.display_name, logo_url=EXCLUDED.logo_url, accent_color=EXCLUDED.accent_color, theme=EXCLUDED.theme, locale=COALESCE($7,client_login_settings.locale), legal=COALESCE($8::jsonb,client_login_settings.legal), updated_at=now()
		RETURNING `+clientColumns, client, m.Environment, input.DisplayName, input.LogoURL, input.AccentColor, encoded, input.Locale, links)
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return hosted.Settings{}, err
	}
	if err = tx.Commit(); err != nil {
		return hosted.Settings{}, failure(err)
	}
	return row.settings()
}

func (r *Repository) DeleteClientSettings(ctx context.Context, m hosted.Mutation, client identity.ClientID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM client_login_settings WHERE client_id=$1 AND environment_id=$2`, client, m.Environment)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return failure(err)
	} else if n == 0 {
		return errx.NotFound("client uses the environment branding")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func audit(ctx context.Context, tx sqlx.ExecerContext, m hosted.Mutation) error {
	return failure(eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target))
}
