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
)

// organizationStyle is an organization_login_settings row; NULL inherits.
type organizationStyle struct {
	Environment  identity.EnvironmentID  `db:"environment_id"`
	Organization identity.OrganizationID `db:"organization_id"`
	DisplayName  *string                 `db:"display_name"`
	LogoURL      *string                 `db:"logo_url"`
	AccentColor  *string                 `db:"accent_color"`
	Theme        []byte                  `db:"theme"`
	Locale       *string                 `db:"locale"`
	UpdatedAt    time.Time               `db:"updated_at"`
}

func (s organizationStyle) settings() (hosted.OrganizationSettings, error) {
	updated := s.UpdatedAt
	out := hosted.OrganizationSettings{Environment: s.Environment, Organization: s.Organization, DisplayName: s.DisplayName, LogoURL: s.LogoURL, AccentColor: s.AccentColor, Locale: s.Locale, UpdatedAt: &updated}
	if s.Theme != nil {
		out.Theme = &hosted.Theme{}
		if err := json.Unmarshal(s.Theme, out.Theme); err != nil {
			return hosted.OrganizationSettings{}, errx.Wrap(err, "decode organization theme", errx.TypeInternal)
		}
	}
	return out, nil
}

const organizationColumns = `environment_id,organization_id,display_name,logo_url,accent_color,theme,locale,updated_at`

func (r *Repository) OrganizationSettings(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (hosted.OrganizationSettings, error) {
	var row organizationStyle
	err := r.db.GetContext(ctx, &row, `SELECT `+organizationColumns+` FROM organization_login_settings WHERE environment_id=$1 AND organization_id=$2`, environment, organization)
	if errors.Is(err, sql.ErrNoRows) {
		return hosted.OrganizationSettings{}, errx.NotFound("organization uses the client or environment branding")
	}
	if err != nil {
		return hosted.OrganizationSettings{}, failure(err)
	}
	return row.settings()
}

func (r *Repository) SaveOrganizationSettings(ctx context.Context, m hosted.Mutation, organization identity.OrganizationID, input hosted.OrganizationSettings) (hosted.OrganizationSettings, error) {
	var encoded any // NULL inherits the theme
	if input.Theme != nil {
		raw, err := json.Marshal(input.Theme)
		if err != nil {
			return hosted.OrganizationSettings{}, errx.Wrap(err, "encode organization theme", errx.TypeInternal)
		}
		encoded = string(raw)
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return hosted.OrganizationSettings{}, failure(err)
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND environment_id=$2)`, organization, m.Environment); err != nil {
		return hosted.OrganizationSettings{}, failure(err)
	}
	if !exists {
		return hosted.OrganizationSettings{}, errx.NotFound("organization not found")
	}
	var row organizationStyle
	err = tx.GetContext(ctx, &row, `INSERT INTO organization_login_settings(organization_id,environment_id,display_name,logo_url,accent_color,theme,locale) VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (organization_id) DO UPDATE SET display_name=EXCLUDED.display_name, logo_url=EXCLUDED.logo_url, accent_color=EXCLUDED.accent_color, theme=EXCLUDED.theme, locale=EXCLUDED.locale, updated_at=now()
		RETURNING `+organizationColumns, organization, m.Environment, input.DisplayName, input.LogoURL, input.AccentColor, encoded, input.Locale)
	if err != nil {
		return hosted.OrganizationSettings{}, failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return hosted.OrganizationSettings{}, err
	}
	if err = tx.Commit(); err != nil {
		return hosted.OrganizationSettings{}, failure(err)
	}
	return row.settings()
}

func (r *Repository) DeleteOrganizationSettings(ctx context.Context, m hosted.Mutation, organization identity.OrganizationID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM organization_login_settings WHERE organization_id=$1 AND environment_id=$2`, organization, m.Environment)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return failure(err)
	} else if n == 0 {
		return errx.NotFound("organization uses the client or environment branding")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) DomainOrganization(ctx context.Context, environment identity.EnvironmentID, domain string) (identity.OrganizationID, error) {
	var out identity.OrganizationID
	err := r.db.GetContext(ctx, &out, `SELECT d.organization_id FROM organization_domains d
		JOIN organizations o ON o.id=d.organization_id AND o.environment_id=d.environment_id AND o.active
		WHERE d.environment_id=$1 AND d.domain=$2 AND d.verified_at IS NOT NULL`, environment, domain)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.OrganizationID{}, nil
	}
	return out, failure(err)
}
