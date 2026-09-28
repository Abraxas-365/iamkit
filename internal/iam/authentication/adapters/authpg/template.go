package authpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// TemplateRepository implements authentication.TemplateRepository.
type TemplateRepository struct{ db *sqlx.DB }

func NewTemplateRepository(db *sqlx.DB) *TemplateRepository { return &TemplateRepository{db} }

var _ authentication.TemplateRepository = (*TemplateRepository)(nil)

type templateRow struct {
	Purpose   string    `db:"purpose"`
	Locale    string    `db:"locale"`
	Subject   string    `db:"subject"`
	Heading   string    `db:"heading"`
	Body      string    `db:"body"`
	Action    string    `db:"action"`
	Footer    string    `db:"footer"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (r templateRow) template() authentication.EmailTemplate {
	return authentication.EmailTemplate{Purpose: r.Purpose, Locale: r.Locale, UpdatedAt: r.UpdatedAt,
		Copy: authentication.Copy{Subject: r.Subject, Heading: r.Heading, Body: r.Body, Action: r.Action, Footer: r.Footer}}
}

const templateColumns = `purpose, locale, subject, heading, body, action, footer, updated_at`

func (r *TemplateRepository) ListTemplates(ctx context.Context, environment identity.EnvironmentID) ([]authentication.EmailTemplate, error) {
	var rows []templateRow
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+templateColumns+` FROM email_templates WHERE environment_id = $1 ORDER BY purpose, locale`, environment); err != nil {
		return nil, errx.Wrap(err, "list email templates", errx.TypeInternal)
	}
	out := make([]authentication.EmailTemplate, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.template())
	}
	return out, nil
}

func (r *TemplateRepository) GetTemplate(ctx context.Context, environment identity.EnvironmentID, key authentication.TemplateKey) (authentication.EmailTemplate, error) {
	var row templateRow
	err := r.db.GetContext(ctx, &row, `SELECT `+templateColumns+` FROM email_templates WHERE environment_id = $1 AND purpose = $2 AND locale = $3`, environment, key.Purpose, key.Locale)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.EmailTemplate{}, errx.NotFound("email template not customized")
	}
	if err != nil {
		return authentication.EmailTemplate{}, errx.Wrap(err, "read email template", errx.TypeInternal)
	}
	return row.template(), nil
}

func (r *TemplateRepository) SetTemplate(ctx context.Context, m authentication.Mutation, key authentication.TemplateKey, input authentication.Copy) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "save email template", errx.TypeInternal)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO email_templates (environment_id, purpose, locale, subject, heading, body, action, footer)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (environment_id, purpose, locale) DO UPDATE SET subject = $4, heading = $5, body = $6, action = $7, footer = $8, updated_at = now()`,
		m.Environment, key.Purpose, key.Locale, input.Subject, input.Heading, input.Body, input.Action, input.Footer)
	if err != nil {
		return errx.Wrap(err, "save email template", errx.TypeInternal)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "save email template")
}

// DeleteTemplate is idempotent: resetting an uncustomized email is still
// audited, as the operator asked for it.
func (r *TemplateRepository) DeleteTemplate(ctx context.Context, m authentication.Mutation, key authentication.TemplateKey) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "reset email template", errx.TypeInternal)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM email_templates WHERE environment_id = $1 AND purpose = $2 AND locale = $3`, m.Environment, key.Purpose, key.Locale); err != nil {
		return errx.Wrap(err, "reset email template", errx.TypeInternal)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "reset email template")
}
