package riskpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// Recipients finds where security alerts go: a human user's verified email.
type Recipients struct{ db *sqlx.DB }

func NewRecipients(db *sqlx.DB) *Recipients { return &Recipients{db} }

// Email returns the user's verified email ("" when the user has none or it
// is unverified: nobody is alerted at an address they never proved).
func (r *Recipients) Email(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (string, error) {
	var email string
	err := r.db.GetContext(ctx, &email,
		`SELECT email FROM users WHERE environment_id = $1 AND id = $2 AND active AND email_verified AND email IS NOT NULL`, environment, user)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", errx.Wrap(err, "find alert recipient", errx.TypeInternal)
	}
	return email, nil
}
