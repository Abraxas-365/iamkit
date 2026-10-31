package authzpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
)

// ReplaceDescriptions swaps the resource's descriptions. The resource row
// is locked first, so a concurrent UpdateCatalog (which updates it) either
// ran before — and the set is checked against the catalog it left — or
// waits; descriptions of a removed permission cannot survive.
func (r *Repository) ReplaceDescriptions(ctx context.Context, m authorization.Mutation, resource identity.ResourceID, descriptions []authorization.PermissionDescription) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var catalog pq.StringArray
		err := tx.GetContext(ctx, &catalog, `SELECT permissions FROM resources WHERE environment_id=$1 AND id=$2 FOR UPDATE`, m.Environment, resource)
		if errors.Is(err, sql.ErrNoRows) {
			return errx.NotFound("resource not found")
		}
		if err != nil {
			return failure(err)
		}
		// The set was cleaned by the service; the locked catalog is the
		// one that counts.
		if _, err := authorization.ValidateDescriptions([]string(catalog), descriptions); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM permission_descriptions WHERE resource_id=$1`, resource); err != nil {
			return failure(err)
		}
		for _, d := range descriptions {
			if _, err := tx.ExecContext(ctx, `INSERT INTO permission_descriptions(environment_id,resource_id,permission,locale,display_name,description) VALUES($1,$2,$3,$4,$5,$6)`,
				m.Environment, resource, d.Permission, d.Locale, d.DisplayName, d.Description); err != nil {
				return failure(err)
			}
		}
		return audit(ctx, tx, m)
	})
}

func (r *Repository) ListDescriptions(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]authorization.PermissionDescription, error) {
	out := []authorization.PermissionDescription{}
	err := r.db.SelectContext(ctx, &out, `SELECT permission, locale, display_name, description FROM permission_descriptions WHERE environment_id=$1 AND resource_id=$2 ORDER BY permission, locale`, environment, resource)
	return out, failure(err)
}

var _ authorization.DescriptionRepository = (*Repository)(nil)
