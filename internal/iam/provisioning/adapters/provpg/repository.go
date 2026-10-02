package provpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "provisioning persistence failed", errx.TypeInternal)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("identity exists or is outside provisioning boundary; explicit linking required")
	}
	return failure(err)
}
func mutability(message string) error {
	return errx.Validation(message).WithDetail("scimType", "mutability")
}

const selectUser = `SELECT u.id,u.email,coalesce(m.display_name,u.name) AS name,(u.active AND m.active) AS active,i.external_id,i.external_id_source,i.version,i.created_at,i.updated_at,coalesce(m.manager_id::text,'') AS manager_id,u.phone ` + fromUsers

// fromUsers selects live (not deprovisioned) identities of the connection that
// still belong to its organization.
const fromUsers = `FROM provisioned_identities i JOIN users u ON u.id=i.user_id AND u.environment_id=i.environment_id JOIN memberships m ON m.user_id=u.id AND m.environment_id=u.environment_id AND m.organization_id=$3 WHERE i.connection_id=$1 AND i.environment_id=$2 AND i.deprovisioned_at IS NULL`

// countUsers uses the same joins as selectUser so totalResults matches the rows.
const countUsers = `SELECT count(*) ` + fromUsers

// filterSQL matches SCIM "eq" filters (field $%[1]d, value $%[2]d).
// emails.value matches the primary address or an alias this connection
// reported; externalId matches only directory-supplied anchors.
const filterSQL = `($%[1]d='' OR ($%[1]d='userName' AND u.email=lower($%[2]d)) OR ($%[1]d='emails.value' AND (u.email=lower($%[2]d) OR EXISTS(SELECT 1 FROM provisioned_emails e WHERE e.connection_id=i.connection_id AND e.user_id=u.id AND e.email=lower($%[2]d)))) OR ($%[1]d='externalId' AND i.external_id_source='client' AND i.external_id=$%[2]d) OR ($%[1]d='id' AND u.id::text=lower($%[2]d)))`

func (r *Repository) Authenticate(ctx context.Context, hash []byte) (provisioning.Principal, error) {
	var row struct {
		ID           identity.CredentialID   `db:"id"`
		Environment  identity.EnvironmentID  `db:"environment_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Connection   identity.ConnectionID   `db:"connection_id"`
		MapPhone     bool                    `db:"map_phone"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT k.id,k.environment_id,k.organization_id,k.connection_id,c.map_phone FROM provisioning_credentials k JOIN organizations o ON o.id=k.organization_id AND o.environment_id=k.environment_id JOIN provisioning_connections c ON c.id=k.connection_id AND c.environment_id=k.environment_id WHERE k.secret_hash=$1 AND k.revoked_at IS NULL AND k.expires_at>now() AND o.active`, hash)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return provisioning.Principal{}, failure(err)
		}
		return provisioning.Principal{}, errx.Unauthorized("invalid credential")
	}
	return provisioning.Principal{ID: row.ID, Environment: row.Environment, Organization: row.Organization, Connection: row.Connection, MapPhone: row.MapPhone}, nil
}
func find(ctx context.Context, q sqlx.QueryerContext, p provisioning.Principal, id identity.UserID) (provisioning.User, error) {
	var row provisioning.User
	err := sqlx.GetContext(ctx, q, &row, selectUser+` AND u.id=$4`, p.Connection, p.Environment, p.Organization, id)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.User{}, errx.NotFound("user not found")
	}
	if err != nil {
		return row, failure(err)
	}
	if !p.MapPhone {
		row.Phone = ""
	}
	row.Aliases, err = aliases(ctx, q, p, id)
	return row, err
}

// aliases returns the secondary addresses this connection reported for id.
func aliases(ctx context.Context, q sqlx.QueryerContext, p provisioning.Principal, id identity.UserID) ([]provisioning.Email, error) {
	out := []provisioning.Email{}
	err := sqlx.SelectContext(ctx, q, &out, `SELECT e.email AS value,e.type FROM provisioned_emails e JOIN users u ON u.id=e.user_id AND u.environment_id=e.environment_id WHERE e.connection_id=$1 AND e.user_id=$2 AND e.email<>u.email ORDER BY e.created_at,e.email`, p.Connection, id)
	return out, failure(err)
}
func (r *Repository) Find(ctx context.Context, p provisioning.Principal, id identity.UserID) (provisioning.User, error) {
	return find(ctx, r.db, p, id)
}
func (r *Repository) List(ctx context.Context, p provisioning.Principal, f provisioning.Filter) ([]provisioning.User, int, error) {
	rows := []provisioning.User{}
	err := r.db.SelectContext(ctx, &rows, selectUser+` AND `+fmt.Sprintf(filterSQL, 4, 5)+` ORDER BY u.id LIMIT $6 OFFSET $7`, p.Connection, p.Environment, p.Organization, f.Field, f.Value, f.Count, f.Start-1)
	if err != nil {
		return nil, 0, failure(err)
	}
	for i := range rows {
		if !p.MapPhone {
			rows[i].Phone = ""
		}
		if rows[i].Aliases, err = aliases(ctx, r.db, p, rows[i].ID); err != nil {
			return nil, 0, err
		}
	}
	var total int
	err = r.db.GetContext(ctx, &total, countUsers+` AND `+fmt.Sprintf(filterSQL, 4, 5), p.Connection, p.Environment, p.Organization, f.Field, f.Value)
	if err != nil {
		return nil, 0, failure(err)
	}
	return rows, total, nil
}

// Create provisions u and returns the resulting user id, which differs from
// u.ID when an earlier deprovisioned identity is reactivated or an existing
// organization member is adopted.
func (r *Repository) Create(ctx context.Context, p provisioning.Principal, u provisioning.User) (identity.UserID, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return u.ID, failure(err)
	}
	defer tx.Rollback()
	// Serialize creates per connection so reactivation/adoption decisions are stable.
	var policy struct {
		Adopt bool   `db:"adopt_existing_members"`
		Scope string `db:"adopt_scope"`
	}
	if err = tx.GetContext(ctx, &policy, `SELECT adopt_existing_members,adopt_scope FROM provisioning_connections WHERE id=$1 AND environment_id=$2 FOR UPDATE`, p.Connection, p.Environment); err != nil {
		return u.ID, failure(err)
	}
	id, err := r.claim(ctx, tx, p, u)
	mode := "claimed"
	if err == nil && id.IsZero() {
		id, err = r.reactivate(ctx, tx, p, u)
		mode = "reactivated"
	}
	if err == nil && id.IsZero() && policy.Adopt {
		id, err = r.adopt(ctx, tx, p, u, policy.Scope)
		mode = "adopted"
	}
	if err == nil && id.IsZero() {
		id, err = u.ID, r.insert(ctx, tx, p, u)
		mode = ""
	}
	if err != nil {
		return id, err
	}
	if mode == "" {
		err = eventpg.UserCreated(ctx, tx, p.Environment, p.ID.String(), id, p.Organization, "scim")
	} else {
		err = scimEvent(ctx, tx, p, event.UserProvisioned, id, map[string]any{"mode": mode})
	}
	if err != nil {
		return id, err
	}
	if u.Manager != "" {
		if err = setManager(ctx, tx, p, id, u.Manager); err != nil {
			return id, err
		}
	}
	if p.MapPhone && u.Phone != "" {
		if err = setPhone(ctx, tx, p, id, u.Phone); err != nil {
			return id, err
		}
	}
	return id, failure(tx.Commit())
}

func (r *Repository) insert(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, u provisioning.User) error {
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,environment_id,email,name,password_hash,home_organization_id) VALUES($1,$2,$3,$4,'',$5)`, []any{u.ID, p.Environment, u.Email, u.Name, p.Organization}},
		{`INSERT INTO memberships(environment_id,organization_id,user_id,active) VALUES($1,$2,$3,$4)`, []any{p.Environment, p.Organization, u.ID, u.Active}},
		{`INSERT INTO provisioned_identities(connection_id,environment_id,user_id,external_id,external_id_source,origin) VALUES($1,$2,$3,$4,$5,'created')`, []any{p.Connection, p.Environment, u.ID, u.External, u.ExternalSource}},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return conflict(err)
		}
	}
	return replaceAliases(ctx, tx, p, u.ID, u.Aliases)
}

// claim resolves a create that carries a client externalId for a live
// identity this connection anchored internally (no externalId was ever sent,
// or migration 002 re-keyed an email-valued externalId): the directory is
// naming its own user, so the anchor is upgraded instead of failing with 409.
func (r *Repository) claim(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, u provisioning.User) (identity.UserID, error) {
	var id identity.UserID
	if u.ExternalSource != provisioning.AnchorClient {
		return id, nil
	}
	err := tx.GetContext(ctx, &id, `SELECT i.user_id FROM provisioned_identities i JOIN users u ON u.id=i.user_id AND u.environment_id=i.environment_id
		WHERE i.connection_id=$1 AND i.environment_id=$2 AND i.deprovisioned_at IS NULL AND i.external_id_source='derived' AND u.email=$3
		FOR UPDATE OF i`, p.Connection, p.Environment, u.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return id, nil
	}
	if err != nil {
		return id, failure(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE provisioned_identities SET external_id=$3,external_id_source='client',updated_at=now(),version=version+1 WHERE connection_id=$1 AND user_id=$2`, p.Connection, id, u.External); err != nil {
		return id, conflict(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE memberships SET active=$4,display_name=$5 WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, id, u.Active, u.Name); err != nil {
		return id, failure(err)
	}
	return id, replaceAliases(ctx, tx, p, id, u.Aliases)
}

// reactivate restores an identity deprovisioned by SCIM DELETE when the
// directory creates it again: same client externalId, or same userName when
// the stored identity never had a client anchor. A different client anchor on
// a reused address is a different person and is not matched (409).
func (r *Repository) reactivate(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, u provisioning.User) (identity.UserID, error) {
	var id identity.UserID
	err := tx.GetContext(ctx, &id, `SELECT i.user_id FROM provisioned_identities i JOIN users u ON u.id=i.user_id AND u.environment_id=i.environment_id
		WHERE i.connection_id=$1 AND i.environment_id=$2 AND i.deprovisioned_at IS NOT NULL
		AND (($3='client' AND i.external_id=$4) OR (u.email=$5 AND i.external_id_source='derived'))
		ORDER BY (i.external_id=$4) DESC LIMIT 1 FOR UPDATE OF i`, p.Connection, p.Environment, u.ExternalSource, u.External, u.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return id, nil
	}
	if err != nil {
		return id, failure(err)
	}
	if u.ExternalSource == provisioning.AnchorClient {
		if _, err = tx.ExecContext(ctx, `UPDATE provisioned_identities SET external_id=$3,external_id_source='client' WHERE connection_id=$1 AND user_id=$2`, p.Connection, id, u.External); err != nil {
			return id, conflict(err)
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE provisioned_identities SET deprovisioned_at=NULL,updated_at=now() WHERE connection_id=$1 AND user_id=$2`, p.Connection, id); err != nil {
		return id, failure(err)
	}
	// The membership may have been removed by an operator meanwhile.
	if _, err = tx.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id,active,display_name) VALUES($1,$2,$3,$4,$5) ON CONFLICT (organization_id,user_id) DO UPDATE SET active=EXCLUDED.active,display_name=EXCLUDED.display_name`, p.Environment, p.Organization, id, u.Active, u.Name); err != nil {
		return id, conflict(err)
	}
	// Renamed in the directory while deprovisioned: follow it when this
	// connection exclusively manages the user, else keep the current address.
	if err = setEmail(ctx, tx, p, id, u.Email); err != nil && !errors.Is(err, errShared) {
		return id, err
	}
	return id, replaceAliases(ctx, tx, p, id, u.Aliases)
}

// adopt links an existing member of the connection's organization whose
// primary email equals userName (opt-in per connection). With scope
// verified_domains the email must also be on one of the organization's
// verified domains; otherwise the create proceeds and conflicts as usual.
func (r *Repository) adopt(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, u provisioning.User, scope string) (identity.UserID, error) {
	var id identity.UserID
	if scope == provisioning.AdoptVerifiedDomains {
		var verified bool
		if err := tx.GetContext(ctx, &verified, `SELECT EXISTS(SELECT 1 FROM organization_domains WHERE environment_id=$1 AND organization_id=$2 AND domain=$3 AND verified_at IS NOT NULL)`,
			p.Environment, p.Organization, identity.EmailDomain(u.Email)); err != nil || !verified {
			return id, failure(err)
		}
	}
	err := tx.GetContext(ctx, &id, `SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id AND m.environment_id=u.environment_id AND m.organization_id=$2
		WHERE u.environment_id=$1 AND u.email=$3 AND NOT EXISTS(SELECT 1 FROM provisioned_identities i WHERE i.connection_id=$4 AND i.user_id=u.id)
		FOR UPDATE OF u`, p.Environment, p.Organization, u.Email, p.Connection)
	if errors.Is(err, sql.ErrNoRows) {
		return id, nil
	}
	if err != nil {
		return id, failure(err)
	}
	external := u.External
	if u.ExternalSource == provisioning.AnchorDerived {
		external = id.String()
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO provisioned_identities(connection_id,environment_id,user_id,external_id,external_id_source,origin) VALUES($1,$2,$3,$4,$5,'adopted')`, p.Connection, p.Environment, id, external, u.ExternalSource); err != nil {
		return id, conflict(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE memberships SET active=$4,display_name=$5 WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, id, u.Active, u.Name); err != nil {
		return id, failure(err)
	}
	return id, replaceAliases(ctx, tx, p, id, u.Aliases)
}

func (r *Repository) Update(ctx context.Context, p provisioning.Principal, id identity.UserID, input provisioning.Update) (provisioning.User, error) {
	var out provisioning.User
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return out, failure(err)
	}
	defer tx.Rollback()
	// Lock the identity: concurrent updates of the same user serialize here.
	var version int64
	err = tx.GetContext(ctx, &version, `SELECT version FROM provisioned_identities WHERE connection_id=$1 AND environment_id=$2 AND user_id=$3 AND deprovisioned_at IS NULL FOR UPDATE`, p.Connection, p.Environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return out, errx.NotFound("user not found")
	}
	if err != nil {
		return out, failure(err)
	}
	if input.IfVersion != nil && *input.IfVersion != version {
		return out, provisioning.ErrStale
	}
	old, err := find(ctx, tx, p, id)
	if err != nil {
		return out, err
	}
	if input.External != nil && *input.External != old.External {
		if old.ExternalSource != provisioning.AnchorDerived {
			return out, mutability("externalId cannot be changed")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE provisioned_identities SET external_id=$3,external_id_source='client' WHERE connection_id=$1 AND user_id=$2 AND external_id_source='derived'`, p.Connection, id, *input.External); err != nil {
			return out, conflict(err)
		}
	}
	if input.Email != nil {
		if err = setEmail(ctx, tx, p, id, *input.Email); err != nil {
			return out, err
		}
	}
	if input.Aliases != nil {
		if err = replaceAliases(ctx, tx, p, id, *input.Aliases); err != nil {
			return out, err
		}
	}
	if input.Manager != nil {
		if err = setManager(ctx, tx, p, id, *input.Manager); err != nil {
			return out, err
		}
	}
	if input.Phone != nil && p.MapPhone {
		if err = setPhone(ctx, tx, p, id, *input.Phone); err != nil {
			return out, err
		}
	}
	if input.Active != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE memberships SET active=$4 WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, id, *input.Active); err != nil {
			return out, failure(err)
		}
	}
	if input.Name != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE memberships SET display_name=$4 WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, id, *input.Name); err != nil {
			return out, failure(err)
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE provisioned_identities SET updated_at=now(),version=version+1 WHERE connection_id=$1 AND user_id=$2`, p.Connection, id); err != nil {
		return out, failure(err)
	}
	if err = scimEvent(ctx, tx, p, event.UserUpdated, id, nil); err != nil {
		return out, err
	}
	out, err = find(ctx, tx, p, id)
	if err != nil {
		return out, err
	}
	return out, failure(tx.Commit())
}

// scimEvent records a directory change of user; the actor is the SCIM
// credential (actor_kind directory).
func scimEvent(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, typ string, user identity.UserID, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	data["user_id"] = user.String()
	data["organization_id"] = p.Organization.String()
	data["connection_id"] = p.Connection.String()
	return eventpg.Emit(ctx, tx, p.Environment, p.ID.String(), typ, event.Subject{Kind: "user", ID: user.String()}, data)
}

// Deprovision implements SCIM DELETE: the identity is hidden from this
// connection, its membership deactivated and its authorization in the
// organization (roles, grants, positions) removed, so a later reactivation
// starts without access. The user itself is kept: it may belong elsewhere.
func (r *Repository) Deprovision(ctx context.Context, p provisioning.Principal, id identity.UserID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if _, err = find(ctx, tx, p, id); err != nil {
		return err
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE provisioned_identities SET deprovisioned_at=now(),updated_at=now(),version=version+1 WHERE environment_id=$1 AND connection_id=$2 AND user_id=$3`, []any{p.Environment, p.Connection, id}},
		{`DELETE FROM provisioned_emails WHERE connection_id=$1 AND user_id=$2`, []any{p.Connection, id}},
		{`UPDATE memberships SET active=false,manager_id=NULL WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, []any{p.Environment, p.Organization, id}},
		{`UPDATE memberships SET manager_id=NULL WHERE environment_id=$1 AND organization_id=$2 AND manager_id=$3`, []any{p.Environment, p.Organization, id}},
		{`DELETE FROM role_assignments WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, []any{p.Environment, p.Organization, id}},
		{`DELETE FROM grants WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, []any{p.Environment, p.Organization, id}},
		{`DELETE FROM position_assignments WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, []any{p.Environment, p.Organization, id}},
		{`DELETE FROM group_members WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, []any{p.Environment, p.Organization, id}},
	} {
		if _, err = tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return failure(err)
		}
	}
	if err = scimEvent(ctx, tx, p, event.UserDeprovisioned, id, nil); err != nil {
		return err
	}
	return failure(tx.Commit())
}

// errShared rejects renaming a user this connection does not exclusively own.
var errShared = mutability("userName cannot be changed: the user was not created by this directory or is shared with another organization or directory")

// setEmail renames the user's primary address (SCIM userName), which is also
// their login. The directory may only rename users it created and exclusively
// manages: adopted or operator-linked users, and users that belong to another
// organization or provisioning connection, keep their address. The new
// address starts unverified.
func setEmail(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, id identity.UserID, email string) error {
	var current string
	if err := tx.GetContext(ctx, &current, `SELECT email FROM users WHERE environment_id=$1 AND id=$2 FOR UPDATE`, p.Environment, id); err != nil {
		return failure(err)
	}
	if current == email {
		return nil
	}
	var shared bool
	if err := tx.GetContext(ctx, &shared, `SELECT EXISTS(SELECT 1 FROM memberships WHERE environment_id=$1 AND user_id=$2 AND organization_id<>$3) OR EXISTS(SELECT 1 FROM provisioned_identities WHERE environment_id=$1 AND user_id=$2 AND (connection_id<>$4 OR origin<>'created'))`, p.Environment, id, p.Organization, p.Connection); err != nil {
		return failure(err)
	}
	if shared {
		return errShared
	}
	_, err := tx.ExecContext(ctx, `UPDATE users SET email=$3,email_verified=false WHERE environment_id=$1 AND id=$2`, p.Environment, id, email)
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		return errx.Conflict("userName already in use")
	}
	return failure(err)
}

// setPhone sets the user's number from the directory; a different number
// is unverified, the same one keeps its verification.
func setPhone(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, id identity.UserID, phone string) error {
	_, err := tx.ExecContext(ctx, `UPDATE users SET phone_verified=(phone_verified AND phone=$3),phone=$3 WHERE environment_id=$1 AND id=$2 AND kind='human'`, p.Environment, id, phone)
	return failure(err)
}

// replaceAliases makes this connection's aliases for id exactly list. Aliases
// are scoped to the connection: they never reserve an address in the
// environment and other directories' aliases are untouched.
func replaceAliases(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, id identity.UserID, list []provisioning.Email) error {
	values := make(pq.StringArray, 0, len(list))
	for _, e := range list {
		values = append(values, e.Value)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM provisioned_emails WHERE connection_id=$1 AND user_id=$2 AND NOT (email = ANY($3))`, p.Connection, id, values); err != nil {
		return failure(err)
	}
	for _, e := range list {
		kind := e.Type
		if kind == "" {
			kind = "other"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO provisioned_emails(connection_id,environment_id,user_id,email,type) VALUES($1,$2,$3,$4,$5) ON CONFLICT (connection_id,user_id,email) DO UPDATE SET type=EXCLUDED.type`, p.Connection, p.Environment, id, e.Value, kind); err != nil {
			return failure(err)
		}
	}
	return nil
}

func setManager(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, user identity.UserID, manager string) error {
	if _, err := tx.ExecContext(ctx, `SELECT id FROM organizations WHERE id=$1 AND environment_id=$2 FOR UPDATE`, p.Organization, p.Environment); err != nil {
		return failure(err)
	}
	if manager != "" {
		var known bool
		if err := tx.GetContext(ctx, &known, `SELECT EXISTS(SELECT 1 FROM provisioned_identities WHERE connection_id=$1 AND environment_id=$2 AND user_id=$3 AND deprovisioned_at IS NULL)`, p.Connection, p.Environment, manager); err != nil {
			return failure(err)
		}
		if !known {
			return errx.Validation("manager must belong to this provisioning connection").WithDetail("scimType", "invalidValue")
		}
		var cycle bool
		if err := tx.GetContext(ctx, &cycle, `WITH RECURSIVE chain AS(SELECT user_id,manager_id FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3 UNION SELECT m.user_id,m.manager_id FROM memberships m JOIN chain c ON m.user_id=c.manager_id WHERE m.environment_id=$1 AND m.organization_id=$2)SELECT EXISTS(SELECT 1 FROM chain WHERE user_id=$4)`, p.Environment, p.Organization, manager, user); err != nil {
			return failure(err)
		}
		if cycle {
			return errx.Validation("manager hierarchy cycle").WithDetail("scimType", "invalidValue")
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE memberships SET manager_id=nullif($4,'')::uuid WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, user, manager)
	return failure(err)
}

var _ provisioning.Repository = (*Repository)(nil)
