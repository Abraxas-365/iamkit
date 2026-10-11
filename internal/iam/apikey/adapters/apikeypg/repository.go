// Package apikeypg persists API keys (api_keys) and the environment's API
// key policy.
package apikeypg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

var _ apikey.Repository = (*Repository)(nil)

func New(db *sqlx.DB) *Repository { return &Repository{db: db} }

func failure(err error, message string) error {
	if err == nil {
		return nil
	}
	var e *errx.Error
	if errors.As(err, &e) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("API key not found")
	}
	var pg *pq.Error
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23503") {
		return errx.Wrap(err, message, errx.TypeConflict)
	}
	return errx.Wrap(err, message, errx.TypeInternal)
}

// neverAfter is how far ahead an expiry counts as "never".
const neverAfter = 50 * 365 * 24 * time.Hour

// keyColumns reads a key with the names of what it points at.
const keyColumns = `k.id,k.environment_id,k.owner_kind,k.user_id,k.organization_id,k.application_id,k.resource_id,k.name,k.permissions,k.last4,
	k.expires_at,k.last_used_at,k.revoked_at,k.created_by_kind,coalesce(k.created_by_id::text,'') AS created_by_id,k.created_at,
	coalesce((SELECT u.name FROM users u WHERE u.id=k.user_id AND u.environment_id=k.environment_id),'') AS user_name,
	coalesce((SELECT o.name FROM organizations o WHERE o.id=k.organization_id AND o.environment_id=k.environment_id),'') AS organization_name,
	coalesce((SELECT a.name FROM applications a WHERE a.id=k.application_id AND a.environment_id=k.environment_id),'') AS application_name,
	coalesce((SELECT s.name FROM resources s WHERE s.id=k.resource_id AND s.environment_id=k.environment_id),'') AS resource_name`

type keyRow struct {
	ID               identity.APIKeyID       `db:"id"`
	Environment      identity.EnvironmentID  `db:"environment_id"`
	OwnerKind        string                  `db:"owner_kind"`
	User             identity.UserID         `db:"user_id"`
	Organization     identity.OrganizationID `db:"organization_id"`
	Application      *identity.ApplicationID `db:"application_id"`
	Resource         identity.ResourceID     `db:"resource_id"`
	Name             string                  `db:"name"`
	Permissions      pq.StringArray          `db:"permissions"`
	Last4            string                  `db:"last4"`
	ExpiresAt        time.Time               `db:"expires_at"`
	LastUsedAt       *time.Time              `db:"last_used_at"`
	RevokedAt        *time.Time              `db:"revoked_at"`
	CreatedByKind    string                  `db:"created_by_kind"`
	CreatedByID      string                  `db:"created_by_id"`
	CreatedAt        time.Time               `db:"created_at"`
	UserName         string                  `db:"user_name"`
	OrganizationName string                  `db:"organization_name"`
	ApplicationName  string                  `db:"application_name"`
	ResourceName     string                  `db:"resource_name"`
}

func (r keyRow) toDomain(now time.Time) apikey.APIKey {
	out := apikey.APIKey{
		ID: r.ID, Environment: r.Environment, Owner: apikey.Owner{Type: apikey.OwnerKind(r.OwnerKind), User: r.User},
		Organization: r.Organization, Application: r.Application, Resource: r.Resource, Name: r.Name,
		ObfuscatedValue: identity.ObfuscatedAPIKey(r.Last4), ExpiresAt: r.ExpiresAt.UTC(), Expires: r.ExpiresAt.Before(now.Add(neverAfter)),
		LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt, CreatedBy: apikey.Creator{Kind: r.CreatedByKind, ID: r.CreatedByID},
		CreatedAt: r.CreatedAt, UserName: r.UserName, OrganizationName: r.OrganizationName,
		ApplicationName: r.ApplicationName, ResourceName: r.ResourceName,
	}
	if r.Permissions != nil {
		out.Permissions = []string(r.Permissions)
	}
	switch {
	case r.RevokedAt != nil:
		out.State = apikey.StateRevoked
	case !r.ExpiresAt.After(now):
		out.State = apikey.StateExpired
	default:
		out.State = apikey.StateActive
	}
	return out
}

// scoped builds the WHERE of a listing or lookup: the scope narrows the
// filter and organization scopes never see machine keys, in SQL.
func scoped(scope apikey.Scope, filter apikey.Filter) (string, []any) {
	f := scope.Narrow(filter)
	where := "k.environment_id=$1"
	args := []any{scope.Environment}
	add := func(clause string, arg any) {
		args = append(args, arg)
		where += " AND " + fmt.Sprintf(clause, len(args))
	}
	if scope.IsOrganization() || scope.IsSelf() {
		where += " AND k.owner_kind<>'machine'"
	}
	if scope.IsSelf() {
		where += " AND k.owner_kind='user'"
		if scope.User.IsZero() {
			where += " AND false"
		}
	}
	if f.OwnerType != "" {
		add("k.owner_kind=$%d", string(f.OwnerType))
	}
	if !f.Organization.IsZero() {
		add("k.organization_id=$%d", f.Organization)
	}
	if !f.User.IsZero() {
		add("k.user_id=$%d", f.User)
	}
	if !f.Resource.IsZero() {
		add("k.resource_id=$%d", f.Resource)
	}
	switch f.State {
	case apikey.StateActive:
		where += " AND k.revoked_at IS NULL AND k.expires_at>now()"
	case apikey.StateRevoked:
		where += " AND k.revoked_at IS NOT NULL"
	case apikey.StateExpired:
		where += " AND k.revoked_at IS NULL AND k.expires_at<=now()"
	}
	return where, args
}

func (r *Repository) List(ctx context.Context, scope apikey.Scope, filter apikey.Filter, page query.Pagination) (query.Paginated[apikey.APIKey], error) {
	where, args := scoped(scope, filter)
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		where += fmt.Sprintf(" AND k.name ILIKE $%d", len(args))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) FROM api_keys k WHERE "+where, args...); err != nil {
		return query.Paginated[apikey.APIKey]{}, failure(err, "list API keys")
	}
	rows := []keyRow{}
	if err := r.db.SelectContext(ctx, &rows, fmt.Sprintf("SELECT %s FROM api_keys k WHERE %s ORDER BY k.created_at DESC, k.id LIMIT %d OFFSET %d", keyColumns, where, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[apikey.APIKey]{}, failure(err, "list API keys")
	}
	now := time.Now()
	items := make([]apikey.APIKey, 0, len(rows))
	for _, row := range rows {
		items = append(items, row.toDomain(now))
	}
	return query.NewPaginated(items, total, page), nil
}

func (r *Repository) Find(ctx context.Context, scope apikey.Scope, key identity.APIKeyID) (apikey.APIKey, error) {
	where, args := scoped(scope, apikey.Filter{})
	args = append(args, key)
	var row keyRow
	if err := r.db.GetContext(ctx, &row, fmt.Sprintf("SELECT %s FROM api_keys k WHERE %s AND k.id=$%d", keyColumns, where, len(args)), args...); err != nil {
		return apikey.APIKey{}, failure(err, "find API key")
	}
	return row.toDomain(time.Now()), nil
}

// check is what Create verifies about the owner and the references.
type check struct {
	Organization bool   `db:"organization"`
	Resource     bool   `db:"resource"`
	Kind         string `db:"kind"`
	Active       bool   `db:"active"`
	Member       bool   `db:"member"`
	Linked       bool   `db:"linked"`
}

func (r *Repository) Create(ctx context.Context, m apikey.Mutation, key apikey.APIKey, secretHash []byte, limit int) (apikey.APIKey, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return apikey.APIKey{}, failure(err, "create API key")
	}
	defer tx.Rollback()
	// The organization row serializes key creation per organization, so
	// the limits below hold under concurrency.
	var orgActive bool
	if err = tx.GetContext(ctx, &orgActive, `SELECT active FROM organizations WHERE environment_id=$1 AND id=$2 FOR UPDATE`, m.Environment, key.Organization); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apikey.APIKey{}, errx.Validation("organization_id must be an organization of the environment")
		}
		return apikey.APIKey{}, failure(err, "create API key")
	}
	if !orgActive {
		return apikey.APIKey{}, errx.Business("the organization is not active")
	}
	if err = r.checkOwner(ctx, tx, m, key); err != nil {
		return apikey.APIKey{}, err
	}
	if len(key.Permissions) > 0 {
		if err = r.checkReach(ctx, tx, m, key); err != nil {
			return apikey.APIKey{}, err
		}
	}
	if key.Owner.Type != apikey.OwnerMachine {
		if err = r.checkLimit(ctx, tx, m, key, limit); err != nil {
			return apikey.APIKey{}, err
		}
	}
	var creator any
	if id, perr := uuid.Parse(m.Actor); perr == nil {
		creator = id.String()
	}
	var application any
	if key.Application != nil {
		application = *key.Application
	}
	var permissions any
	if key.Permissions != nil {
		permissions = pq.Array(key.Permissions)
	}
	last4 := strings.TrimPrefix(key.ObfuscatedValue, identity.ObfuscatedAPIKey(""))
	var row keyRow
	err = tx.GetContext(ctx, &row, `WITH k AS (
			INSERT INTO api_keys(id,environment_id,owner_kind,user_id,organization_id,application_id,resource_id,name,secret_hash,expires_at,permissions,created_by_id,last4)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::uuid,$13) RETURNING *)
		SELECT `+keyColumns+` FROM k`, key.ID, m.Environment, string(key.Owner.Type), key.Owner.User, key.Organization, application, key.Resource,
		key.Name, secretHash, key.ExpiresAt, permissions, creator, last4)
	if err != nil {
		return apikey.APIKey{}, failure(err, "create API key")
	}
	if err = audit(ctx, tx, m, key.ID, eventData(row)); err != nil {
		return apikey.APIKey{}, err
	}
	if err = tx.Commit(); err != nil {
		return apikey.APIKey{}, failure(err, "commit API key")
	}
	return row.toDomain(time.Now()), nil
}

// ownerSQL reads what an owner check needs: the resource, the user's kind
// and state, its membership and the application's link to the resource.
// Organization keys have no user, so only the resource counts for them.
const ownerSQL = `SELECT true AS organization, EXISTS(SELECT 1 FROM resources WHERE environment_id=$1 AND id=$4) AS resource,
	coalesce(u.kind,'') AS kind, coalesce(u.active,false) AS active,
	EXISTS(SELECT 1 FROM memberships m WHERE m.environment_id=$1 AND m.organization_id=$2 AND m.user_id=$3::uuid AND m.active) AS member,
	EXISTS(SELECT 1 FROM application_resources ar JOIN applications a ON a.id=ar.application_id AND a.environment_id=ar.environment_id
		WHERE ar.environment_id=$1 AND ar.application_id=$5::uuid AND ar.resource_id=$4 AND a.active) AS linked
	FROM (SELECT 1) one LEFT JOIN users u ON u.environment_id=$1 AND u.id=$3::uuid`

func userArg(u identity.UserID) any {
	if u.IsZero() {
		return nil
	}
	return u
}

func (r *Repository) checkOwner(ctx context.Context, tx *sqlx.Tx, m apikey.Mutation, key apikey.APIKey) error {
	var c check
	var application any
	switch {
	case key.Application != nil:
		application = *key.Application
	case m.IsSelf() && !m.Application.IsZero():
		application = m.Application
	}
	if err := tx.GetContext(ctx, &c, ownerSQL, m.Environment, key.Organization, userArg(key.Owner.User), key.Resource, application); err != nil {
		return failure(err, "create API key")
	}
	if !c.Resource {
		return errx.Validation("resource_id must be a resource of the environment")
	}
	switch key.Owner.Type {
	case apikey.OwnerUser:
		if c.Kind != "human" || !c.Active {
			return errx.Business("the user must be an active person")
		}
		if !c.Member {
			return errx.Validation("organization_id must be an organization the user belongs to")
		}
		if m.IsSelf() && !c.Linked {
			return errx.Validation("resource_id must be a resource of the application")
		}
	case apikey.OwnerMachine:
		if c.Kind != "machine" {
			return errx.Business("machine API keys are only for machine users")
		}
		if !c.Active {
			return errx.Business("the machine user is not active")
		}
		if !c.Member {
			return errx.Validation("organization_id must be an organization the user belongs to")
		}
		if !c.Linked {
			return errx.Validation("resource_id must be a resource of the application")
		}
	}
	return nil
}

// checkReach re-checks, in the transaction, that the key would act with
// every permission it asks for.
func (r *Repository) checkReach(ctx context.Context, tx *sqlx.Tx, m apikey.Mutation, key apikey.APIKey) error {
	var effective pq.StringArray
	if err := tx.GetContext(ctx, &effective, `SELECT api_key_permissions($1,$2,$3,$4,$5,$6)`,
		string(key.Owner.Type), pq.Array(key.Permissions), m.Environment, key.Organization, key.Owner.User, key.Resource); err != nil {
		return failure(err, "create API key")
	}
	var refused []string
	for _, p := range key.Permissions {
		found := false
		for _, e := range effective {
			if e == p {
				found = true
				break
			}
		}
		if !found {
			refused = append(refused, p)
		}
	}
	if len(refused) > 0 {
		return errx.Business("permissions not allowed for this key: " + strings.Join(refused, ", "))
	}
	return nil
}

func (r *Repository) checkLimit(ctx context.Context, tx *sqlx.Tx, m apikey.Mutation, key apikey.APIKey, limit int) error {
	if limit <= 0 {
		return nil
	}
	var live int
	live_ := `SELECT count(*) FROM api_keys WHERE environment_id=$1 AND organization_id=$2 AND revoked_at IS NULL AND expires_at>now()`
	if key.Owner.Type == apikey.OwnerUser {
		err := tx.GetContext(ctx, &live, live_+` AND owner_kind='user' AND user_id=$3`, m.Environment, key.Organization, key.Owner.User)
		if err != nil {
			return failure(err, "create API key")
		}
		if live >= limit {
			return apikey.ErrLimitReached(fmt.Sprintf("a user may hold at most %d live API keys in an organization", limit))
		}
		return nil
	}
	if err := tx.GetContext(ctx, &live, live_+` AND owner_kind='organization'`, m.Environment, key.Organization); err != nil {
		return failure(err, "create API key")
	}
	if live >= limit {
		return apikey.ErrLimitReached(fmt.Sprintf("an organization may hold at most %d live API keys", limit))
	}
	return nil
}

func eventData(row keyRow) map[string]any {
	data := map[string]any{
		"owner_type": row.OwnerKind, "organization_id": row.Organization.String(), "resource_id": row.Resource.String(),
		"name": row.Name, "permissions": []string(row.Permissions),
	}
	if row.Permissions == nil {
		data["permissions"] = []string{}
	}
	if !row.User.IsZero() {
		data["user_id"] = row.User.String()
	}
	return data
}

func audit(ctx context.Context, tx *sqlx.Tx, m apikey.Mutation, key identity.APIKeyID, data map[string]any) error {
	return failure(eventpg.AuditSubject(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, key.String(), data), "audit API key")
}

// Revoke ends the key and the sessions exchanged from it; a key already
// revoked stays as it is (no second event).
func (r *Repository) Revoke(ctx context.Context, m apikey.Mutation, key identity.APIKeyID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "revoke API key")
	}
	defer tx.Rollback()
	where, args := scoped(m.Scope, apikey.Filter{})
	args = append(args, key)
	var row keyRow
	if err = tx.GetContext(ctx, &row, fmt.Sprintf("SELECT %s FROM api_keys k WHERE %s AND k.id=$%d FOR UPDATE OF k", keyColumns, where, len(args)), args...); err != nil {
		return failure(err, "revoke API key")
	}
	if row.RevokedAt != nil {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE api_keys SET revoked_at=now() WHERE environment_id=$1 AND id=$2`, m.Environment, key); err != nil {
		return failure(err, "revoke API key")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND api_key_id=$2 AND revoked_at IS NULL`, m.Environment, key); err != nil {
		return failure(err, "revoke API key sessions")
	}
	if err = audit(ctx, tx, m, key, eventData(row)); err != nil {
		return err
	}
	return failure(tx.Commit(), "commit API key revocation")
}

func (r *Repository) Reach(ctx context.Context, environment identity.EnvironmentID, input apikey.NewAPIKey) ([]string, error) {
	var out pq.StringArray
	err := r.db.GetContext(ctx, &out, `SELECT api_key_permissions($1,$2,$3,$4,$5,$6)`,
		string(input.Owner.Type), pq.Array(input.Permissions), environment, input.Organization, input.Owner.User, input.Resource)
	return []string(out), failure(err, "check API key permissions")
}

func (r *Repository) Held(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID, resource identity.ResourceID) ([]string, error) {
	var out pq.StringArray
	err := r.db.GetContext(ctx, &out, `SELECT api_key_reach($1,$2,$3,$4)`, environment, organization, user, resource)
	return []string(out), failure(err, "check the creator's permissions")
}

func (r *Repository) OptionResources(ctx context.Context, scope apikey.Scope, kind apikey.OwnerKind, granter identity.UserID, application identity.ApplicationID) ([]apikey.OptionResource, error) {
	var owner, by any
	if kind == apikey.OwnerUser {
		owner = scope.User
	} else if !granter.IsZero() {
		by = granter
	}
	var app any
	if kind == apikey.OwnerUser && !application.IsZero() {
		app = application
	}
	rows := []struct {
		ID          identity.ResourceID `db:"id"`
		Name        string              `db:"name"`
		Audience    string              `db:"audience"`
		Permissions pq.StringArray      `db:"permissions"`
	}{}
	err := r.db.SelectContext(ctx, &rows, `SELECT r.id, r.name, r.audience, p.permissions
		FROM resources r
		CROSS JOIN LATERAL (SELECT coalesce(array_agg(x ORDER BY x),'{}') AS permissions
			FROM unnest(CASE $5 WHEN 'user' THEN r.api_key_user_permissions ELSE r.api_key_organization_permissions END) x
			WHERE x = ANY (api_key_reach($1,$2,$3::uuid,r.id))
			  AND ($4::uuid IS NULL OR x = ANY (api_key_reach($1,$2,$4::uuid,r.id)))) p
		WHERE r.environment_id=$1 AND r.prefix<>'iam' AND cardinality(p.permissions) > 0
		  AND ($6::uuid IS NULL OR EXISTS (SELECT 1 FROM application_resources ar WHERE ar.environment_id=r.environment_id AND ar.application_id=$6::uuid AND ar.resource_id=r.id))
		ORDER BY r.name, r.id`, scope.Environment, scope.Organization, owner, by, string(kind), app)
	if err != nil {
		return nil, failure(err, "list API key options")
	}
	out := make([]apikey.OptionResource, 0, len(rows))
	for _, row := range rows {
		out = append(out, apikey.OptionResource{ID: row.ID, Name: row.Name, Audience: row.Audience, Permissions: []string(row.Permissions)})
	}
	return out, nil
}

func (r *Repository) Policy(ctx context.Context, environment identity.EnvironmentID) (apikey.Policy, error) {
	policy := apikey.Policy{MaxPerUser: config.APIKeyMaxPerUserDefault, MaxPerOrganization: config.APIKeyMaxPerOrganizationDefault}
	var row struct {
		UserKeys           bool      `db:"user_keys"`
		OrganizationKeys   bool      `db:"organization_keys"`
		MaxTTLDays         *int      `db:"max_ttl_days"`
		MaxPerUser         int       `db:"max_per_user"`
		MaxPerOrganization int       `db:"max_per_organization"`
		UpdatedAt          time.Time `db:"updated_at"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT user_keys,organization_keys,max_ttl_days,max_per_user,max_per_organization,updated_at FROM api_key_policies WHERE environment_id=$1`, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, nil
	}
	if err != nil {
		return policy, failure(err, "read API key policy")
	}
	return apikey.Policy{UserKeys: row.UserKeys, OrganizationKeys: row.OrganizationKeys, MaxTTLDays: row.MaxTTLDays,
		MaxPerUser: row.MaxPerUser, MaxPerOrganization: row.MaxPerOrganization, UpdatedAt: row.UpdatedAt}, nil
}

func (r *Repository) SavePolicy(ctx context.Context, m apikey.Mutation, policy apikey.Policy) (apikey.Policy, error) {
	var saved apikey.Policy
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var row struct {
			UpdatedAt time.Time `db:"updated_at"`
		}
		if err := tx.GetContext(ctx, &row, `INSERT INTO api_key_policies(environment_id,user_keys,organization_keys,max_ttl_days,max_per_user,max_per_organization)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT (environment_id) DO UPDATE SET user_keys=EXCLUDED.user_keys, organization_keys=EXCLUDED.organization_keys,
				max_ttl_days=EXCLUDED.max_ttl_days, max_per_user=EXCLUDED.max_per_user, max_per_organization=EXCLUDED.max_per_organization, updated_at=now()
			RETURNING updated_at`, m.Environment, policy.UserKeys, policy.OrganizationKeys, policy.MaxTTLDays, policy.MaxPerUser, policy.MaxPerOrganization); err != nil {
			return failure(err, "save API key policy")
		}
		saved = policy
		saved.UpdatedAt = row.UpdatedAt
		return failure(eventpg.AuditSubject(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, m.Environment.String(), map[string]any{
			"user_keys": policy.UserKeys, "organization_keys": policy.OrganizationKeys, "max_ttl_days": policy.MaxTTLDays,
			"max_per_user": policy.MaxPerUser, "max_per_organization": policy.MaxPerOrganization}), "audit API key policy")
	})
	return saved, err
}
