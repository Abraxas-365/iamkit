package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Consents stores users' consents and administrators' grants to OAuth
// clients at protected resources. Every change that ends access ends the
// client's sessions it covered in the same transaction (D32); revoked
// rows stay as records until PruneConsents.
type Consents struct{ db *sqlx.DB }

func NewConsents(db *sqlx.DB) *Consents { return &Consents{db: db} }

var _ oauth.ConsentRepository = (*Consents)(nil)

// agreed reads the user's live consent for key and, with admin, the live
// administrator grants for the client there (environment-wide and the
// user's organization). lock holds the consent row until the
// transaction ends.
func agreed(ctx context.Context, q sqlx.QueryerContext, key oauth.ConsentKey, admin, lock bool) (oauth.Agreed, error) {
	var out oauth.Agreed
	var user pq.StringArray
	suffix := ""
	if lock {
		// The consent row only: its key never changes, so a no-key lock.
		suffix = " FOR NO KEY UPDATE OF oauth_consents"
	}
	err := sqlx.GetContext(ctx, q, &user, `SELECT scopes FROM oauth_consents WHERE environment_id=$1 AND user_id=$2 AND organization_id=$3 AND client_id=$4 AND protected_resource_id=$5 AND revoked_at IS NULL`+suffix,
		key.Environment, key.User, key.Organization, key.Client, key.Protected)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, failure(err)
	}
	out.User = []string(user)
	if !admin {
		return out, nil
	}
	var granted pq.StringArray
	err = sqlx.GetContext(ctx, q, &granted, `SELECT COALESCE(array_agg(DISTINCT s ORDER BY s), '{}') FROM oauth_client_grants g, unnest(g.scopes) s
		WHERE g.environment_id=$1 AND g.protected_resource_id=$2 AND g.client_id=$3 AND (g.organization_id IS NULL OR g.organization_id=$4)
		  AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>now())`,
		key.Environment, key.Protected, key.Client, key.Organization)
	out.Admin = []string(granted)
	return out, failure(err)
}

// recordConsent adds the record's scopes to the live consent of its key (a
// new row with record.ID when there is none) and writes
// oauth_consent.granted.
func recordConsent(ctx context.Context, tx *sqlx.Tx, record oauth.ConsentRecord) error {
	k := record.Key
	var id identity.ConsentID
	err := tx.GetContext(ctx, &id, `INSERT INTO oauth_consents(id,environment_id,organization_id,user_id,client_id,protected_resource_id,scopes)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (environment_id,user_id,organization_id,client_id,protected_resource_id) WHERE revoked_at IS NULL
		DO UPDATE SET scopes=(SELECT array_agg(DISTINCT s ORDER BY s) FROM unnest(oauth_consents.scopes || EXCLUDED.scopes) s), updated_at=now()
		RETURNING id`,
		record.ID, k.Environment, k.Organization, k.User, k.Client, k.Protected, pq.StringArray(record.Scopes))
	if err != nil {
		return failure(err)
	}
	return consentEvent(ctx, tx, event.OAuthConsentGranted, record, id, nil)
}

// consentEvent writes a consent event on behalf of the user (granted,
// denied) with what it carries: never a token.
func consentEvent(ctx context.Context, tx *sqlx.Tx, typ string, record oauth.ConsentRecord, id identity.ConsentID, extra map[string]any) error {
	k := record.Key
	info := identity.ClientInfoFrom(ctx)
	data := map[string]any{
		"user_id":               k.User.String(),
		"organization_id":       k.Organization.String(),
		"client":                map[string]any{"id": k.Client.String(), "client_id": record.ClientID, "host": record.Host},
		"protected_resource_id": k.Protected.String(),
		"resource":              record.Resource,
		"requested_scopes":      nonNil(record.Requested),
		"consent_ui":            record.UI,
		"ip":                    info.IP,
		"user_agent":            info.UserAgent,
	}
	if typ == event.OAuthConsentGranted {
		data["granted_scopes"] = nonNil(record.Scopes)
	}
	for key, v := range extra {
		data[key] = v
	}
	subject := event.Subject{Kind: "oauth_consent", ID: id.String()}
	if id.IsZero() {
		// A denial records no consent: its subject is the client.
		subject = event.Subject{Kind: "oauth_client", ID: k.Client.String()}
	}
	return eventpg.Emit(ctx, tx, k.Environment, k.User.String(), typ, subject, data)
}

func (r *Consents) Agreed(ctx context.Context, key oauth.ConsentKey, admin bool) (oauth.Agreed, error) {
	return agreed(ctx, r.db, key, admin, false)
}

type liveConsent struct {
	ID           identity.ConsentID            `db:"id"`
	Organization identity.OrganizationID       `db:"organization_id"`
	Protected    *identity.ProtectedResourceID `db:"protected_resource_id"`
	Scopes       pq.StringArray                `db:"scopes"`
}

// revokeConsents ends the live consents matched by where (over c, with
// args after the environment) as reason and writes one
// oauth_consent.revoked per row, actor actor ("" = the system).
func revokeConsents(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, actor, reason, where string, args ...any) ([]liveConsent, error) {
	var rows []liveConsent
	err := tx.SelectContext(ctx, &rows, `UPDATE oauth_consents c SET revoked_at=now(), revoked_reason=$2 WHERE c.environment_id=$1 AND c.revoked_at IS NULL AND `+where+` RETURNING c.id,c.organization_id,c.protected_resource_id,c.scopes`,
		append([]any{environment, reason}, args...)...)
	return rows, failure(err)
}

func (r *Consents) Disconnect(ctx context.Context, m oauth.Mutation, input oauth.Disconnect) (int, error) {
	var ended int
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var client struct {
			ExternalID sql.NullString `db:"external_id"`
		}
		if err := tx.GetContext(ctx, &client, `SELECT external_id FROM oauth_clients WHERE id=$1 AND environment_id=$2`, input.Client, input.Environment); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errx.NotFound("connected app not found")
			}
			return failure(err)
		}
		consents, err := revokeConsents(ctx, tx, input.Environment, m.Actor, input.Reason,
			`c.user_id=$3 AND c.client_id=$4 AND ($5::uuid IS NULL OR c.organization_id=$5)`, input.User, input.Client, input.Organization)
		if err != nil {
			return err
		}
		if err = sessionReason(ctx, tx, "consent_revoked"); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND user_id=$2 AND oauth_client_id=$3 AND protected_resource_id IS NOT NULL AND ($4::uuid IS NULL OR organization_id=$4) AND revoked_at IS NULL`,
			input.Environment, input.User, input.Client, input.Organization)
		if err != nil {
			return failure(err)
		}
		n, _ := res.RowsAffected()
		ended = int(n)
		if len(consents) == 0 && ended == 0 {
			return errx.NotFound("connected app not found")
		}
		if m.Action != "" {
			if err = eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target); err != nil {
				return err
			}
		}
		id := client.ExternalID.String
		if id == "" {
			id = input.Client.String()
		}
		for _, c := range consents {
			data := map[string]any{
				"user_id": input.User.String(), "organization_id": c.Organization.String(),
				"client": map[string]any{"id": input.Client.String(), "client_id": id, "host": oauth.ClientHost(id)},
				"scopes": []string(c.Scopes), "reason": input.Reason, "revoked_sessions": ended,
			}
			if c.Protected != nil {
				data["protected_resource_id"] = c.Protected.String()
			}
			if err = eventpg.Emit(ctx, tx, input.Environment, m.Actor, event.OAuthConsentRevoked, event.Subject{Kind: "oauth_consent", ID: c.ID.String()}, data); err != nil {
				return err
			}
		}
		return nil
	})
	return ended, err
}

// revokeClientConsents ends every live consent to the clients (a block):
// reason client_blocked, actor the operator.
func revokeClientConsents(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, actor string, clients []string) error {
	var rows []struct {
		liveConsent
		User   identity.UserID   `db:"user_id"`
		Client identity.ClientID `db:"client_id"`
	}
	err := tx.SelectContext(ctx, &rows, `UPDATE oauth_consents c SET revoked_at=now(), revoked_reason=$2 WHERE c.environment_id=$1 AND c.revoked_at IS NULL AND c.client_id = ANY($3::uuid[])
		RETURNING c.id,c.organization_id,c.protected_resource_id,c.scopes,c.user_id,c.client_id`, environment, oauth.ConsentClientBlocked, pq.StringArray(clients))
	if err != nil {
		return failure(err)
	}
	for _, c := range rows {
		data := map[string]any{"user_id": c.User.String(), "organization_id": c.Organization.String(), "client": map[string]any{"id": c.Client.String()},
			"scopes": []string(c.Scopes), "reason": oauth.ConsentClientBlocked}
		if c.Protected != nil {
			data["protected_resource_id"] = c.Protected.String()
		}
		if err = eventpg.Emit(ctx, tx, environment, actor, event.OAuthConsentRevoked, event.Subject{Kind: "oauth_consent", ID: c.ID.String()}, data); err != nil {
			return err
		}
	}
	return nil
}

func (r *Consents) ClientGrantTarget(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (oauth.ClientGrantTarget, error) {
	var row struct {
		Permissions pq.StringArray `db:"permissions"`
		Mode        string         `db:"consent_mode"`
	}
	// A client of the server: one of its external clients, or a registered
	// client of its application and resource.
	err := r.db.GetContext(ctx, &row, `SELECT r.permissions,pr.consent_mode FROM protected_resources pr
		JOIN resources r ON r.id=pr.resource_id AND r.environment_id=pr.environment_id
		JOIN oauth_clients c ON c.id=$3 AND c.environment_id=pr.environment_id AND c.active
		  AND (c.protected_resource_id=pr.id OR (c.source='registered' AND c.application_id=pr.application_id AND c.resource_id=pr.resource_id))
		WHERE pr.id=$2 AND pr.environment_id=$1`, environment, protected, client)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.ClientGrantTarget{}, errx.NotFound("client not found for this protected resource")
	}
	return oauth.ClientGrantTarget{Permissions: []string(row.Permissions), ConsentMode: row.Mode}, failure(err)
}

const grantColumns = `id,protected_resource_id,client_id,organization_id,scopes,expires_at,created_at,updated_at,revoked_at,revoked_reason`

type grantRow struct {
	ID        identity.ClientGrantID       `db:"id"`
	Protected identity.ProtectedResourceID `db:"protected_resource_id"`
	Client    identity.ClientID            `db:"client_id"`
	Org       *identity.OrganizationID     `db:"organization_id"`
	Scopes    pq.StringArray               `db:"scopes"`
	Expires   *time.Time                   `db:"expires_at"`
	Created   time.Time                    `db:"created_at"`
	Updated   time.Time                    `db:"updated_at"`
	Revoked   *time.Time                   `db:"revoked_at"`
	Reason    sql.NullString               `db:"revoked_reason"`
}

func (g grantRow) toDomain() oauth.ClientGrant {
	return oauth.ClientGrant{ID: g.ID, Protected: g.Protected, Client: g.Client, Organization: g.Org, Scopes: []string(g.Scopes), ExpiresAt: g.Expires,
		CreatedAt: g.Created, UpdatedAt: g.Updated, RevokedAt: g.Revoked, RevokedReason: g.Reason.String}
}

func grantData(g grantRow) map[string]any {
	data := map[string]any{"protected_resource_id": g.Protected.String(), "client_id": g.Client.String(), "scopes": []string(g.Scopes)}
	if g.Org != nil {
		data["organization_id"] = g.Org.String()
	}
	if g.Expires != nil {
		data["expires_at"] = g.Expires.UTC().Format(time.RFC3339)
	}
	return data
}

func (r *Consents) SaveClientGrant(ctx context.Context, m oauth.Mutation, grant oauth.ClientGrantSave) (oauth.ClientGrant, error) {
	var row grantRow
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		// Replacing a live grant keeps its row: narrower scopes take effect
		// at each grant's next refresh (D32), nothing is cut now.
		err := tx.GetContext(ctx, &row, `INSERT INTO oauth_client_grants(id,environment_id,protected_resource_id,client_id,organization_id,scopes,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (protected_resource_id,client_id,organization_id) WHERE revoked_at IS NULL
			DO UPDATE SET scopes=EXCLUDED.scopes, expires_at=EXCLUDED.expires_at, updated_at=now()
			RETURNING `+grantColumns,
			grant.ID, m.Environment, grant.Protected, grant.Client, grant.Input.Organization, pq.StringArray(grant.Input.Scopes), grant.Input.ExpiresAt)
		if err != nil {
			return conflict(err)
		}
		return eventpg.AuditSubject(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, row.ID.String(), grantData(row))
	})
	return row.toDomain(), err
}

// sessionReason names why the sessions this transaction ends were
// ended (session.revoked data.reason).
func sessionReason(ctx context.Context, tx *sqlx.Tx, reason string) error {
	_, err := tx.ExecContext(ctx, `SELECT set_config('iamkit.session_reason', $1, true)`, reason)
	return failure(err)
}

// endGrantSessions ends the client's sessions at the protected resource a
// grant covered: its organization's, or the environment's.
func endGrantSessions(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, g grantRow) (int, error) {
	if err := sessionReason(ctx, tx, "client_grant_revoked"); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND oauth_client_id=$2 AND protected_resource_id=$3 AND ($4::uuid IS NULL OR organization_id=$4) AND revoked_at IS NULL`,
		environment, g.Client, g.Protected, g.Org)
	if err != nil {
		return 0, failure(err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (r *Consents) RevokeClientGrant(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID, grant identity.ClientGrantID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var row grantRow
		err := tx.GetContext(ctx, &row, `UPDATE oauth_client_grants SET revoked_at=now(), revoked_reason=$5, updated_at=now()
			WHERE id=$1 AND environment_id=$2 AND protected_resource_id=$3 AND client_id=$4 AND revoked_at IS NULL RETURNING `+grantColumns,
			grant, m.Environment, protected, client, oauth.GrantRevokedByOperator)
		if errors.Is(err, sql.ErrNoRows) {
			return errx.NotFound("grant not found")
		}
		if err != nil {
			return failure(err)
		}
		n, err := endGrantSessions(ctx, tx, m.Environment, row)
		if err != nil {
			return err
		}
		data := grantData(row)
		data["reason"], data["revoked_sessions"] = oauth.GrantRevokedByOperator, n
		return eventpg.AuditSubject(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, row.ID.String(), data)
	})
}

// revokeServerGrants revokes every live administrator grant at a server
// (reason), ending the sessions each covered, one oauth_client.grant_revoked
// per grant, in the caller's transaction.
func revokeServerGrants(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, actor string, protected identity.ProtectedResourceID, reason string) error {
	var rows []grantRow
	err := tx.SelectContext(ctx, &rows, `UPDATE oauth_client_grants SET revoked_at=now(), revoked_reason=$3, updated_at=now()
		WHERE environment_id=$1 AND protected_resource_id=$2 AND revoked_at IS NULL RETURNING `+grantColumns,
		environment, protected, reason)
	if err != nil {
		return failure(err)
	}
	for _, g := range rows {
		n, err := endGrantSessions(ctx, tx, environment, g)
		if err != nil {
			return err
		}
		data := grantData(g)
		data["reason"], data["revoked_sessions"] = reason, n
		if err = eventpg.Emit(ctx, tx, environment, actor, event.OAuthClientGrantRevoked, event.Subject{Kind: "oauth_client", ID: g.Client.String()}, data); err != nil {
			return err
		}
	}
	return nil
}

func (r *Consents) ListClientGrants(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter oauth.ClientGrantFilter) ([]oauth.ClientGrant, error) {
	var rows []grantRow
	err := r.db.SelectContext(ctx, &rows, `SELECT `+grantColumns+` FROM oauth_client_grants WHERE environment_id=$1 AND protected_resource_id=$2 AND ($3::uuid IS NULL OR client_id=$3) AND ($4 OR revoked_at IS NULL) ORDER BY created_at DESC, id LIMIT 500`,
		environment, protected, filter.Client, filter.Revoked)
	out := make([]oauth.ClientGrant, 0, len(rows))
	for _, g := range rows {
		out = append(out, g.toDomain())
	}
	return out, failure(err)
}

func (r *Consents) ExpireClientGrants(ctx context.Context, limit int) (int, error) {
	count := 0
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var rows []struct {
			grantRow
			Environment identity.EnvironmentID `db:"environment_id"`
		}
		err := tx.SelectContext(ctx, &rows, `UPDATE oauth_client_grants g SET revoked_at=now(), revoked_reason=$2, updated_at=now()
			WHERE g.id IN (SELECT id FROM oauth_client_grants WHERE revoked_at IS NULL AND expires_at<=now() ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)
			RETURNING g.environment_id,`+grantColumns, limit, oauth.GrantExpired)
		if err != nil {
			return failure(err)
		}
		for _, g := range rows {
			n, err := endGrantSessions(ctx, tx, g.Environment, g.grantRow)
			if err != nil {
				return err
			}
			data := grantData(g.grantRow)
			data["reason"], data["revoked_sessions"] = oauth.GrantExpired, n
			if err = eventpg.Emit(ctx, tx, g.Environment, "", event.OAuthClientGrantRevoked, event.Subject{Kind: "oauth_client", ID: g.Client.String()}, data); err != nil {
				return err
			}
		}
		count = len(rows)
		return nil
	})
	return count, err
}

func (r *Consents) PruneConsents(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM oauth_consents WHERE id IN (SELECT id FROM oauth_consents WHERE revoked_at IS NOT NULL AND revoked_at<$1 LIMIT $2 FOR UPDATE SKIP LOCKED)`, cutoff, limit)
	if err != nil {
		return 0, failure(err)
	}
	a, _ := res.RowsAffected()
	if res, err = r.db.ExecContext(ctx, `DELETE FROM oauth_client_grants WHERE id IN (SELECT id FROM oauth_client_grants WHERE revoked_at IS NOT NULL AND revoked_at<$1 LIMIT $2 FOR UPDATE SKIP LOCKED)`, cutoff, limit); err != nil {
		return int(a), failure(err)
	}
	b, _ := res.RowsAffected()
	return int(a + b), nil
}

func (r *Consents) ConnectedApps(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, filter oauth.ConnectedAppFilter) ([]oauth.ConnectedApp, error) {
	var rows []struct {
		Client       identity.ClientID            `db:"client_id"`
		ExternalID   sql.NullString               `db:"external_id"`
		Source       string                       `db:"source"`
		Name         string                       `db:"name"`
		Logo         string                       `db:"logo_uri"`
		Preset       string                       `db:"preset"`
		Protected    identity.ProtectedResourceID `db:"protected_resource_id"`
		Resource     string                       `db:"uri"`
		ResourceName string                       `db:"resource_name"`
		ResourceID   identity.ResourceID          `db:"catalog_resource_id"`
		Org          identity.OrganizationID      `db:"organization_id"`
		Scopes       pq.StringArray               `db:"scopes"`
		Consented    *time.Time                   `db:"consented_at"`
		Sessions     int                          `db:"sessions"`
		Authorized   *time.Time                   `db:"last_authorized_at"`
	}
	err := r.db.SelectContext(ctx, &rows, `WITH c AS (
			SELECT client_id, protected_resource_id, organization_id, scopes, created_at FROM oauth_consents
			 WHERE environment_id=$1 AND user_id=$2 AND revoked_at IS NULL AND protected_resource_id IS NOT NULL AND ($3::uuid IS NULL OR organization_id=$3)
		), s AS (
			SELECT oauth_client_id AS client_id, protected_resource_id, organization_id, count(*) AS sessions, max(created_at) AS last_authorized_at FROM sessions
			 WHERE environment_id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() AND oauth_client_id IS NOT NULL AND protected_resource_id IS NOT NULL AND parent_session_id IS NULL
			   AND ($3::uuid IS NULL OR organization_id=$3)
			 GROUP BY 1, 2, 3
		)
		SELECT k.client_id, oc.external_id, oc.source, COALESCE(NULLIF(oc.client_name,''), a.name) AS name, oc.logo_uri, oc.preset,
		       k.protected_resource_id, pr.uri, pr.name AS resource_name, pr.resource_id AS catalog_resource_id, k.organization_id,
		       COALESCE(c.scopes, '{}') AS scopes, c.created_at AS consented_at, COALESCE(s.sessions, 0) AS sessions, s.last_authorized_at
		  FROM (SELECT client_id, protected_resource_id, organization_id FROM c UNION SELECT client_id, protected_resource_id, organization_id FROM s) k
		  LEFT JOIN c USING (client_id, protected_resource_id, organization_id)
		  LEFT JOIN s USING (client_id, protected_resource_id, organization_id)
		  JOIN oauth_clients oc ON oc.id=k.client_id AND oc.environment_id=$1
		  JOIN applications a ON a.id=oc.application_id AND a.environment_id=oc.environment_id
		  JOIN protected_resources pr ON pr.id=k.protected_resource_id AND pr.environment_id=$1
		 ORDER BY GREATEST(c.created_at, s.last_authorized_at) DESC NULLS LAST, k.client_id
		 LIMIT 500`, environment, user, filter.Organization)
	out := make([]oauth.ConnectedApp, 0, len(rows))
	for _, row := range rows {
		id := row.ExternalID.String
		if id == "" {
			id = row.Client.String()
		}
		client := oauth.ConnectedClient{ID: row.Client, ClientID: id, Source: row.Source, Name: row.Name, Preset: row.Preset}.Describe(row.Logo)
		out = append(out, oauth.ConnectedApp{Client: client, Protected: row.Protected, Resource: row.Resource, ResourceName: row.ResourceName, Organization: row.Org,
			Scopes: oauth.NewScopeInfos([]string(row.Scopes), nil), ResourceID: row.ResourceID, ConsentedAt: row.Consented, Sessions: row.Sessions, LastUsedAt: row.Authorized})
	}
	return out, failure(err)
}
