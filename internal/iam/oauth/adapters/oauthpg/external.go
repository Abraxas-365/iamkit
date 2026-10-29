package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

var _ oauth.ExternalRepository = (*Repository)(nil)

func (r *Repository) ExternalTarget(ctx context.Context, uri string) (oauth.ExternalTarget, error) {
	return r.externalTarget(ctx, "pr.uri=$1", uri)
}

func (r *Repository) ClientMetadataEnvironments(ctx context.Context) ([]identity.EnvironmentID, error) {
	var out []identity.EnvironmentID
	err := r.db.SelectContext(ctx, &out, `SELECT DISTINCT pr.environment_id FROM protected_resources pr JOIN applications a ON a.id=pr.application_id AND a.environment_id=pr.environment_id WHERE pr.allow_client_metadata AND pr.active AND a.active`)
	return out, failure(err)
}

func (r *Repository) ExternalTargetByID(ctx context.Context, protected identity.ProtectedResourceID) (oauth.ExternalTarget, error) {
	return r.externalTarget(ctx, "pr.id=$1", protected)
}

func (r *Repository) externalTarget(ctx context.Context, where string, arg any) (oauth.ExternalTarget, error) {
	var row struct {
		Environment identity.EnvironmentID       `db:"environment_id"`
		Protected   identity.ProtectedResourceID `db:"id"`
		Application identity.ApplicationID       `db:"application_id"`
		Resource    identity.ResourceID          `db:"resource_id"`
		Allow       bool                         `db:"allow_client_metadata"`
		Admission   string                       `db:"client_admission"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT pr.environment_id,pr.id,pr.application_id,pr.resource_id,pr.allow_client_metadata,pr.client_admission FROM protected_resources pr JOIN applications a ON a.id=pr.application_id AND a.environment_id=pr.environment_id WHERE `+where+` AND pr.active AND a.active`, arg)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.ExternalTarget{}, errx.NotFound("protected resource not found")
	}
	if err != nil {
		return oauth.ExternalTarget{}, failure(err)
	}
	out := oauth.ExternalTarget{Environment: row.Environment, Protected: row.Protected, Application: row.Application, Resource: row.Resource, AllowClientMetadata: row.Allow, ClientAdmission: row.Admission}
	err = r.db.SelectContext(ctx, &out.Allowlist, `SELECT id,environment_id,protected_resource_id,origin,path_prefix,preset,created_at FROM oauth_client_allowlist WHERE environment_id=$1 AND (protected_resource_id IS NULL OR protected_resource_id=$2)`, row.Environment, row.Protected)
	return out, failure(err)
}

func (r *Repository) ExternalClientID(ctx context.Context, protected identity.ProtectedResourceID, externalID string) (identity.ClientID, error) {
	var id identity.ClientID
	err := r.db.GetContext(ctx, &id, `SELECT id FROM oauth_clients WHERE protected_resource_id=$1 AND external_id=$2`, protected, externalID)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.ClientID{}, nil
	}
	return id, failure(err)
}

func (r *Repository) UnsavedExternal(ctx context.Context, target oauth.ExternalTarget, doc oauth.ExternalClient) (*oauth.Client, error) {
	var row struct {
		Audience string `db:"audience"`
		protectedRow
	}
	err := r.db.GetContext(ctx, &row, `SELECT r.audience,r.permissions,pr.id AS protected_id,pr.uri AS protected_uri,pr.default_scopes AS protected_default_scopes,pr.idle_ttl_seconds AS protected_idle,pr.max_ttl_seconds AS protected_max,pp.max_idle_ttl_seconds AS policy_idle,pp.max_lifetime_ttl_seconds AS policy_lifetime
		FROM protected_resources pr JOIN resources r ON r.id=pr.resource_id AND r.environment_id=pr.environment_id JOIN applications a ON a.id=pr.application_id AND a.environment_id=pr.environment_id
		LEFT JOIN protected_resource_policies pp ON pp.environment_id=pr.environment_id WHERE pr.id=$1 AND pr.environment_id=$2 AND pr.active AND a.active`, target.Protected, target.Environment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errx.NotFound("protected resource not found")
	}
	if err != nil {
		return nil, failure(err)
	}
	return &oauth.Client{Environment: target.Environment, Application: target.Application, Resource: target.Resource, Audience: row.Audience, Redirects: slices.Clone(doc.Redirects),
		Public: doc.Public(), HostedLogin: true, Auth: doc.Auth, AccessTokenFormat: oauth.TokenFormatJWT, GrantTypes: slices.Clone(doc.GrantTypes), Protected: row.target(),
		Source: oauth.SourceCIMD, ExternalID: doc.ExternalID, Name: doc.Name, ClientURI: doc.ClientURI, LogoURI: doc.LogoURI, Admission: oauth.AdmissionPending}, nil
}

// externalRow is what a client's document set on its row.
type externalRow struct {
	ID        identity.ClientID `db:"id"`
	Name      string            `db:"client_name"`
	ClientURI string            `db:"client_uri"`
	LogoURI   string            `db:"logo_uri"`
	Redirects pq.StringArray    `db:"redirect_uris"`
	Grants    pq.StringArray    `db:"grant_types"`
	Method    string            `db:"token_endpoint_auth_method"`
	Alg       string            `db:"token_endpoint_auth_signing_alg"`
	JWKSURI   string            `db:"jwks_uri"`
	Fetched   *time.Time        `db:"metadata_fetched_at"`
	Admission string            `db:"admission"`
	Source    string            `db:"admission_source"`
	Approved  string            `db:"approved_metadata_hash"`
}

func (row externalRow) same(doc oauth.ExternalClient) bool {
	return row.Name == doc.Name && row.ClientURI == doc.ClientURI && row.LogoURI == doc.LogoURI && slices.Equal(row.Redirects, doc.Redirects) && slices.Equal(row.Grants, doc.GrantTypes) && row.Method == doc.Auth.Method && row.Alg == doc.Auth.SigningAlg && row.JWKSURI == doc.Auth.JWKSURI
}

// approvedHash is what the approval vouched for: the hash stored when it
// was given, else (an approval written without one) the fields the row had.
func (row externalRow) approvedHash() string {
	if row.Approved != "" {
		return row.Approved
	}
	return oauth.MetadataHash([]string(row.Redirects), row.JWKSURI, row.Method)
}

// lockExternal serializes writers of one (server, URL) pair: concurrent
// first authorizations insert once.
func lockExternal(ctx context.Context, tx *sqlx.Tx, protected identity.ProtectedResourceID, externalID string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cimd:"+protected.String()+":"+externalID)
	return failure(err)
}

func selectExternal(ctx context.Context, tx *sqlx.Tx, protected identity.ProtectedResourceID, externalID string) (externalRow, bool, error) {
	var row externalRow
	err := tx.GetContext(ctx, &row, `SELECT id,client_name,client_uri,logo_uri,redirect_uris,grant_types,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks_uri,metadata_fetched_at,admission,admission_source,approved_metadata_hash FROM oauth_clients WHERE protected_resource_id=$1 AND external_id=$2 FOR NO KEY UPDATE`, protected, externalID)
	if errors.Is(err, sql.ErrNoRows) {
		return row, false, nil
	}
	return row, err == nil, failure(err)
}

// insertExternal writes a first-seen (server, URL) pair and its
// oauth_client.discovered event. An approved row remembers who approved it
// (source) and what (the document's hash).
func insertExternal(ctx context.Context, tx *sqlx.Tx, target oauth.ExternalTarget, id identity.ClientID, doc oauth.ExternalClient, fetched time.Time, admission, source string) error {
	hash := ""
	if admission == oauth.AdmissionApproved {
		hash = doc.Hash()
	} else {
		source = ""
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public,hosted_login,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks_uri,grant_types,source,external_id,protected_resource_id,admission,admission_source,approved_metadata_hash,client_name,client_uri,logo_uri,metadata_fetched_at) VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,'cimd',$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		id, target.Environment, target.Application, target.Resource, pq.StringArray(doc.Redirects), doc.Public(), doc.Auth.Method, doc.Auth.SigningAlg, doc.Auth.JWKSURI, pq.StringArray(doc.GrantTypes), doc.ExternalID, target.Protected, admission, source, hash, doc.Name, doc.ClientURI, doc.LogoURI, fetched); err != nil {
		return failure(err)
	}
	return eventpg.Emit(ctx, tx, target.Environment, "", event.OAuthClientDiscovered, event.Subject{Kind: "oauth_client", ID: id.String()},
		map[string]any{"client_id": doc.ExternalID, "client_name": doc.Name, "protected_resource_id": target.Protected.String(), "admission": admission})
}

func (r *Repository) SaveExternalClient(ctx context.Context, save oauth.ExternalSave) (identity.ClientID, error) {
	target, doc, fetched := save.Target, save.Document, save.Fetched
	var out identity.ClientID
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if err := lockExternal(ctx, tx, target.Protected, doc.ExternalID); err != nil {
			return err
		}
		row, found, err := selectExternal(ctx, tx, target.Protected, doc.ExternalID)
		if err != nil {
			return err
		}
		if !found {
			out = save.ID
			return insertExternal(ctx, tx, target, save.ID, doc, fetched, save.Admission, save.Source)
		}
		out = row.ID
		if row.Fetched != nil && !fetched.After(*row.Fetched) {
			return nil
		}
		if row.same(doc) {
			_, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET metadata_fetched_at=$2 WHERE id=$1`, row.ID, fetched)
			return failure(err)
		}
		// What an approval vouches for changed (redirect URIs, jwks_uri,
		// authentication method)? A manual approval no longer stands: the
		// client waits for IT again, and every user asks anew. Approvals
		// by policy (allowlist, open server, preset) hold, the change is
		// only on record.
		changed := row.Admission == oauth.AdmissionApproved && row.approvedHash() != doc.Hash()
		revoked := changed && (row.Source == "" || row.Source == oauth.SourceManual)
		admission, hash := row.Admission, row.Approved
		if revoked {
			admission, hash = oauth.AdmissionPending, ""
		} else if changed {
			hash = doc.Hash()
		}
		// record_changes attaches the diff to the event (data.changes).
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET redirect_uris=$2,public=$3,token_endpoint_auth_method=$4,token_endpoint_auth_signing_alg=$5,jwks_uri=$6,grant_types=$7,client_name=$8,client_uri=$9,logo_uri=$10,metadata_fetched_at=$11,
			admission=$12, admission_expires_at=CASE WHEN $13 THEN NULL ELSE admission_expires_at END, approved_metadata_hash=$14 WHERE id=$1`,
			row.ID, pq.StringArray(doc.Redirects), doc.Public(), doc.Auth.Method, doc.Auth.SigningAlg, doc.Auth.JWKSURI, pq.StringArray(doc.GrantTypes), doc.Name, doc.ClientURI, doc.LogoURI, fetched, admission, revoked, hash); err != nil {
			return failure(err)
		}
		data := map[string]any{"client_id": doc.ExternalID, "protected_resource_id": target.Protected.String(), "source": oauth.SourceCIMD}
		if changed {
			data["approval_metadata_changed"] = true
			data["admission_source"] = row.Source
			data["admission"] = admission
		}
		if revoked {
			// Earlier requests were for the document IT approved: users
			// ask again, and IT hears of each (a new
			// oauth_client.access_requested).
			if _, err = tx.ExecContext(ctx, `DELETE FROM oauth_client_access_requests WHERE client_id=$1`, row.ID); err != nil {
				return failure(err)
			}
			// And the grants given for it end with the approval (L-4): its
			// sessions would otherwise stay live, in lists and impact
			// counts, until the next refresh.
			n, err := revokeClients(ctx, tx, target.Environment, []string{row.ID.String()}, false)
			if err != nil {
				return err
			}
			data["revoked_sessions"] = n
		}
		return eventpg.Emit(ctx, tx, target.Environment, "", event.OAuthClientUpdated, event.Subject{Kind: "oauth_client", ID: row.ID.String()}, data)
	})
	return out, err
}

func (r *Repository) RequestExternalAccess(ctx context.Context, access oauth.AccessRequest) error {
	target, doc := access.Target, access.Document
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if err := lockExternal(ctx, tx, target.Protected, doc.ExternalID); err != nil {
			return err
		}
		row, found, err := selectExternal(ctx, tx, target.Protected, doc.ExternalID)
		if err != nil {
			return err
		}
		id := row.ID
		interval := access.Interval.Seconds()
		if found {
			// Asked within the interval already: nothing changes, and the
			// caps below do not count a request that exists.
			var recent bool
			if err = tx.GetContext(ctx, &recent, `SELECT EXISTS(SELECT 1 FROM oauth_client_access_requests WHERE client_id=$1 AND user_id=$2 AND requested_at > now()-make_interval(secs => $3))`, id, access.User, interval); err != nil {
				return failure(err)
			}
			if recent {
				return nil
			}
		}
		// M-3: a user, and the organization they ask from, keep a bounded
		// number of requests for clients still waiting. Counted under locks
		// of their own, so concurrent requests cannot overshoot; always
		// taken in this order (user, organization, environment backlog).
		if err = capAccessRequests(ctx, tx, target.Environment, access); err != nil {
			return err
		}
		if !found {
			// The environment's backlog is counted under a lock of its own,
			// so concurrent first requests of different clients cannot
			// overshoot the cap.
			if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cimd-pending:"+target.Environment.String()); err != nil {
				return failure(err)
			}
			var pending int
			if err = tx.GetContext(ctx, &pending, `SELECT count(*) FROM oauth_clients WHERE environment_id=$1 AND source='cimd' AND admission='pending'`, target.Environment); err != nil {
				return failure(err)
			}
			if pending >= access.MaxPending {
				return oauth.ErrAdmissionBacklog()
			}
			id = access.ID
			if err = insertExternal(ctx, tx, target, id, doc, access.Fetched, oauth.AdmissionPending, ""); err != nil {
				return err
			}
		}
		// One request (and event) per client and user and interval.
		var organization any
		if !access.Organization.IsZero() {
			organization = access.Organization
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO oauth_client_access_requests(client_id,environment_id,user_id,organization_id) VALUES($1,$2,$3,$4)
			ON CONFLICT (client_id,user_id) DO UPDATE SET requested_at=now(), organization_id=EXCLUDED.organization_id WHERE oauth_client_access_requests.requested_at <= now()-make_interval(secs => $5)`,
			id, target.Environment, access.User, organization, interval)
		if err != nil {
			return failure(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		data := map[string]any{"client_id": doc.ExternalID, "host": hostOf(doc.ExternalID), "protected_resource_id": target.Protected.String(), "user_id": access.User.String()}
		if !access.Organization.IsZero() {
			data["organization_id"] = access.Organization.String()
		}
		return eventpg.Emit(ctx, tx, target.Environment, access.User.String(), event.OAuthClientAccessRequested, event.Subject{Kind: "oauth_client", ID: id.String()}, data)
	})
}

// capAccessRequests refuses (oauth.ErrAccessRequestLimit) a request that
// would leave the user, or their organization, with more live requests for
// clients still waiting than they may: requests made within the interval
// whose client is pending.
func capAccessRequests(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, access oauth.AccessRequest) error {
	interval := access.Interval.Seconds()
	count := func(column string, id string) (int, error) {
		var n int
		err := tx.GetContext(ctx, &n, `SELECT count(*) FROM oauth_client_access_requests r JOIN oauth_clients c ON c.id=r.client_id AND c.environment_id=r.environment_id
			WHERE r.environment_id=$1 AND r.`+column+`=$2 AND c.admission='pending' AND r.requested_at > now()-make_interval(secs => $3)`, environment, id, interval)
		return n, failure(err)
	}
	if access.MaxPerUser > 0 {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cimd-user:"+access.User.String()); err != nil {
			return failure(err)
		}
		if n, err := count("user_id", access.User.String()); err != nil {
			return err
		} else if n >= access.MaxPerUser {
			return oauth.ErrAccessRequestLimit()
		}
	}
	if access.MaxPerOrganization > 0 && !access.Organization.IsZero() {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cimd-org:"+access.Organization.String()); err != nil {
			return failure(err)
		}
		if n, err := count("organization_id", access.Organization.String()); err != nil {
			return err
		} else if n >= access.MaxPerOrganization {
			return oauth.ErrAccessRequestLimit()
		}
	}
	return nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func (r *Repository) TouchExternal(ctx context.Context, client identity.ClientID, interval time.Duration) error {
	_, err := r.db.ExecContext(ctx, `UPDATE oauth_clients SET last_used_at=now() WHERE id=$1 AND source='cimd' AND (last_used_at IS NULL OR last_used_at <= now()-make_interval(secs => $2))`, client, interval.Seconds())
	return failure(err)
}

func (r *Repository) PruneExternal(ctx context.Context, before time.Time, limit int) (int, error) {
	n := 0
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var ids []identity.ClientID
		// Its access requests go with it (ON DELETE CASCADE): a user who asks
		// again creates it anew. Idle is counted from the later of its
		// discovery and the latest request for it (L-1): a client users keep
		// asking for waits for IT however old its row is. A client with
		// token rows or device codes (used once, its last_used_at write
		// lost, then demoted) is not idle: those reference it without
		// cascading, and deleting it would fail the whole batch every round
		// (W5-5).
		if err := tx.SelectContext(ctx, &ids, `SELECT c.id FROM oauth_clients c WHERE c.source='cimd' AND c.admission='pending' AND c.last_used_at IS NULL AND c.discovered_at < $1
			AND NOT EXISTS (SELECT 1 FROM oauth_client_access_requests a WHERE a.client_id=c.id AND a.requested_at >= $1)
			AND NOT EXISTS (SELECT 1 FROM oauth_requests q WHERE q.client_id=c.id)
			AND NOT EXISTS (SELECT 1 FROM oauth_device_codes d WHERE d.client_id=c.id)
			ORDER BY c.discovered_at LIMIT $2 FOR UPDATE OF c SKIP LOCKED`, before, limit); err != nil {
			return failure(err)
		}
		if len(ids) == 0 {
			return nil
		}
		// Its tickets are long expired.
		if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_authorizations WHERE client_id = ANY($1::uuid[])`, pq.Array(ids)); err != nil {
			return failure(err)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM oauth_clients WHERE id = ANY($1::uuid[])`, pq.Array(ids))
		if err != nil {
			return failure(err)
		}
		count, err := res.RowsAffected()
		n = int(count)
		return failure(err)
	})
	return n, err
}

func (r *Repository) GrantClient(ctx context.Context, clientID, kind, signatureHash string) (identity.EnvironmentID, identity.ClientID, error) {
	var row struct {
		Environment identity.EnvironmentID `db:"environment_id"`
		Client      identity.ClientID      `db:"id"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT c.environment_id,c.id FROM oauth_requests q JOIN oauth_clients c ON c.id=q.client_id AND c.environment_id=q.environment_id WHERE q.kind=$1 AND q.signature_hash=$2 AND q.expires_at>clock_timestamp() AND c.external_id=$3 AND c.active LIMIT 1`, kind, signatureHash, clientID)
	return row.Environment, row.Client, lookup(err)
}
