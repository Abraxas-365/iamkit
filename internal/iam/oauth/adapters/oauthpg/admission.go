package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"net/url"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Admission stores what IT decides about external clients: approvals,
// blocks, the allowlist and template clients. Every change that ends a
// client's access revokes its grants in the same transaction (M3).
type Admission struct{ db *sqlx.DB }

func NewAdmission(db *sqlx.DB) *Admission { return &Admission{db: db} }

var _ oauth.AdmissionRepository = (*Admission)(nil)

func (r *Admission) FindProtectedResource(ctx context.Context, environment identity.EnvironmentID, id identity.ProtectedResourceID) (oauth.ProtectedResource, error) {
	return (&ProtectedResources{db: r.db}).FindProtectedResource(ctx, environment, id)
}

// revokeClients ends every grant of the clients: their sessions (the
// OAuth sessions the tokens belong to), token families (authorization
// codes, access and refresh tokens), authorization tickets and device
// codes. With forget the token rows go too, which deleting the clients
// (or their protected resource) needs: the foreign keys do not cascade.
// It returns how many live sessions ended.
func revokeClients(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, clients []string, forget bool) (int, error) {
	if len(clients) == 0 {
		return 0, nil
	}
	ids := pq.StringArray(clients)
	res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND oauth_client_id = ANY($2::uuid[]) AND revoked_at IS NULL`, environment, ids)
	if err != nil {
		return 0, failure(err)
	}
	n, _ := res.RowsAffected()
	// Tickets and device codes first: a ticket may point at a device code.
	if _, err = tx.ExecContext(ctx, `DELETE FROM oauth_authorizations WHERE environment_id=$1 AND client_id = ANY($2::uuid[])`, environment, ids); err != nil {
		return 0, failure(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM oauth_device_codes WHERE environment_id=$1 AND client_id = ANY($2::uuid[])`, environment, ids); err != nil {
		return 0, failure(err)
	}
	if forget {
		_, err = tx.ExecContext(ctx, `DELETE FROM oauth_requests WHERE environment_id=$1 AND client_id = ANY($2::uuid[])`, environment, ids)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE oauth_requests SET active=false WHERE environment_id=$1 AND client_id = ANY($2::uuid[]) AND active`, environment, ids)
	}
	return int(n), failure(err)
}

// externalRowView is the columns of an operator's view of a client.
const externalViewColumns = `c.id,c.external_id,c.protected_resource_id,c.client_name,c.client_uri,c.logo_uri,c.redirect_uris,c.token_endpoint_auth_method,c.jwks_uri,c.admission,c.admission_expires_at,c.admission_source,c.metadata_fetched_at,c.last_used_at,c.discovered_at,
	(SELECT count(*) FROM oauth_client_access_requests a WHERE a.client_id=c.id) AS access_requests`

type viewRow struct {
	ID         identity.ClientID            `db:"id"`
	ExternalID string                       `db:"external_id"`
	Protected  identity.ProtectedResourceID `db:"protected_resource_id"`
	Name       string                       `db:"client_name"`
	ClientURI  string                       `db:"client_uri"`
	LogoURI    string                       `db:"logo_uri"`
	Redirects  pq.StringArray               `db:"redirect_uris"`
	Method     string                       `db:"token_endpoint_auth_method"`
	JWKSURI    string                       `db:"jwks_uri"`
	Admission  string                       `db:"admission"`
	Expires    *time.Time                   `db:"admission_expires_at"`
	Source     string                       `db:"admission_source"`
	Fetched    *time.Time                   `db:"metadata_fetched_at"`
	LastUsed   *time.Time                   `db:"last_used_at"`
	Created    time.Time                    `db:"discovered_at"`
	Requests   int                          `db:"access_requests"`
}

func (v viewRow) domain() oauth.ExternalClientView {
	redirects := []string(v.Redirects)
	if redirects == nil {
		redirects = []string{}
	}
	source := v.Source
	if v.Admission == oauth.AdmissionApproved && source == "" {
		source = oauth.SourceManual
	} else if v.Admission != oauth.AdmissionApproved {
		source = ""
	}
	out := oauth.ExternalClientView{ID: v.ID, ClientID: v.ExternalID, Protected: v.Protected, Name: v.Name, ClientURI: v.ClientURI, LogoURI: v.LogoURI, Host: oauth.ClientHost(v.ExternalID), Redirects: redirects,
		AuthMethod: v.Method, JWKSURI: v.JWKSURI, Admission: v.Admission, AdmissionExpiresAt: v.Expires, AdmissionSource: source, AccessRequests: v.Requests, MetadataFetchedAt: v.Fetched, MetadataHash: oauth.MetadataHash(redirects, v.JWKSURI, v.Method), LastUsedAt: v.LastUsed, CreatedAt: v.Created}
	if p, ok := oauth.PresetForClient(v.ExternalID); ok {
		out.Preset, out.PresetName = p.Key, p.Name
	}
	return out
}

func (r *Admission) ListExternalClients(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter oauth.ExternalClientFilter, page query.Pagination) (query.Paginated[oauth.ExternalClientView], error) {
	where := `c.environment_id=$1 AND c.protected_resource_id=$2 AND c.source='cimd' AND ($3='' OR c.admission=$3)`
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM oauth_clients c WHERE `+where, environment, protected, filter.Admission); err != nil {
		return query.Paginated[oauth.ExternalClientView]{}, failure(err)
	}
	rows := []viewRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+externalViewColumns+` FROM oauth_clients c WHERE `+where+` ORDER BY c.discovered_at DESC, c.id LIMIT $4 OFFSET $5`, environment, protected, filter.Admission, page.Limit, page.Offset); err != nil {
		return query.Paginated[oauth.ExternalClientView]{}, failure(err)
	}
	out := make([]oauth.ExternalClientView, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.domain())
	}
	return query.NewPaginated(out, total, page), nil
}

func (r *Admission) FindExternalClient(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (oauth.ExternalClientView, error) {
	var row viewRow
	err := r.db.GetContext(ctx, &row, `SELECT `+externalViewColumns+` FROM oauth_clients c WHERE c.environment_id=$1 AND c.protected_resource_id=$2 AND c.id=$3 AND c.source='cimd'`, environment, protected, client)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.ExternalClientView{}, errx.NotFound("client not found")
	}
	return row.domain(), failure(err)
}

func (r *Admission) ListAccessRequests(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID, page query.Pagination) (query.Paginated[oauth.AccessRequestView], error) {
	var found bool
	if err := r.db.GetContext(ctx, &found, `SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE id=$3 AND environment_id=$1 AND protected_resource_id=$2)`, environment, protected, client); err != nil {
		return query.Paginated[oauth.AccessRequestView]{}, failure(err)
	}
	if !found {
		return query.Paginated[oauth.AccessRequestView]{}, errx.NotFound("client not found")
	}
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM oauth_client_access_requests WHERE client_id=$1`, client); err != nil {
		return query.Paginated[oauth.AccessRequestView]{}, failure(err)
	}
	rows := []oauth.AccessRequestView{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT a.user_id,COALESCE(u.email,'') AS email,u.name,a.requested_at FROM oauth_client_access_requests a JOIN users u ON u.id=a.user_id WHERE a.client_id=$1 ORDER BY a.requested_at DESC, a.user_id LIMIT $2 OFFSET $3`, client, page.Limit, page.Offset); err != nil {
		return query.Paginated[oauth.AccessRequestView]{}, failure(err)
	}
	return query.NewPaginated(rows, total, page), nil
}

// lockClient reads an external client of the protected resource for a
// change of its admission. FOR NO KEY UPDATE: it conflicts with the FOR
// SHARE of a running authorization or token request (which then finishes
// or waits), not with the key-share lock of a row merely referencing the
// client. Removing the client takes lockClientForDelete.
func lockClient(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (externalRow, error) {
	return lockClientAs(ctx, tx, environment, protected, client, "FOR NO KEY UPDATE")
}

// lockClientForDelete is lockClient for a client about to be deleted: FOR
// UPDATE, so rows that would reference it wait and then find it gone.
func lockClientForDelete(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (externalRow, error) {
	return lockClientAs(ctx, tx, environment, protected, client, "FOR UPDATE")
}

func lockClientAs(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID, lock string) (externalRow, error) {
	var row externalRow
	err := tx.GetContext(ctx, &row, `SELECT id,client_name,client_uri,logo_uri,redirect_uris,grant_types,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks_uri,metadata_fetched_at,admission,admission_source,approved_metadata_hash FROM oauth_clients WHERE id=$1 AND environment_id=$2 AND protected_resource_id=$3 AND source='cimd' `+lock, client, environment, protected)
	if errors.Is(err, sql.ErrNoRows) {
		return row, errx.NotFound("client not found")
	}
	return row, failure(err)
}

// approveRow approves a locked client from source, vouching for the
// document it holds now; a client that was blocked or expired gets a fresh
// start.
func approveRow(ctx context.Context, tx *sqlx.Tx, row externalRow, source string, expires *time.Time) error {
	hash := oauth.MetadataHash([]string(row.Redirects), row.JWKSURI, row.Method)
	_, err := tx.ExecContext(ctx, `UPDATE oauth_clients SET admission='approved', admission_source=$2, admission_expires_at=$3, approved_metadata_hash=$4 WHERE id=$1`, row.ID, source, expires, hash)
	return failure(err)
}

func (r *Admission) ApproveClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID, input oauth.Approval) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		row, err := lockClient(ctx, tx, m.Environment, protected, client)
		if err != nil {
			return err
		}
		// The locked row is the document the approval vouches for: it must
		// be the one the operator reviewed.
		if oauth.MetadataHash([]string(row.Redirects), row.JWKSURI, row.Method) != input.MetadataHash {
			return oauth.ErrClientMetadataChanged()
		}
		if err = approveRow(ctx, tx, row, oauth.SourceManual, input.ExpiresAt); err != nil {
			return err
		}
		data := map[string]any{"protected_resource_id": protected.String(), "admission_source": oauth.SourceManual, "metadata_hash": input.MetadataHash}
		if input.ExpiresAt != nil {
			data["expires_at"] = input.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, data)
	})
}

func (r *Admission) BlockClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := lockClient(ctx, tx, m.Environment, protected, client); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE oauth_clients SET admission='blocked', admission_expires_at=NULL, admission_source='', approved_metadata_hash='' WHERE id=$1`, client); err != nil {
			return failure(err)
		}
		n, err := revokeClients(ctx, tx, m.Environment, []string{client.String()}, false)
		if err != nil {
			return err
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"protected_resource_id": protected.String(), "revoked_sessions": n})
	})
}

func (r *Admission) UnblockClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		row, err := lockClient(ctx, tx, m.Environment, protected, client)
		if err != nil {
			return err
		}
		if row.Admission != oauth.AdmissionBlocked {
			return errx.Conflict("the client is not blocked")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET admission='pending' WHERE id=$1`, client); err != nil {
			return failure(err)
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"protected_resource_id": protected.String()})
	})
}

func (r *Admission) ForgetClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := lockClientForDelete(ctx, tx, m.Environment, protected, client); err != nil {
			return err
		}
		n, err := revokeClients(ctx, tx, m.Environment, []string{client.String()}, true)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM oauth_clients WHERE id=$1 AND environment_id=$2`, client, m.Environment); err != nil {
			return failure(err)
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"protected_resource_id": protected.String(), "revoked_sessions": n})
	})
}

// ExpireApprovals returns approvals past their expiry to pending and ends
// their grants: a client already refused at use (Client.Admitted) stops
// holding live tokens too. Rounds from several replicas split the clients
// (SKIP LOCKED).
func (r *Admission) ExpireApprovals(ctx context.Context, limit int) (int, error) {
	count := 0
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		type due struct {
			ID          identity.ClientID            `db:"id"`
			Environment identity.EnvironmentID       `db:"environment_id"`
			Protected   identity.ProtectedResourceID `db:"protected_resource_id"`
		}
		var rows []due
		if err := tx.SelectContext(ctx, &rows, `SELECT id,environment_id,protected_resource_id FROM oauth_clients WHERE source='cimd' AND admission='approved' AND admission_expires_at IS NOT NULL AND admission_expires_at<=now() ORDER BY admission_expires_at LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED`, limit); err != nil {
			return failure(err)
		}
		for _, d := range rows {
			if _, err := tx.ExecContext(ctx, `UPDATE oauth_clients SET admission='pending', admission_expires_at=NULL, admission_source='', approved_metadata_hash='' WHERE id=$1`, d.ID); err != nil {
				return failure(err)
			}
			n, err := revokeClients(ctx, tx, d.Environment, []string{d.ID.String()}, false)
			if err != nil {
				return err
			}
			if err = eventpg.Emit(ctx, tx, d.Environment, "", event.OAuthClientExpired, event.Subject{Kind: "oauth_client", ID: d.ID.String()},
				map[string]any{"protected_resource_id": d.Protected.String(), "revoked_sessions": n}); err != nil {
				return err
			}
		}
		count = len(rows)
		return nil
	})
	return count, err
}

func (r *Admission) ApprovedEnvironments(ctx context.Context) ([]identity.EnvironmentID, error) {
	var out []identity.EnvironmentID
	err := r.db.SelectContext(ctx, &out, `SELECT DISTINCT environment_id FROM oauth_clients WHERE source='cimd' AND admission='approved'`)
	return out, failure(err)
}

func (r *Admission) DemoteDocuments(ctx context.Context, environment identity.EnvironmentID, limit int) (int, error) {
	n := 0
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) (err error) {
		n, err = demoteApproved(ctx, tx, environment, "", nil, limit, oauth.DemotionFeatureOff, false)
		return err
	})
	return n, err
}

func (r *Admission) ListAllowlist(ctx context.Context, environment identity.EnvironmentID, protected *identity.ProtectedResourceID, page query.Pagination) (query.Paginated[oauth.AllowlistEntry], error) {
	var arg any
	if protected != nil {
		arg = *protected
	}
	where := `environment_id=$1 AND ($2::uuid IS NULL OR protected_resource_id IS NULL OR protected_resource_id=$2)`
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM oauth_client_allowlist WHERE `+where, environment, arg); err != nil {
		return query.Paginated[oauth.AllowlistEntry]{}, failure(err)
	}
	rows := []oauth.AllowlistEntry{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT id,environment_id,protected_resource_id,origin,path_prefix,preset,created_at FROM oauth_client_allowlist WHERE `+where+` ORDER BY created_at, id LIMIT $3 OFFSET $4`, environment, arg, page.Limit, page.Offset); err != nil {
		return query.Paginated[oauth.AllowlistEntry]{}, failure(err)
	}
	return query.NewPaginated(rows, total, page), nil
}

func (r *Admission) FindAllowlistEntry(ctx context.Context, environment identity.EnvironmentID, entry identity.AllowlistEntryID) (oauth.AllowlistEntry, error) {
	var out oauth.AllowlistEntry
	err := r.db.GetContext(ctx, &out, `SELECT id,environment_id,protected_resource_id,origin,path_prefix,preset,created_at FROM oauth_client_allowlist WHERE id=$1 AND environment_id=$2`, entry, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return out, errx.NotFound("allowlist entry not found")
	}
	return out, failure(err)
}

func (r *Admission) CreateAllowlistEntry(ctx context.Context, m oauth.Mutation, entry identity.AllowlistEntryID, input oauth.AllowlistCreate) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var created oauth.AllowlistEntry
		err := tx.GetContext(ctx, &created, `INSERT INTO oauth_client_allowlist(id,environment_id,protected_resource_id,origin,path_prefix,preset) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,environment_id,protected_resource_id,origin,path_prefix,preset,created_at`,
			entry, m.Environment, input.Protected, input.Origin, input.PathPrefix, input.Preset)
		if err != nil {
			var pg *pq.Error
			if errors.As(err, &pg) {
				switch pg.Code.Class() {
				case "23":
					if pg.Constraint == "oauth_client_allowlist_key" {
						return errx.Conflict("this entry is already on the allowlist")
					}
					return errx.NotFound("protected resource not found")
				}
			}
			return failure(err)
		}
		data := map[string]any{"origin": input.Origin, "path_prefix": input.PathPrefix, "preset": input.Preset}
		if input.Protected != nil {
			data["protected_resource_id"] = input.Protected.String()
		}
		if err = eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, data); err != nil {
			return err
		}
		return admitByPolicy(ctx, tx, m, created.Protected, created.Origin, map[string]any{"allowlist_entry_id": created.ID.String()})
	})
}

// admitByPolicy approves the pending clients of the environment (of one
// protected resource, when set) whose URL starts with prefix and that the
// server's policy admits now (an allowlist entry or the open mode), each
// with its own event. It runs when a policy widens: an entry or preset is
// added, the server turns open or takes document clients again.
func admitByPolicy(ctx context.Context, tx *sqlx.Tx, m oauth.Mutation, protected *identity.ProtectedResourceID, prefix string, extra map[string]any) error {
	var arg any
	if protected != nil {
		arg = *protected
	}
	var rows []struct {
		externalRow
		ExternalID string                       `db:"external_id"`
		Protected  identity.ProtectedResourceID `db:"protected_resource_id"`
		Mode       string                       `db:"client_admission"`
	}
	if err := tx.SelectContext(ctx, &rows, `SELECT c.id,c.external_id,c.protected_resource_id,c.client_name,c.client_uri,c.logo_uri,c.redirect_uris,c.grant_types,c.token_endpoint_auth_method,c.token_endpoint_auth_signing_alg,c.jwks_uri,c.metadata_fetched_at,c.admission,c.admission_source,c.approved_metadata_hash,pr.client_admission
		FROM oauth_clients c JOIN protected_resources pr ON pr.id=c.protected_resource_id AND pr.environment_id=c.environment_id
		WHERE c.environment_id=$1 AND c.source='cimd' AND c.admission='pending' AND pr.allow_client_metadata AND c.external_id LIKE $3 AND ($2::uuid IS NULL OR c.protected_resource_id=$2) ORDER BY c.id FOR NO KEY UPDATE OF c`, m.Environment, arg, prefix+"%"); err != nil {
		return failure(err)
	}
	entries, err := allowlistOf(ctx, tx, m.Environment)
	if err != nil {
		return err
	}
	for _, row := range rows {
		u, err := url.Parse(row.ExternalID)
		if err != nil {
			continue
		}
		source := oauth.ExternalTarget{ClientAdmission: row.Mode, Allowlist: entriesFor(entries, row.Protected)}.AdmissionSource(u)
		if source == "" {
			continue
		}
		if err = approveRow(ctx, tx, row.externalRow, source, nil); err != nil {
			return err
		}
		data := map[string]any{"protected_resource_id": row.Protected.String(), "admission_source": source}
		maps.Copy(data, extra)
		if err = eventpg.Emit(ctx, tx, m.Environment, m.Actor, event.OAuthClientApproved, event.Subject{Kind: "oauth_client", ID: row.ID.String()}, data); err != nil {
			return err
		}
	}
	return nil
}

// allowlistOf is every allowlist entry of the environment.
func allowlistOf(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID) ([]oauth.AllowlistEntry, error) {
	var entries []oauth.AllowlistEntry
	err := tx.SelectContext(ctx, &entries, `SELECT id,environment_id,protected_resource_id,origin,path_prefix,preset,created_at FROM oauth_client_allowlist WHERE environment_id=$1`, environment)
	return entries, failure(err)
}

// entriesFor are the entries that apply to one protected resource: its own
// and those for every server of the environment.
func entriesFor(entries []oauth.AllowlistEntry, protected identity.ProtectedResourceID) []oauth.AllowlistEntry {
	var out []oauth.AllowlistEntry
	for _, e := range entries {
		if e.Protected == nil || *e.Protected == protected {
			out = append(out, e)
		}
	}
	return out
}

// approvedRow is an approved external client a policy change may take
// back.
type approvedRow struct {
	ID         identity.ClientID            `db:"id"`
	ExternalID string                       `db:"external_id"`
	Protected  identity.ProtectedResourceID `db:"protected_resource_id"`
	Source     string                       `db:"admission_source"`
	Mode       string                       `db:"client_admission"`
}

// demote returns approved clients to pending, ends their grants and
// sessions and records oauth_client.demoted, all in the caller's
// transaction (M-2): a client that policy no longer admits keeps no live
// token. actor is the operator whose change did it ("" for a job).
func demote(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, actor string, rows []approvedRow, reason string) error {
	if len(rows) == 0 {
		return nil
	}
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID.String()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_clients SET admission='pending', admission_expires_at=NULL, admission_source='', approved_metadata_hash='' WHERE id = ANY($1::uuid[]) AND environment_id=$2`, pq.StringArray(ids), environment); err != nil {
		return failure(err)
	}
	if _, err := revokeClients(ctx, tx, environment, ids, false); err != nil {
		return err
	}
	for _, row := range rows {
		if err := eventpg.Emit(ctx, tx, environment, actor, event.OAuthClientDemoted, event.Subject{Kind: "oauth_client", ID: row.ID.String()},
			map[string]any{"protected_resource_id": row.Protected.String(), "reason": reason, "admission_source": row.Source}); err != nil {
			return err
		}
	}
	return nil
}

// demoteApproved takes back every approval of the protected resource (or
// the whole environment when protected is nil), manual ones too: the
// server no longer takes clients named by a document. wait decides a row
// held by a running authorization (Complete): an operator's change waits
// for it (N-2), so no approval survives the change; the reconcile job skips
// it and takes it on its next round.
func demoteApproved(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, actor string, protected *identity.ProtectedResourceID, limit int, reason string, wait bool) (int, error) {
	var arg any
	if protected != nil {
		arg = *protected
	}
	lock := `FOR NO KEY UPDATE OF c SKIP LOCKED`
	if wait {
		lock = `FOR NO KEY UPDATE OF c`
	}
	var rows []approvedRow
	if err := tx.SelectContext(ctx, &rows, `SELECT c.id,c.external_id,c.protected_resource_id,c.admission_source,'' AS client_admission FROM oauth_clients c
		WHERE c.environment_id=$1 AND c.source='cimd' AND c.admission='approved' AND ($2::uuid IS NULL OR c.protected_resource_id=$2) ORDER BY c.id LIMIT $3 `+lock, environment, arg, limit); err != nil {
		return 0, failure(err)
	}
	return len(rows), demote(ctx, tx, environment, actor, rows, reason)
}

// reconcilePolicy re-checks the clients approved by policy (allowlist, open
// server, preset) whose URL starts with prefix against the policy as it
// stands: one that nothing admits any more returns to pending with its
// grants revoked; one admitted by something else (another entry) is
// relabelled. Manual approvals are not policy and stay.
func reconcilePolicy(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, actor string, protected *identity.ProtectedResourceID, prefix string) error {
	var arg any
	if protected != nil {
		arg = *protected
	}
	var rows []approvedRow
	if err := tx.SelectContext(ctx, &rows, `SELECT c.id,c.external_id,c.protected_resource_id,c.admission_source,pr.client_admission FROM oauth_clients c JOIN protected_resources pr ON pr.id=c.protected_resource_id AND pr.environment_id=c.environment_id
		WHERE c.environment_id=$1 AND c.source='cimd' AND c.admission='approved' AND c.admission_source IN ('allowlist','open','preset') AND ($2::uuid IS NULL OR c.protected_resource_id=$2) AND c.external_id LIKE $3 ORDER BY c.id FOR NO KEY UPDATE OF c`, environment, arg, prefix+"%"); err != nil {
		return failure(err)
	}
	if len(rows) == 0 {
		return nil
	}
	entries, err := allowlistOf(ctx, tx, environment)
	if err != nil {
		return err
	}
	var gone []approvedRow
	for _, row := range rows {
		u, err := url.Parse(row.ExternalID)
		source := ""
		if err == nil {
			source = oauth.ExternalTarget{ClientAdmission: row.Mode, Allowlist: entriesFor(entries, row.Protected)}.AdmissionSource(u)
		}
		switch {
		case source == "":
			gone = append(gone, row)
		case source != row.Source:
			if _, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET admission_source=$2 WHERE id=$1`, row.ID, source); err != nil {
				return failure(err)
			}
		}
	}
	return demote(ctx, tx, environment, actor, gone, oauth.DemotionPolicyEnded)
}

func (r *Admission) DeleteAllowlistEntry(ctx context.Context, m oauth.Mutation, entry identity.AllowlistEntryID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var gone oauth.AllowlistEntry
		err := tx.GetContext(ctx, &gone, `DELETE FROM oauth_client_allowlist WHERE id=$1 AND environment_id=$2 RETURNING id,environment_id,protected_resource_id,origin,path_prefix,preset,created_at`, entry, m.Environment)
		if errors.Is(err, sql.ErrNoRows) {
			return errx.NotFound("allowlist entry not found")
		}
		if err != nil {
			return failure(err)
		}
		if err = eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"origin": gone.Origin, "path_prefix": gone.PathPrefix, "preset": gone.Preset}); err != nil {
			return err
		}
		// The clients this entry admitted lose their approval unless
		// something else still admits them (M-2).
		return reconcilePolicy(ctx, tx, m.Environment, m.Actor, gone.Protected, gone.Origin)
	})
}

func (r *Admission) CreateTemplateClient(ctx context.Context, m oauth.Mutation, id identity.ClientID, input oauth.Registration) (identity.ClientID, bool, error) {
	auth := input.ClientAuth
	out, created := id, false
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public,secret_hash,hosted_login,token_endpoint_auth_method,token_endpoint_auth_signing_alg,access_token_format,grant_types,preset,loopback_any_port) VALUES($1,$2,$3,$4,$5,true,'\x',true,$6,$7,$8,$9,$10,$11) ON CONFLICT (environment_id,application_id,resource_id,preset) WHERE preset<>'' AND source='registered' DO NOTHING`,
			id, m.Environment, input.Application, input.Resource, pq.StringArray(input.Redirects), auth.Method, auth.SigningAlg, input.AccessTokenFormat, pq.StringArray(input.Grants()), input.Preset, input.LoopbackAnyPort)
		if err != nil {
			return conflict(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return tx.GetContext(ctx, &out, `SELECT id FROM oauth_clients WHERE environment_id=$1 AND application_id=$2 AND resource_id=$3 AND preset=$4 AND source='registered'`, m.Environment, input.Application, input.Resource, input.Preset)
		}
		created = true
		return eventpg.Emit(ctx, tx, m.Environment, m.Actor, event.OAuthClientCreated, event.Subject{Kind: "oauth_client", ID: id.String()}, map[string]any{"preset": input.Preset, "application_id": input.Application.String(), "resource_id": input.Resource.String()})
	})
	return out, created, err
}
