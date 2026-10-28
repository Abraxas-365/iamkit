package oauthpg

import (
	"context"
	"database/sql"
	"errors"
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
	var row struct {
		Environment identity.EnvironmentID       `db:"environment_id"`
		Protected   identity.ProtectedResourceID `db:"id"`
		Application identity.ApplicationID       `db:"application_id"`
		Resource    identity.ResourceID          `db:"resource_id"`
		Allow       bool                         `db:"allow_client_metadata"`
		Admission   string                       `db:"client_admission"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT pr.environment_id,pr.id,pr.application_id,pr.resource_id,pr.allow_client_metadata,pr.client_admission FROM protected_resources pr JOIN applications a ON a.id=pr.application_id AND a.environment_id=pr.environment_id WHERE pr.uri=$1 AND pr.active AND a.active`, uri)
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
}

func (row externalRow) same(doc oauth.ExternalClient) bool {
	return row.Name == doc.Name && row.ClientURI == doc.ClientURI && row.LogoURI == doc.LogoURI && slices.Equal(row.Redirects, doc.Redirects) && slices.Equal(row.Grants, doc.GrantTypes) && row.Method == doc.Auth.Method && row.Alg == doc.Auth.SigningAlg && row.JWKSURI == doc.Auth.JWKSURI
}

func (r *Repository) SaveExternalClient(ctx context.Context, target oauth.ExternalTarget, id identity.ClientID, doc oauth.ExternalClient, fetched time.Time, admission string) (identity.ClientID, error) {
	var out identity.ClientID
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		// One writer per (server, URL): concurrent first authorizations
		// insert once.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "cimd:"+target.Protected.String()+":"+doc.ExternalID); err != nil {
			return failure(err)
		}
		var row externalRow
		err := tx.GetContext(ctx, &row, `SELECT id,client_name,client_uri,logo_uri,redirect_uris,grant_types,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks_uri,metadata_fetched_at FROM oauth_clients WHERE protected_resource_id=$1 AND external_id=$2`, target.Protected, doc.ExternalID)
		if errors.Is(err, sql.ErrNoRows) {
			out = id
			if _, err = tx.ExecContext(ctx, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public,hosted_login,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks_uri,grant_types,source,external_id,protected_resource_id,admission,client_name,client_uri,logo_uri,metadata_fetched_at) VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,'cimd',$11,$12,$13,$14,$15,$16,$17)`,
				id, target.Environment, target.Application, target.Resource, pq.StringArray(doc.Redirects), doc.Public(), doc.Auth.Method, doc.Auth.SigningAlg, doc.Auth.JWKSURI, pq.StringArray(doc.GrantTypes), doc.ExternalID, target.Protected, admission, doc.Name, doc.ClientURI, doc.LogoURI, fetched); err != nil {
				return failure(err)
			}
			return eventpg.Emit(ctx, tx, target.Environment, "", event.OAuthClientDiscovered, event.Subject{Kind: "oauth_client", ID: id.String()},
				map[string]any{"client_id": doc.ExternalID, "client_name": doc.Name, "protected_resource_id": target.Protected.String(), "admission": admission})
		}
		if err != nil {
			return failure(err)
		}
		out = row.ID
		if row.Fetched != nil && !fetched.After(*row.Fetched) {
			return nil
		}
		if row.same(doc) {
			_, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET metadata_fetched_at=$2 WHERE id=$1`, row.ID, fetched)
			return failure(err)
		}
		// record_changes attaches the diff to the event (data.changes).
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_clients SET redirect_uris=$2,public=$3,token_endpoint_auth_method=$4,token_endpoint_auth_signing_alg=$5,jwks_uri=$6,grant_types=$7,client_name=$8,client_uri=$9,logo_uri=$10,metadata_fetched_at=$11 WHERE id=$1`,
			row.ID, pq.StringArray(doc.Redirects), doc.Public(), doc.Auth.Method, doc.Auth.SigningAlg, doc.Auth.JWKSURI, pq.StringArray(doc.GrantTypes), doc.Name, doc.ClientURI, doc.LogoURI, fetched); err != nil {
			return failure(err)
		}
		return eventpg.Emit(ctx, tx, target.Environment, "", event.OAuthClientUpdated, event.Subject{Kind: "oauth_client", ID: row.ID.String()},
			map[string]any{"client_id": doc.ExternalID, "protected_resource_id": target.Protected.String(), "source": oauth.SourceCIMD})
	})
	return out, err
}

func (r *Repository) GrantClient(ctx context.Context, clientID, kind, signatureHash string) (identity.EnvironmentID, identity.ClientID, error) {
	var row struct {
		Environment identity.EnvironmentID `db:"environment_id"`
		Client      identity.ClientID      `db:"id"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT c.environment_id,c.id FROM oauth_requests q JOIN oauth_clients c ON c.id=q.client_id AND c.environment_id=q.environment_id WHERE q.kind=$1 AND q.signature_hash=$2 AND q.expires_at>clock_timestamp() AND c.external_id=$3 AND c.active LIMIT 1`, kind, signatureHash, clientID)
	return row.Environment, row.Client, lookup(err)
}
