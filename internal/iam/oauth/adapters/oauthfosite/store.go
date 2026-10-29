package oauthfosite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/ory/fosite"
)

type Store struct {
	DB          *sqlx.DB
	Environment identity.EnvironmentID
	Clients     oauth.ClientRepository
	// Bound is the client the request was resolved to (nil: none). It is
	// served as is (with a loopback redirect oauth.Client.AdmitRedirect
	// admitted), and it is the only client a client_id URL names: an
	// external client has a row per protected resource, and the handler
	// picked this one.
	Bound *oauth.Client
}

// Client is the client a client_id names: the bound client by the id it
// sends (PublicID: the document URL of an external client, never its row
// uuid, H-1), or a registered client by its uuid.
func (s *Store) Client(ctx context.Context, id string) (*oauth.Client, error) {
	if b := s.Bound; b != nil && id == b.PublicID() {
		return b, nil
	}
	clientID, err := identity.ParseClientID(id)
	if err != nil {
		return nil, errx.NotFound("client not found")
	}
	return s.Clients.FindActive(ctx, s.Environment, clientID)
}

// holder is the client a stored request names by row uuid (the server wrote
// it, so either kind): the bound client, or another live client (a token
// being introspected belongs to a client other than the caller).
func (s *Store) holder(ctx context.Context, row string) (*oauth.Client, error) {
	if b := s.Bound; b != nil && row == b.ID.String() {
		return b, nil
	}
	clientID, err := identity.ParseClientID(row)
	if err != nil {
		return nil, errx.NotFound("client not found")
	}
	return s.Clients.FindHolder(ctx, s.Environment, clientID)
}

// Client is fosite's view of a client: its ID is the client_id the client
// sends (oauth.Client.PublicID, the document URL of an external client),
// and it carries the row's uuid for storage (RowID).
type Client struct {
	*fosite.DefaultOpenIDConnectClient
	Row identity.ClientID
}

// RowID is the oauth_clients id behind a fosite client (zero for a client
// this package did not build).
func RowID(c fosite.Client) identity.ClientID {
	if dto, ok := c.(*Client); ok {
		return dto.Row
	}
	id, _ := identity.ParseClientID(c.GetID())
	return id
}

func clientDTO(c *oauth.Client) *Client {
	return &Client{authClient(&fosite.DefaultClient{ID: c.PublicID(), Secret: c.Secret, RedirectURIs: c.Redirects, Scopes: clientScopes(c), Public: c.Public, Audience: []string{c.Audience}, GrantTypes: grantTypes(c), ResponseTypes: []string{"code"}}, c.Auth), c.ID}
}

// clientScopes are what the client may ask for: the OpenID Connect scopes
// and, when its resource is a protected resource, the resource's
// permissions (ScopeStrategy matches them exactly: they hold no wildcard).
func clientScopes(c *oauth.Client) []string {
	scopes := slices.Clone(oauth.OIDCScopes)
	if c.Protected != nil {
		scopes = append(scopes, c.Protected.Scopes...)
	}
	return scopes
}

// grantTypes are the client's grants (the defaults for a client built
// without them).
func grantTypes(c *oauth.Client) []string {
	if len(c.GrantTypes) == 0 {
		return oauth.DefaultGrantTypes
	}
	return c.GrantTypes
}
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return s.dto(ctx, id, s.Client)
}

// dto is the fosite view of the client find returns, not found as fosite's.
func (s *Store) dto(ctx context.Context, id string, find func(context.Context, string) (*oauth.Client, error)) (fosite.Client, error) {
	c, err := find(ctx, id)
	if err != nil {
		var custom *errx.Error
		if errors.As(err, &custom) && custom != nil && custom.HTTPStatus == 404 {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return clientDTO(c), nil
}
func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return Assertions{s.DB}.Valid(s.assertionContext(ctx), jti)
}
func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, expires time.Time) error {
	return Assertions{s.DB}.Use(s.assertionContext(ctx), jti, expires)
}

// assertionContext keys an external client's spent jti values by its
// client_id URL (D18): one document materialized at several protected
// resources is one client, and an assertion it signed is spent once.
func (s *Store) assertionContext(ctx context.Context) context.Context {
	if s.Bound != nil && s.Bound.External() {
		return context.WithValue(ctx, ClientContextKey{}, s.Bound.ExternalID)
	}
	return ctx
}
func SignatureHash(signature string) string {
	h := sha256.Sum256([]byte(signature))
	return hex.EncodeToString(h[:])
}

type storedRequest struct {
	ID                                                               string
	ClientID                                                         string
	RequestedAt                                                      time.Time
	RequestedScope, GrantedScope, RequestedAudience, GrantedAudience fosite.Arguments
	Form                                                             url.Values
	Session                                                          json.RawMessage
}

func encodeRequest(r fosite.Requester) ([]byte, error) {
	session, err := json.Marshal(r.GetSession())
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "response_mode"} {
		if values, ok := r.GetRequestForm()[key]; ok {
			form[key] = values
		}
	}
	return json.Marshal(storedRequest{r.GetID(), RowID(r.GetClient()).String(), r.GetRequestedAt(), r.GetRequestedScopes(), r.GetGrantedScopes(), r.GetRequestedAudience(), r.GetGrantedAudience(), form, session})
}
func decodeRequest(data []byte, client fosite.Client, session fosite.Session) (fosite.Requester, error) {
	var r storedRequest
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if session == nil || r.ClientID != RowID(client).String() {
		return nil, fosite.ErrInvalidRequest
	}
	// Storage reads must never overwrite the live issuance session: Fosite may
	// reload authorization metadata after current permissions were resolved.
	session = session.Clone()
	if err := json.Unmarshal(r.Session, session); err != nil {
		return nil, err
	}
	return &fosite.Request{ID: r.ID, Client: client, RequestedAt: r.RequestedAt, RequestedScope: r.RequestedScope, GrantedScope: r.GrantedScope, RequestedAudience: r.RequestedAudience, GrantedAudience: r.GrantedAudience, Form: r.Form, Session: session}, nil
}
func (s *Store) put(ctx context.Context, kind, key string, r fosite.Requester, ttl time.Duration) error {
	if _, err := s.GetClient(ctx, r.GetClient().GetID()); err != nil {
		return err
	}
	if err := s.admittedInTx(ctx); err != nil {
		return err
	}
	data, err := encodeRequest(r)
	if err != nil {
		return errx.Wrap(err, "encode OAuth request", errx.TypeInternal)
	}
	_, err = s.executor(ctx).ExecContext(ctx, `INSERT INTO oauth_requests(environment_id,kind,signature_hash,client_id,request_id,data,expires_at) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+($7*interval '1 millisecond'))`, s.Environment, kind, SignatureHash(key), RowID(r.GetClient()), r.GetID(), string(data), ttl.Milliseconds())
	return wrap(err, "persist OAuth request")
}
func (s *Store) get(ctx context.Context, kind, key string, session fosite.Session) (fosite.Requester, error) {
	var row struct {
		Client string `db:"client_id"`
		Data   []byte `db:"data"`
		Active bool   `db:"active"`
	}
	err := sqlx.GetContext(ctx, s.executor(ctx), &row, `SELECT client_id,data,active FROM oauth_requests WHERE environment_id=$1 AND kind=$2 AND signature_hash=$3 AND expires_at>clock_timestamp()`, s.Environment, kind, SignatureHash(key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, wrap(err, "load OAuth storage")
	}
	expected, _ := ctx.Value(ClientContextKey{}).(string)
	if expected != "" && expected != row.Client {
		return nil, fosite.ErrNotFound
	}
	client, err := s.dto(ctx, row.Client, s.holder)
	if err != nil {
		return nil, err
	}
	if session == nil {
		session = NewSession()
	}
	r, err := decodeRequest(row.Data, client, session)
	if err != nil {
		return nil, wrap(err, "decode OAuth request")
	}
	if !row.Active {
		if kind == "refresh" {
			return r, fosite.ErrInactiveToken
		}
		return r, fosite.ErrInvalidatedAuthorizeCode
	}
	return r, nil
}
func (s *Store) remove(ctx context.Context, kind, key string) error {
	_, err := s.executor(ctx).ExecContext(ctx, `DELETE FROM oauth_requests WHERE environment_id=$1 AND kind=$2 AND signature_hash=$3`, s.Environment, kind, SignatureHash(key))
	return wrap(err, "delete OAuth request")
}
func wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, message, errx.TypeInternal)
}
func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, key string, r fosite.Requester) error {
	return s.put(ctx, "code", key, r, 5*time.Minute)
}
func (s *Store) GetAuthorizeCodeSession(ctx context.Context, key string, session fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "code", key, session)
}
func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, key string) error {
	if err := s.admittedInTx(ctx); err != nil {
		return err
	}
	res, err := s.executor(ctx).ExecContext(ctx, `UPDATE oauth_requests SET active=false WHERE environment_id=$1 AND kind='code' AND signature_hash=$2 AND active AND expires_at>clock_timestamp()`, s.Environment, SignatureHash(key))
	if err != nil {
		return wrap(err, "consume code")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrap(err, "consume code")
	}
	if n != 1 {
		return fosite.ErrInvalidatedAuthorizeCode
	}
	return nil
}
func (s *Store) CreatePKCERequestSession(ctx context.Context, key string, r fosite.Requester) error {
	return s.put(ctx, "pkce", key, r, 5*time.Minute)
}
func (s *Store) GetPKCERequestSession(ctx context.Context, key string, session fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "pkce", key, session)
}
func (s *Store) DeletePKCERequestSession(ctx context.Context, key string) error {
	// Code consumption is the single-use guard. Keep PKCE metadata until expiry,
	// including after invalid verifier attempts.
	return nil
}
func (s *Store) CreateOpenIDConnectSession(ctx context.Context, key string, r fosite.Requester) error {
	return s.put(ctx, "openid", key, r, 5*time.Minute)
}
func (s *Store) GetOpenIDConnectSession(ctx context.Context, key string, r fosite.Requester) (fosite.Requester, error) {
	return s.get(ctx, "openid", key, r.GetSession())
}
func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, key string) error {
	return s.remove(ctx, "openid", key)
}
func (s *Store) CreateAccessTokenSession(ctx context.Context, key string, r fosite.Requester) error {
	return s.put(ctx, "access", key, r, time.Until(r.GetSession().GetExpiresAt(fosite.AccessToken)))
}
func (s *Store) GetAccessTokenSession(ctx context.Context, key string, session fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "access", key, session)
}
func (s *Store) DeleteAccessTokenSession(ctx context.Context, key string) error {
	return s.remove(ctx, "access", key)
}
func (s *Store) CreateRefreshTokenSession(ctx context.Context, key, _ string, r fosite.Requester) error {
	return s.put(ctx, "refresh", key, r, time.Until(r.GetSession().GetExpiresAt(fosite.RefreshToken)))
}
func (s *Store) GetRefreshTokenSession(ctx context.Context, key string, session fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "refresh", key, session)
}
func (s *Store) DeleteRefreshTokenSession(context.Context, string) error { return nil }
func (s *Store) RotateRefreshToken(ctx context.Context, id, key string) error {
	if err := s.admittedInTx(ctx); err != nil {
		return err
	}
	if err := s.lock(ctx, id); err != nil {
		return err
	}
	res, err := s.executor(ctx).ExecContext(ctx, `UPDATE oauth_requests SET active=false WHERE environment_id=$1 AND kind='refresh' AND request_id=$2 AND signature_hash=$3 AND active AND expires_at>now()`, s.Environment, id, SignatureHash(key))
	if err != nil {
		return wrap(err, "rotate token")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrap(err, "rotate token")
	}
	if n != 1 {
		return fosite.ErrInactiveToken
	}
	return nil
}
func (s *Store) RevokeRefreshToken(ctx context.Context, id string) error {
	if _, ok := ctx.Value(txKey{s}).(*sqlx.Tx); !ok {
		return s.revokeFamily(ctx, id)
	}
	if err := s.lock(ctx, id); err != nil {
		return err
	}
	_, err := s.executor(ctx).ExecContext(ctx, `UPDATE oauth_requests SET active=false WHERE environment_id=$1 AND kind='refresh' AND request_id=$2`, s.Environment, id)
	return wrap(err, "revoke refresh family")
}
func (s *Store) RevokeAccessToken(ctx context.Context, id string) error {
	if _, ok := ctx.Value(txKey{s}).(*sqlx.Tx); !ok {
		return s.revokeFamily(ctx, id)
	}
	_, err := s.executor(ctx).ExecContext(ctx, `DELETE FROM oauth_requests WHERE environment_id=$1 AND kind='access' AND request_id=$2`, s.Environment, id)
	return wrap(err, "revoke access family")
}

type txKey struct{ store *Store }

// admittedKey holds, in a transaction of an external client, whether the
// client's row (locked by BeginTX) admits it.
type admittedKey struct{ store *Store }

// ErrNotAdmitted is what a token transaction of an external client answers
// when, in the transaction, the client is no longer admitted (blocked,
// demoted, expired, forgotten or its server gone). The token endpoint
// answers it as an ended grant (invalid_grant).
var ErrNotAdmitted = errors.New("the client is not admitted")

// admittedInTx refuses, in a token transaction of an external client, a
// client its locked row no longer admits. It runs before the transaction
// spends a code, rotates a refresh token or stores a token: an operator's
// change that committed first is seen here (and has already revoked the
// rows it would touch); one that comes later waits for this transaction
// and revokes what it issued.
func (s *Store) admittedInTx(ctx context.Context) error {
	if admitted, ok := ctx.Value(admittedKey{s}).(bool); ok && !admitted {
		return ErrNotAdmitted
	}
	return nil
}

func (s *Store) executor(ctx context.Context) sqlx.ExtContext {
	if tx, ok := ctx.Value(txKey{s}).(*sqlx.Tx); ok {
		return tx
	}
	return s.DB
}

// BeginTX opens fosite's transaction. For an external client it first
// locks the client's row (FOR SHARE) and reads its admission: the one lock
// order of IAMKit (the client row, then its tickets, token rows and
// sessions), which an operator's block, demotion or delete takes too. A
// token transaction that held a token row first and then met the client
// row through the foreign key of its insert would deadlock with them
// (W4-1).
func (s *Store) BeginTX(ctx context.Context) (context.Context, error) {
	tx, err := s.DB.BeginTxx(ctx, nil)
	if err != nil {
		return ctx, wrap(err, "begin OAuth transaction")
	}
	ctx = context.WithValue(ctx, txKey{s}, tx)
	if b := s.Bound; b != nil && b.External() && !b.ID.IsZero() {
		admitted, state, err := s.admitted(ctx, tx, b.ID)
		if err != nil {
			_ = tx.Rollback()
			return ctx, err
		}
		ctx = context.WithValue(ctx, admittedKey{s}, admitted)
		ctx = context.WithValue(ctx, stateKey{s}, state)
	}
	return ctx, nil
}

// stateKey holds the admission BeginTX read for an external client (nil:
// its row is gone).
type stateKey struct{ store *Store }

// Refusal is the hosted refusal of an external client its transaction
// found not admitted: blocked, documents off, or pending (demoted,
// expired, forgotten or deleted with its server).
func (s *Store) Refusal(ctx context.Context) error {
	state, _ := ctx.Value(stateKey{s}).(*oauth.AdmissionState)
	switch {
	case state != nil && state.Disabled:
		return oauth.ErrClientDisabled()
	case state != nil && state.Admission == oauth.AdmissionBlocked:
		return oauth.ErrClientBlocked()
	}
	return oauth.ErrAdmissionPending()
}

// admitted locks an external client's row in tx and reports whether it
// admits the client now, with the state it read; a row that is gone does
// not (nil state). It does not read the source's feature
// (client_metadata_documents, dynamic_client_registration; W5-4): the
// handler's at-use Client.Admitted check does, and a flag turned off
// between that check and this transaction is caught by the
// client_documents_reconcile job, which demotes and revokes.
func (s *Store) admitted(ctx context.Context, tx *sqlx.Tx, client identity.ClientID) (bool, *oauth.AdmissionState, error) {
	var row struct {
		Admission string     `db:"admission"`
		Expires   *time.Time `db:"admission_expires_at"`
		Allow     bool       `db:"allow_client_metadata"`
	}
	err := tx.GetContext(ctx, &row, `SELECT c.admission,c.admission_expires_at,CASE c.source WHEN 'dcr' THEN pr.allow_dynamic_registration ELSE pr.allow_client_metadata END AS allow_client_metadata FROM oauth_clients c JOIN protected_resources pr ON pr.id=c.protected_resource_id AND pr.environment_id=c.environment_id WHERE c.id=$1 AND c.environment_id=$2 AND c.source<>'registered' AND c.active FOR SHARE OF c`, client, s.Environment)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, wrap(err, "lock OAuth client")
	}
	state := &oauth.AdmissionState{Admission: row.Admission, Expires: row.Expires, Disabled: !row.Allow}
	return state.Admitted(time.Now()), state, nil
}
func (s *Store) Commit(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{s}).(*sqlx.Tx)
	if !ok {
		return fosite.ErrServerError
	}
	return wrap(tx.Commit(), "commit OAuth transaction")
}
func (s *Store) Rollback(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{s}).(*sqlx.Tx)
	if !ok {
		return fosite.ErrServerError
	}
	err := tx.Rollback()
	if errors.Is(err, sql.ErrTxDone) {
		return nil
	}
	return wrap(err, "rollback OAuth transaction")
}
func (s *Store) lock(ctx context.Context, id string) error {
	if _, ok := ctx.Value(txKey{s}).(*sqlx.Tx); !ok {
		return fosite.ErrServerError
	}
	_, err := s.executor(ctx).ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, s.Environment.String()+":"+id)
	return wrap(err, "lock OAuth family")
}
