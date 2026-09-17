package oauthfosite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/jmoiron/sqlx"
	"github.com/ory/fosite"
)

type Store struct {
	DB          *sqlx.DB
	Environment string
	Clients     oauth.ClientRepository
}

func (s *Store) Client(ctx context.Context, id string) (*oauth.Client, error) {
	return s.Clients.FindActive(ctx, s.Environment, id)
}
func clientDTO(c *oauth.Client) *fosite.DefaultOpenIDConnectClient {
	method := "client_secret_basic"
	if c.Public {
		method = "none"
	}
	return &fosite.DefaultOpenIDConnectClient{DefaultClient: &fosite.DefaultClient{ID: c.ID, Secret: c.Secret, RedirectURIs: c.Redirects, Scopes: []string{"openid", "profile", "email", "offline_access"}, Public: c.Public, Audience: []string{c.Audience}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}}, TokenEndpointAuthMethod: method}
}
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	c, err := s.Client(ctx, id)
	if err != nil {
		var custom *errx.Error
		if errors.As(err, &custom) && custom != nil && custom.HTTPStatus == 404 {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return clientDTO(c), nil
}
func (s *Store) ClientAssertionJWTValid(context.Context, string) error {
	return fosite.ErrInvalidClient
}
func (s *Store) SetClientAssertionJWT(context.Context, string, time.Time) error {
	return fosite.ErrInvalidClient
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
	return json.Marshal(storedRequest{r.GetID(), r.GetClient().GetID(), r.GetRequestedAt(), r.GetRequestedScopes(), r.GetGrantedScopes(), r.GetRequestedAudience(), r.GetGrantedAudience(), form, session})
}
func decodeRequest(data []byte, client fosite.Client, session fosite.Session) (fosite.Requester, error) {
	var r storedRequest
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if session == nil || r.ClientID != client.GetID() {
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
	data, err := encodeRequest(r)
	if err != nil {
		return errx.Wrap(err, "encode OAuth request", errx.TypeInternal)
	}
	_, err = s.executor(ctx).ExecContext(ctx, `INSERT INTO oauth_requests(environment_id,kind,signature_hash,client_id,request_id,data,expires_at) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+($7*interval '1 millisecond'))`, s.Environment, kind, SignatureHash(key), r.GetClient().GetID(), r.GetID(), string(data), ttl.Milliseconds())
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
	client, err := s.GetClient(ctx, row.Client)
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

func (s *Store) executor(ctx context.Context) sqlx.ExtContext {
	if tx, ok := ctx.Value(txKey{s}).(*sqlx.Tx); ok {
		return tx
	}
	return s.DB
}
func (s *Store) BeginTX(ctx context.Context) (context.Context, error) {
	tx, err := s.DB.BeginTxx(ctx, nil)
	if err != nil {
		return ctx, wrap(err, "begin OAuth transaction")
	}
	return context.WithValue(ctx, txKey{s}, tx), nil
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
	_, err := s.executor(ctx).ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, s.Environment+":"+id)
	return wrap(err, "lock OAuth family")
}
