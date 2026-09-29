// Package oauthfosite integrates Fosite with environment-bound IAMKit ports.
package oauthfosite

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

type Session struct {
	*openid.DefaultSession
	Deadline      time.Time      `json:"deadline"`
	AccessClaims  *jwt.JWTClaims `json:"access_claims"`
	AccessHeaders *jwt.Headers   `json:"access_headers"`
}

func NewSession() *Session {
	return &Session{DefaultSession: openid.NewDefaultSession(), AccessClaims: &jwt.JWTClaims{}, AccessHeaders: &jwt.Headers{}}
}
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer { return s.AccessClaims }
func (s *Session) GetJWTHeader() *jwt.Headers           { return s.AccessHeaders }
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(*Session)
}

// GetExtraClaims is what /oauth/introspect adds to its response: the
// IAMKit access claims (environment, organization, application, resource,
// permissions, sid, amr, auth_time) and the issuer. fosite keeps its own
// reserved fields (sub, aud, exp, scope, client_id, iat).
func (s *Session) GetExtraClaims() map[string]interface{} {
	out := map[string]interface{}{}
	if s == nil || s.AccessClaims == nil {
		return out
	}
	for k, v := range s.AccessClaims.Extra {
		out[k] = v
	}
	if s.AccessClaims.Issuer != "" {
		out["iss"] = s.AccessClaims.Issuer
	}
	return out
}

type ClientContextKey struct{}

// NewProvider builds the OAuth2/OIDC provider for one environment. opaque
// makes new access tokens HMAC handles (ory_at_…) instead of JWTs; tokens
// of either shape keep validating.
func NewProvider(store *Store, issuer string, secret []byte, keys signing.Keyring, fetcher fosite.JWKSFetcherStrategy, opaque bool) (fosite.OAuth2Provider, error) {
	if len(secret) < 32 || keys == nil {
		return nil, errx.Internal("OIDC signing configuration is invalid")
	}
	cfg := &fosite.Config{GlobalSecret: secret, AuthorizeCodeLifespan: config.OAuthAuthorizeCodeLifespan, AccessTokenLifespan: config.OAuthAccessTokenLifespan, RefreshTokenLifespan: config.OAuthRefreshTokenLifespan, RefreshTokenScopes: []string{"offline_access"}, IDTokenLifespan: config.OAuthIDTokenLifespan, IDTokenIssuer: issuer, AccessTokenIssuer: issuer, EnforcePKCE: true, EnablePKCEPlainChallengeMethod: false, SendDebugMessagesToClients: false, TokenURL: issuer + "/oauth/token", JWKSFetcherStrategy: fetcher}
	signer := Signer{Keys: keys, Environment: store.Environment}
	hmac := compose.NewOAuth2HMACStrategy(cfg)
	strategy := &compose.CommonStrategy{
		CoreStrategy:               &formatStrategy{jwt: &oauth2.DefaultJWTStrategy{Signer: signer, HMACSHAStrategy: hmac, Config: cfg}, HMACSHAStrategy: hmac, opaque: opaque},
		OpenIDConnectTokenStrategy: &openid.DefaultStrategy{Signer: signer, Config: cfg},
		Signer:                     signer,
	}
	p := compose.Compose(cfg, store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2RefreshTokenGrantFactory, compose.OpenIDConnectExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory, revocationFactory, deviceFactory)
	if f, ok := p.(*fosite.Fosite); ok {
		f.Config = tokenURLs{Config: cfg, issuer: issuer}
	}
	return p, nil
}

// formatStrategy issues JWT or opaque access tokens and recognises both by
// shape, so switching a client's format never strands tokens already
// issued (and introspection by another client of the environment works).
// Refresh tokens and authorization codes are HMAC handles either way.
type formatStrategy struct {
	*oauth2.HMACSHAStrategy
	jwt    *oauth2.DefaultJWTStrategy
	opaque bool
}

func isJWT(token string) bool { return strings.Count(token, ".") == 2 }

func (s *formatStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	if isJWT(token) {
		return s.jwt.AccessTokenSignature(ctx, token)
	}
	return s.HMACSHAStrategy.AccessTokenSignature(ctx, token)
}
func (s *formatStrategy) GenerateAccessToken(ctx context.Context, r fosite.Requester) (string, string, error) {
	if s.opaque {
		return s.HMACSHAStrategy.GenerateAccessToken(ctx, r)
	}
	return s.jwt.GenerateAccessToken(ctx, r)
}
func (s *formatStrategy) ValidateAccessToken(ctx context.Context, r fosite.Requester, token string) error {
	if isJWT(token) {
		return s.jwt.ValidateAccessToken(ctx, r, token)
	}
	return s.HMACSHAStrategy.ValidateAccessToken(ctx, r, token)
}

// OpaquePrefix starts every opaque access token.
const OpaquePrefix = "ory_at_"

// OpaqueKey is the storage key (signature hash) of an opaque access token,
// empty for anything else.
func OpaqueKey(token string) string {
	if !strings.HasPrefix(token, OpaquePrefix) || strings.Count(token, ".") != 1 {
		return ""
	}
	signature := token[strings.Index(token, ".")+1:]
	if signature == "" {
		return ""
	}
	return SignatureHash(signature)
}

type transactionalRevoker struct {
	handler fosite.RevocationHandler
	store   storage.Transactional
}

func (r *transactionalRevoker) RevokeToken(ctx context.Context, token string, kind fosite.TokenType, client fosite.Client) error {
	ctx, err := r.store.BeginTX(ctx)
	if err != nil {
		return err
	}
	defer r.store.Rollback(ctx)
	if err = r.handler.RevokeToken(ctx, token, kind, client); err != nil {
		return err
	}
	return r.store.Commit(ctx)
}
func revocationFactory(config fosite.Configurator, store interface{}, strategy interface{}) interface{} {
	return &transactionalRevoker{handler: compose.OAuth2TokenRevocationFactory(config, store, strategy).(fosite.RevocationHandler), store: store.(storage.Transactional)}
}
