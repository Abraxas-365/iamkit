// Package oauthfosite integrates Fosite with environment-bound IAMKit ports.
package oauthfosite

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
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

type ClientContextKey struct{}

func NewProvider(store *Store, issuer string, secret []byte, key *rsa.PrivateKey) (fosite.OAuth2Provider, error) {
	if len(secret) < 32 || key == nil || key.N.BitLen() < 2048 {
		return nil, errx.Internal("OIDC signing configuration is invalid")
	}
	cfg := &fosite.Config{GlobalSecret: secret, AuthorizeCodeLifespan: 5 * time.Minute, AccessTokenLifespan: 15 * time.Minute, RefreshTokenLifespan: 24 * time.Hour, RefreshTokenScopes: []string{"offline_access"}, IDTokenLifespan: 15 * time.Minute, IDTokenIssuer: issuer, AccessTokenIssuer: issuer, EnforcePKCE: true, EnablePKCEPlainChallengeMethod: false, SendDebugMessagesToClients: false}
	getter := func(context.Context) (any, error) { return key, nil }
	hmac := compose.NewOAuth2HMACStrategy(cfg)
	strategy := &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2JWTStrategy(getter, hmac, cfg), OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(getter, cfg), Signer: &jwt.DefaultSigner{GetPrivateKey: getter}}
	return compose.Compose(cfg, store, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2RefreshTokenGrantFactory, compose.OpenIDConnectExplicitFactory, compose.OAuth2PKCEFactory, revocationFactory), nil
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
