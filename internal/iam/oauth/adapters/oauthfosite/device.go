package oauthfosite

import (
	"context"
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
)

// deviceGrant is the token endpoint side of the device authorization
// grant (RFC 8628 §3.4). fosite has no handler for it: this one only
// checks the request (after fosite authenticated the client); the HTTP
// adapter redeems the device code and fills the session in between
// NewAccessRequest and NewAccessResponse, and PopulateTokenEndpointResponse
// then issues the tokens like the authorization code grant does.
type deviceGrant struct {
	config   fosite.Configurator
	store    *Store
	strategy *deviceStrategy
}

// deviceStrategy is the part of fosite's CommonStrategy the grant needs.
type deviceStrategy struct {
	access  oauth2.AccessTokenStrategy
	refresh oauth2.RefreshTokenStrategy
	id      openid.OpenIDConnectTokenStrategy
}

func deviceFactory(config fosite.Configurator, store interface{}, strategy interface{}) interface{} {
	return &deviceGrant{config: config, store: store.(*Store), strategy: &deviceStrategy{access: strategy.(oauth2.AccessTokenStrategy), refresh: strategy.(oauth2.RefreshTokenStrategy), id: strategy.(openid.OpenIDConnectTokenStrategy)}}
}

func (d *deviceGrant) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool { return false }
func (d *deviceGrant) CanHandleTokenEndpointRequest(_ context.Context, r fosite.AccessRequester) bool {
	return r.GetGrantTypes().ExactOne(oauth.GrantDeviceCode)
}
func (d *deviceGrant) HandleTokenEndpointRequest(ctx context.Context, r fosite.AccessRequester) error {
	if !d.CanHandleTokenEndpointRequest(ctx, r) {
		return fosite.ErrUnknownRequest
	}
	if !r.GetClient().GetGrantTypes().Has(oauth.GrantDeviceCode) {
		return fosite.ErrUnauthorizedClient.WithHint("The client is not allowed to use the device grant.")
	}
	if r.GetRequestForm().Get("device_code") == "" {
		return fosite.ErrInvalidRequest.WithHint("device_code is required.")
	}
	return nil
}

// PopulateTokenEndpointResponse issues the access token, a refresh token
// when offline_access was granted, and an ID token for openid.
func (d *deviceGrant) PopulateTokenEndpointResponse(ctx context.Context, r fosite.AccessRequester, w fosite.AccessResponder) (err error) {
	if !d.CanHandleTokenEndpointRequest(ctx, r) {
		return fosite.ErrUnknownRequest
	}
	session, ok := r.GetSession().(*Session)
	if !ok || session.Subject == "" {
		return fosite.ErrServerError.WithDebug("device session missing")
	}
	now := time.Now().UTC()
	lifespan := d.config.GetAccessTokenLifespan(ctx)
	session.SetExpiresAt(fosite.AccessToken, now.Add(lifespan).Round(time.Second))
	access, accessSignature, err := d.strategy.access.GenerateAccessToken(ctx, r)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	var refresh, refreshSignature string
	if r.GetGrantedScopes().Has("offline_access") && r.GetClient().GetGrantTypes().Has("refresh_token") {
		if refresh, refreshSignature, err = d.strategy.refresh.GenerateRefreshToken(ctx, r); err != nil {
			return fosite.ErrServerError.WithWrap(err)
		}
	}
	ctx, err = storage.MaybeBeginTx(ctx, d.store)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	defer func() {
		if err != nil {
			_ = storage.MaybeRollbackTx(ctx, d.store)
		}
	}()
	if err = d.store.CreateAccessTokenSession(ctx, accessSignature, r.Sanitize([]string{})); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if refreshSignature != "" {
		if err = d.store.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, r.Sanitize([]string{})); err != nil {
			return fosite.ErrServerError.WithWrap(err)
		}
	}
	if err = storage.MaybeCommitTx(ctx, d.store); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	w.SetAccessToken(access)
	w.SetTokenType("bearer")
	w.SetExpiresIn(time.Until(session.GetExpiresAt(fosite.AccessToken)))
	w.SetScopes(r.GetGrantedScopes())
	if refresh != "" {
		w.SetExtra("refresh_token", refresh)
	}
	if r.GetGrantedScopes().Has("openid") {
		helper := openid.IDTokenHandleHelper{IDTokenStrategy: d.strategy.id}
		session.IDTokenClaims().AccessTokenHash = helper.GetAccessTokenHash(ctx, r, w)
		if err := helper.IssueExplicitIDToken(ctx, d.config.GetIDTokenLifespan(ctx), r, w); err != nil {
			return err
		}
	}
	return nil
}

// AuthenticateClient runs the provider's client authentication (secret,
// private_key_jwt or none for public clients) on a parsed form request,
// for endpoints fosite does not serve (/oauth/device_authorization).
func AuthenticateClient(ctx context.Context, p fosite.OAuth2Provider, r *http.Request) (fosite.Client, error) {
	f, ok := p.(*fosite.Fosite)
	if !ok {
		return nil, errx.Internal("OAuth provider does not authenticate clients")
	}
	return f.AuthenticateClient(ctx, r, r.PostForm)
}
