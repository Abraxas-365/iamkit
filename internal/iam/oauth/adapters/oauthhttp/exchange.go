package oauthhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Exchanges enables grant_type=urn:ietf:params:oauth:grant-type:token-exchange.
func (h *Handler) Exchanges(exchanges oauth.Exchanges) { h.exchanges = exchanges }

// exchangeToken is RFC 8693 token exchange. The subject token type picks
// the kind: an access token (an OAuth client exchanging a user's token for
// another resource of its application) or a user id (a service account
// allowed to impersonate, authenticated like client_credentials). Issued
// tokens are IAMKit access JWTs, tied to their session like any other.
func (h *Handler) exchangeToken(c *fiber.Ctx, req *http.Request, rawID string) error {
	form := req.PostForm
	if form.Get("subject_token") == "" {
		return oauthError(c, oauth.ExchangeInvalidRequest, 400)
	}
	if t := form.Get("requested_token_type"); t != "" && t != oauth.TokenTypeAccessToken {
		return oauthError(c, oauth.ExchangeInvalidRequest, 400)
	}
	// The acting party is the authenticated client, not a second token.
	if form.Get("actor_token") != "" || form.Get("actor_token_type") != "" {
		return oauthError(c, oauth.ExchangeInvalidRequest, 400)
	}
	var out oauth.Exchanged
	var err error
	switch form.Get("subject_token_type") {
	case oauth.TokenTypeAccessToken:
		p, client, _, loadErr := h.loadFromString(c, rawID)
		if loadErr != nil {
			return clientError(c, loadErr)
		}
		ctx := context.WithValue(req.Context(), oauthfosite.ClientContextKey{}, client.ID.String())
		if _, authErr := oauthfosite.AuthenticateClient(ctx, p, req.WithContext(ctx)); authErr != nil {
			return oauthError(c, "invalid_client", 401)
		}
		subject, subjectErr := h.subjectToken(c, form.Get("subject_token"))
		if subjectErr != nil {
			return oauthError(c, oauth.ExchangeInvalidRequest, 400)
		}
		out, err = h.exchanges.ExchangeResource(c.UserContext(), client, oauth.Exchange{Subject: subject, Audience: form.Get("audience"), Scope: strings.Fields(form.Get("scope"))})
	case oauth.TokenTypeUserID:
		if h.accounts == nil {
			return oauthError(c, oauth.ExchangeUnauthorizedClient, 400)
		}
		id, parseErr := identity.ParseAccountID(rawID)
		if parseErr != nil {
			return oauthError(c, "invalid_client", 401)
		}
		account, authErr := h.accounts.Authenticate(req.Context(), id, req)
		if authErr != nil {
			return clientError(c, authErr)
		}
		user, _ := identity.ParseUserID(form.Get("subject_token"))
		organization, _ := identity.ParseOrganizationID(form.Get("organization_id"))
		out, err = h.exchanges.Impersonate(c.UserContext(), oauth.Impersonation{Account: account, User: user, Organization: organization, Reason: form.Get("reason"), Audience: form.Get("audience")})
	default:
		return oauthError(c, oauth.ExchangeInvalidRequest, 400)
	}
	if err != nil {
		return exchangeError(c, err)
	}
	raw, err := h.tokens.Sign(c, out.Token, out.Audience)
	if err != nil {
		return oauthError(c, "server_error", 500)
	}
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	return c.JSON(fiber.Map{"access_token": raw, "issued_token_type": oauth.TokenTypeAccessToken, "token_type": "Bearer", "expires_in": int(config.TokenTTL.Seconds())})
}

// subjectToken resolves a user access token: a JWT, or an opaque OAuth
// access token (through introspection).
func (h *Handler) subjectToken(c *fiber.Ctx, raw string) (authentication.Token, error) {
	if key := oauthfosite.OpaqueKey(raw); key != "" {
		return h.opaqueToken(c, key, raw)
	}
	return h.tokens.Verify(c, raw)
}

// exchangeError sends an exchange error (the errx Code) as an OAuth error.
func exchangeError(c *fiber.Ctx, err error) error {
	var e *errx.Error
	if errors.As(err, &e) && e != nil && e.HTTPStatus < 500 {
		switch e.Code {
		case oauth.ExchangeInvalidRequest, oauth.ExchangeInvalidTarget, oauth.ExchangeInvalidScope, oauth.ExchangeUnauthorizedClient:
			return oauthError(c, e.Code, 400)
		}
		return oauthError(c, oauth.ExchangeInvalidRequest, 400)
	}
	return oauthError(c, "server_error", 500)
}
