package oauthhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/ory/fosite"
)

// Devices enables the device authorization grant (RFC 8628): the
// /oauth/device_authorization endpoint, grant_type device_code at the token
// endpoint, and done, the page a user sees after approving a device.
func (h *Handler) Devices(devices oauth.Devices, done func(c *fiber.Ctx, environment identity.EnvironmentID) error) {
	h.devices, h.deviceDone = devices, done
}

// deviceApproved ends a hosted device approval.
func (h *Handler) deviceApproved(c *fiber.Ctx, client *oauth.Client) error {
	if h.deviceDone == nil {
		return c.SendStatus(fiber.StatusNoContent)
	}
	return h.deviceDone(c, client.Environment)
}

// deviceAuthorization is POST /oauth/device_authorization: the client
// authenticates like at the token endpoint (public clients send only
// client_id) and gets a device code and a user code.
func (h *Handler) deviceAuthorization(c *fiber.Ctx) error {
	req := request(c)
	rawID, err := tokenClient(req)
	if err != nil {
		return oauthError(c, "invalid_request", 400)
	}
	p, client, _, err := h.loadFromString(c, rawID)
	if err != nil {
		return clientError(c, err)
	}
	ctx := context.WithValue(req.Context(), oauthfosite.ClientContextKey{}, client.ID.String())
	if _, err = oauthfosite.AuthenticateClient(ctx, p, req.WithContext(ctx)); err != nil {
		return oauthError(c, "invalid_client", 401)
	}
	out, err := h.devices.AuthorizeDevice(c.Context(), client, req.PostForm.Get("scope"))
	if err != nil {
		return deviceError(c, err)
	}
	out.VerificationURI = h.issuer + oauth.DeviceVerificationPath
	out.VerificationURIComplete = out.VerificationURI + "?" + url.Values{"user_code": {out.UserCode}}.Encode()
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	return c.JSON(out)
}

// deviceError sends a device grant error (the errx Code) as an OAuth
// error; anything else is a server error.
func deviceError(c *fiber.Ctx, err error) error {
	var e *errx.Error
	if errors.As(err, &e) && e != nil && e.HTTPStatus < 500 && e.Code != "" {
		return oauthError(c, e.Code, 400)
	}
	return oauthError(c, "server_error", 500)
}

// deviceToken is grant_type=urn:ietf:params:oauth:grant-type:device_code:
// fosite authenticates the client, the service redeems the device code
// (authorization_pending, slow_down, expired_token, access_denied), and
// the tokens carry the claims of the authorization code grant.
func (h *Handler) deviceToken(c *fiber.Ctx, req *http.Request, rawID string) error {
	p, client, _, err := h.loadFromString(c, rawID)
	if err != nil {
		return clientError(c, err)
	}
	ctx := context.WithValue(req.Context(), oauthfosite.ClientContextKey{}, client.ID.String())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ar, err := p.NewAccessRequest(ctx, req, oauthfosite.NewSession())
	if err != nil {
		p.WriteAccessError(ctx, w, ar, err)
		return response(c, w)
	}
	grant, err := h.devices.RedeemDevice(ctx, client, req.PostForm.Get("device_code"))
	if err != nil {
		return deviceError(c, err)
	}
	session := h.session(client, grant.Login, grant.Session, grant.Requested)
	session.SetExpiresAt(fosite.RefreshToken, session.Deadline)
	ar.SetSession(session)
	for _, scope := range grant.Scopes {
		ar.GrantScope(scope)
	}
	ar.GrantAudience(client.Audience)
	out, err := p.NewAccessResponse(ctx, ar)
	if err != nil {
		p.WriteAccessError(ctx, w, ar, err)
	} else {
		p.WriteAccessResponse(ctx, w, ar, out)
	}
	return response(c, w)
}
