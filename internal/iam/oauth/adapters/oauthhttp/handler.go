package oauthhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/oauthsvc"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/ory/fosite"
)

type Provider func(*oauth.Client) (fosite.OAuth2Provider, *oauthfosite.Store, error)
type Handler struct {
	commands oauth.Commands
	queries  oauth.Queries
	flows    oauth.Flows
	provider Provider
	tokens   *authhttp.Tokens
	issuer   string
	actor    func(*fiber.Ctx) string
}

func New(commands oauth.Commands, queries oauth.Queries, flows oauth.Flows, provider Provider, tokens *authhttp.Tokens, issuer string, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands, queries, flows, provider, tokens, issuer, actor}
}
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) RegisterManagement(r fiber.Router) {
	r.Post("/oauth-clients", h.create)
	r.Get("/oauth-clients", h.list)
	r.Delete("/oauth-clients/:id", h.disable)
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input oauth.Registration
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, secret, err := h.commands.Create(c.Context(), env(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id, "client_id": id, "client_secret": secret})
}
func (h *Handler) disable(c *fiber.Ctx) error {
	clientID, err := identity.ParseClientID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid client id")
	}
	m := oauth.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.Disable(c.Context(), m, clientID); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) list(c *fiber.Ctx) error {
	out, err := h.queries.List(c.Context(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(httpx.NewPaginated(c, out))
}
func (h *Handler) load(c *fiber.Ctx, id identity.ClientID) (fosite.OAuth2Provider, *oauth.Client, *oauthfosite.Store, error) {
	client, err := h.flows.Client(c.Context(), id)
	if err != nil {
		return nil, nil, nil, errx.Wrap(err, "OAuth client lookup failed", errx.TypeInternal)
	}
	p, store, err := h.provider(client)
	return p, client, store, err
}
func (h *Handler) loadFromString(c *fiber.Ctx, raw string) (fosite.OAuth2Provider, *oauth.Client, *oauthfosite.Store, error) {
	id, err := identity.ParseClientID(raw)
	if err != nil {
		return nil, nil, nil, errx.NotFound("client not found")
	}
	return h.load(c, id)
}
func request(c *fiber.Ctx) *http.Request {
	req := httptest.NewRequest(c.Method(), "https://iamkit.invalid"+c.OriginalURL(), strings.NewReader(string(c.Body())))
	c.Request().Header.VisitAll(func(k, v []byte) { req.Header.Set(string(k), string(v)) })
	return req.WithContext(c.Context())
}
func response(c *fiber.Ctx, w *httptest.ResponseRecorder) error {
	for k, values := range w.Header() {
		for _, v := range values {
			c.Append(k, v)
		}
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(w.Code).Send(w.Body.Bytes())
}
func (h *Handler) Register(app *fiber.App) {
	app.Get("/.well-known/openid-configuration", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"issuer": h.issuer, "authorization_endpoint": h.issuer + "/oauth/authorize", "token_endpoint": h.issuer + "/oauth/token", "revocation_endpoint": h.issuer + "/oauth/revoke", "jwks_uri": h.issuer + "/.well-known/jwks.json", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "scopes_supported": []string{"openid", "profile", "email", "offline_access"}, "code_challenge_methods_supported": []string{"S256"}})
	})
	app.Get("/oauth/authorize", h.authorize)
	app.Post("/oauth/authorize/complete", h.complete)
	app.Post("/oauth/token", endpointErrors(h.token))
	app.Post("/oauth/revoke", endpointErrors(h.revoke))
}
func (h *Handler) authorize(c *fiber.Ctx) error {
	req := request(c)
	q := req.URL.Query()
	p, client, _, err := h.loadFromString(c, q.Get("client_id"))
	if err != nil {
		return err
	}
	if err = oauthsvc.ValidateAuthorization(h.issuer, client, q); err != nil {
		return err
	}
	ar, err := p.NewAuthorizeRequest(req.Context(), req)
	if err != nil {
		return errx.Validation("invalid authorization request")
	}
	if !ar.GetRequestedScopes().Has("openid") {
		return errx.Validation("openid scope required")
	}
	ticket, binding, err := h.flows.Start(c.Context(), client, q.Encode())
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-authorization", Value: binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: 300})
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"authorization_ticket": ticket, "client_id": client.ID, "environment_id": client.Environment, "application_id": client.Application, "resource_id": client.Resource, "audience": client.Audience, "scopes": ar.GetRequestedScopes()})
}
func (h *Handler) complete(c *fiber.Ctx) error {
	var input struct {
		Ticket  string `json:"authorization_ticket"`
		Approve bool   `json:"approve"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	var p fosite.OAuth2Provider
	var ar fosite.AuthorizeRequester
	var session *oauthfosite.Session
	err := h.flows.Complete(c.Context(), input.Ticket, c.Cookies("__Host-iamkit-authorization"), input.Approve, func(row oauth.Ticket, tx oauth.Authorization) error {
		var client *oauth.Client
		var err error
		p, client, _, err = h.load(c, row.Client)
		if err != nil {
			return err
		}
		access, err := h.tokens.Validate(c, client.Environment, client.Audience)
		if err != nil {
			return errx.Forbidden("login does not match client")
		}
		if err = oauthsvc.ValidateLogin(access, client); err != nil {
			return err
		}
		req := httptest.NewRequest("GET", "https://iamkit.invalid/oauth/authorize?"+row.Form, nil).WithContext(c.Context())
		ar, err = p.NewAuthorizeRequest(req.Context(), req)
		if err != nil {
			return errx.Validation("invalid authorization request")
		}
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
		ar.GrantAudience(client.Audience)
		expires, authenticated, err := tx.SessionTimes(c.Context(), access.SessionID)
		if err != nil {
			return err
		}
		session = oauthfosite.NewSession()
		session.Subject = access.Subject.String()
		session.Deadline = expires
		session.IDTokenClaims().Subject = access.Subject.String()
		session.IDTokenClaims().AuthTime = authenticated
		session.IDTokenClaims().RequestedAt = row.Requested
		session.IDTokenClaims().Extra = map[string]interface{}{"environment_id": client.Environment.String(), "organization_id": access.OrganizationID.String()}
		session.IDTokenHeaders().Extra = map[string]interface{}{"kid": h.tokens.KeyID()}
		session.AccessHeaders.Extra = map[string]interface{}{"kid": h.tokens.KeyID()}
		session.AccessClaims.Subject = access.Subject.String()
		session.AccessClaims.Issuer = h.issuer
		session.AccessClaims.Audience = []string{client.Audience}
		session.AccessClaims.IssuedAt = time.Now()
		session.AccessClaims.Extra = map[string]interface{}{"purpose": "application", "environment_id": client.Environment.String(), "organization_id": access.OrganizationID.String(), "application_id": client.Application.String(), "resource_id": client.Resource.String(), "permissions": access.Permissions, "sid": access.SessionID.String(), "oauth_client_id": client.ID.String()}
		return nil
	})
	if err != nil {
		return err
	}
	out, err := p.NewAuthorizeResponse(c.Context(), ar, session)
	w := httptest.NewRecorder()
	if err != nil {
		p.WriteAuthorizeError(c.Context(), w, ar, err)
	} else {
		p.WriteAuthorizeResponse(c.Context(), w, ar, out)
	}
	return response(c, w)
}
func tokenClient(req *http.Request) (string, error) {
	if err := req.ParseForm(); err != nil {
		return "", errx.Validation("invalid token request")
	}
	if len(req.URL.Query()) > 0 {
		return "", errx.Validation("query parameters forbidden")
	}
	for _, v := range req.PostForm {
		if len(v) != 1 {
			return "", errx.Validation("duplicate parameter")
		}
	}
	id := req.PostForm.Get("client_id")
	if basic, _, ok := req.BasicAuth(); ok {
		if id != "" && id != basic {
			return "", errx.Validation("client mismatch")
		}
		id = basic
	}
	return id, nil
}
func oauthError(c *fiber.Ctx, code string, status int) error {
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	if code == "invalid_client" {
		c.Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	return c.Status(status).JSON(fiber.Map{"error": code})
}
func clientError(c *fiber.Ctx, err error) error {
	var custom *errx.Error
	if errors.As(err, &custom) && custom != nil && custom.HTTPStatus >= 500 {
		return oauthError(c, "server_error", 500)
	}
	return oauthError(c, "invalid_client", 401)
}
func endpointErrors(next fiber.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := next(c); err != nil {
			return oauthError(c, "server_error", 500)
		}
		return nil
	}
}
func (h *Handler) token(c *fiber.Ctx) error {
	req := request(c)
	rawID, err := tokenClient(req)
	if err != nil {
		return oauthError(c, "invalid_request", 400)
	}
	grant := req.PostForm.Get("grant_type")
	if grant != "authorization_code" && grant != "refresh_token" {
		return oauthError(c, "unsupported_grant_type", 400)
	}
	p, client, store, err := h.loadFromString(c, rawID)
	if err != nil {
		return clientError(c, err)
	}
	ctx := context.WithValue(req.Context(), oauthfosite.ClientContextKey{}, client.ID.String())
	req = req.WithContext(ctx)
	kind, raw := "code", req.PostForm.Get("code")
	if grant == "refresh_token" {
		kind, raw = "refresh", req.PostForm.Get("refresh_token")
	}
	return store.WithTokenLock(ctx, raw, kind, client.ID.String(), func() error {
		w := httptest.NewRecorder()
		ar, err := p.NewAccessRequest(ctx, req, oauthfosite.NewSession())
		if err != nil {
			p.WriteAccessError(ctx, w, ar, err)
			return response(c, w)
		}
		session, ok := ar.GetSession().(*oauthfosite.Session)
		if !ok || session.AccessClaims == nil || oauthsvc.ValidateSession(session.Deadline) != nil {
			p.WriteAccessError(ctx, w, ar, fosite.ErrAccessDenied)
			return response(c, w)
		}
		extra := session.AccessClaims.Extra
		sid, _ := extra["sid"].(string)
		org, _ := extra["organization_id"].(string)
		envStr, _ := extra["environment_id"].(string)
		appStr, _ := extra["application_id"].(string)
		resStr, _ := extra["resource_id"].(string)
		if envStr != client.Environment.String() || appStr != client.Application.String() || resStr != client.Resource.String() {
			p.WriteAccessError(ctx, w, ar, fosite.ErrAccessDenied)
			return response(c, w)
		}
		subjectID, _ := identity.ParseUserID(session.Subject)
		sessionID, _ := identity.ParseSessionID(sid)
		orgID, _ := identity.ParseOrganizationID(org)
		access, err := h.flows.Access(ctx, client, subjectID, sessionID, orgID)
		if err != nil {
			p.WriteAccessError(ctx, w, ar, fosite.ErrAccessDenied)
			return response(c, w)
		}
		extra["permissions"] = []string(access.Permissions)
		session.AccessClaims.IssuedAt = time.Now()
		session.AccessClaims.JTI = ""
		session.SetExpiresAt(fosite.RefreshToken, session.Deadline)
		out, err := p.NewAccessResponse(ctx, ar)
		if err != nil {
			p.WriteAccessError(ctx, w, ar, err)
		} else {
			p.WriteAccessResponse(ctx, w, ar, out)
		}
		return response(c, w)
	})
}
func (h *Handler) revoke(c *fiber.Ctx) error {
	req := request(c)
	rawID, err := tokenClient(req)
	if err != nil {
		return oauthError(c, "invalid_request", 400)
	}
	p, client, store, err := h.loadFromString(c, rawID)
	if err != nil {
		return clientError(c, err)
	}
	ctx := context.WithValue(req.Context(), oauthfosite.ClientContextKey{}, client.ID.String())
	req = req.WithContext(ctx)
	raw := req.PostForm.Get("token")
	kind := "refresh"
	if strings.Count(raw, ".") == 2 {
		kind = "access"
	}
	return store.WithTokenLock(ctx, raw, kind, client.ID.String(), func() error {
		err := p.NewRevocationRequest(ctx, req)
		w := httptest.NewRecorder()
		p.WriteRevocationResponse(ctx, w, err)
		return response(c, w)
	})
}
