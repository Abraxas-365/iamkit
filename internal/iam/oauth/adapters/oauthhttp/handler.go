package oauthhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/oauthsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/ory/fosite"
)

type Provider func(*oauth.Client) (fosite.OAuth2Provider, *oauthfosite.Store, error)

// AccountAuthenticator authenticates a service account at the token
// endpoint (client_credentials): its secret or a private_key_jwt assertion.
type AccountAuthenticator interface {
	Authenticate(ctx context.Context, account identity.AccountID, r *http.Request) (identity.AccountID, error)
}
type Handler struct {
	commands oauth.Commands
	queries  oauth.Queries
	flows    oauth.Flows
	provider Provider
	tokens   *authhttp.Tokens
	issuer   string
	actor    func(*fiber.Ctx) string
	// signedOut renders the end_session result page (hosted module);
	// problem is nil after a successful logout.
	signedOut func(c *fiber.Ctx, environment identity.EnvironmentID, problem error) error
	accounts  AccountAuthenticator
	devices   oauth.Devices
	exchanges oauth.Exchanges
	// deviceDone renders the page shown once a device is approved (hosted
	// module).
	deviceDone func(c *fiber.Ctx, environment identity.EnvironmentID) error
	claims     oauth.ProfileClaims
	actions    oauth.Actions
	usage      oauth.Usage
}

// Usage counts the access tokens fosite issues.
func (h *Handler) Usage(u oauth.Usage) { h.usage = u }

// issued counts one access token of client's environment.
func (h *Handler) issued(ctx context.Context, client *oauth.Client) {
	if h.usage != nil {
		h.usage.Count(ctx, client.Environment, usage.MetricTokens, 1)
	}
}

// ProfileClaims releases the user's profile and phone claims.
func (h *Handler) ProfileClaims(claims oauth.ProfileClaims) { h.claims = claims }

// customClaims are the user's claims when scopes grant profile or phone;
// a failure leaves them out rather than failing the sign-in.
func (h *Handler) customClaims(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, scopes []string) map[string]json.RawMessage {
	if h.claims == nil || (!slices.Contains(scopes, "profile") && !slices.Contains(scopes, "phone")) {
		return nil
	}
	claims, err := h.claims.Claims(ctx, environment, user, scopes)
	if err != nil {
		return nil
	}
	return claims
}

// addClaims puts custom claims into an ID token session.
func addClaims(session *oauthfosite.Session, claims map[string]json.RawMessage) {
	for name, value := range claims {
		var v any
		if json.Unmarshal(value, &v) == nil {
			session.IDTokenClaims().Extra[name] = v
		}
	}
}

// Accounts enables grant_type=client_credentials for service accounts.
func (h *Handler) Accounts(accounts AccountAuthenticator) { h.accounts = accounts }

// SignedOut sets the page /oauth/end_session shows when it does not
// redirect (wired to the hosted pages in bootstrap).
func (h *Handler) SignedOut(page func(c *fiber.Ctx, environment identity.EnvironmentID, problem error) error) {
	h.signedOut = page
}

func New(commands oauth.Commands, queries oauth.Queries, flows oauth.Flows, provider Provider, tokens *authhttp.Tokens, issuer string, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, flows: flows, provider: provider, tokens: tokens, issuer: issuer, actor: actor}
}
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) RegisterManagement(r fiber.Router) {
	r.Post("/oauth-clients", h.create)
	r.Get("/oauth-clients", h.list)
	r.Get("/oauth-clients/:id", h.find)
	r.Patch("/oauth-clients/:id", h.update)
	r.Delete("/oauth-clients/:id", h.disable)
}
func (h *Handler) update(c *fiber.Ctx) error {
	clientID, err := identity.ParseClientID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid client id")
	}
	var input oauth.ClientUpdate
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	m := oauth.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err = h.commands.Update(c.UserContext(), m, clientID, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input oauth.Registration
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, secret, err := h.commands.Create(c.UserContext(), env(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id, "client_id": id, "client_secret": secret, "warnings": oauth.Warnings(input.Redirects, input.PostLogoutRedirects)})
}
func (h *Handler) disable(c *fiber.Ctx) error {
	clientID, err := identity.ParseClientID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid client id")
	}
	m := oauth.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.Disable(c.UserContext(), m, clientID); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) find(c *fiber.Ctx) error {
	clientID, err := identity.ParseClientID(c.Params("id"))
	if err != nil {
		return errx.NotFound("OAuth client not found")
	}
	out, err := h.queries.Find(c.UserContext(), env(c), clientID)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) list(c *fiber.Ctx) error {
	var filter oauth.ClientFilter
	if raw := c.Query("application_id"); raw != "" {
		application, err := identity.ParseApplicationID(raw)
		if err != nil {
			return errx.Validation("invalid application_id")
		}
		filter.Application = application
	}
	out, err := h.queries.List(c.UserContext(), env(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) load(c *fiber.Ctx, id identity.ClientID) (fosite.OAuth2Provider, *oauth.Client, *oauthfosite.Store, error) {
	client, err := h.flows.Client(c.UserContext(), id)
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
	return req.WithContext(c.UserContext())
}
func response(c *fiber.Ctx, w *httptest.ResponseRecorder) error {
	// Set, not Append: fiber presets Content-Type, and a doubled value
	// makes relying-party libraries misread the JSON body.
	for k, values := range w.Header() {
		for i, v := range values {
			if i == 0 {
				c.Set(k, v)
			} else {
				c.Append(k, v)
			}
		}
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(w.Code).Send(w.Body.Bytes())
}
func (h *Handler) Register(app *fiber.App) {
	app.Get("/.well-known/openid-configuration", func(c *fiber.Ctx) error {
		return c.JSON(oauth.NewDiscovery(h.issuer))
	})
	app.Get("/oauth/authorize", h.authorize)
	app.Post("/oauth/authorize/complete", h.complete)
	app.Post("/oauth/token", endpointErrors, h.token)
	if h.devices != nil {
		app.Post("/oauth/device_authorization", endpointErrors, h.deviceAuthorization)
	}
	app.Post("/oauth/revoke", endpointErrors, h.revoke)
	app.Post("/oauth/introspect", endpointErrors, h.introspect)
	app.Get("/oauth/userinfo", h.userinfo)
	app.Post("/oauth/userinfo", h.userinfo)
	app.Get("/oauth/end_session", h.endSession)
	app.Post("/oauth/end_session", h.endSession)
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
		return authorizeError(err)
	}
	if !ar.GetRequestedScopes().Has("openid") {
		return errx.Validation("openid scope required")
	}
	ticket, binding, err := h.flows.Start(c.UserContext(), client, q.Encode())
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-authorization", Value: binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: int(config.OAuthAuthorizationTicketTTL.Seconds())})
	c.Set("Cache-Control", "no-store")
	if client.HostedLogin {
		return c.Redirect("/hosted/login?"+url.Values{"ticket": {ticket}}.Encode(), fiber.StatusSeeOther)
	}
	return c.JSON(fiber.Map{"authorization_ticket": ticket, "client_id": client.ID, "environment_id": client.Environment, "application_id": client.Application, "resource_id": client.Resource, "audience": client.Audience, "scopes": ar.GetRequestedScopes()})
}

// authorizeError names what fosite refused in an authorization request (its
// hint: a too short state, a scope the client may not request…), so the
// caller is not left with a bare "invalid authorization request".
func authorizeError(err error) error {
	if hint := fosite.ErrorToRFC6749Error(err).HintField; hint != "" {
		return errx.Validation("invalid authorization request: " + hint)
	}
	return errx.Validation("invalid authorization request")
}

func (h *Handler) complete(c *fiber.Ctx) error {
	var input struct {
		Ticket  string `json:"authorization_ticket"`
		Approve bool   `json:"approve"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	err := h.finish(c, input.Ticket, input.Approve, func(client *oauth.Client) (oauth.Login, error) {
		access, err := h.tokens.Validate(c, client.Environment, client.Audience)
		if err != nil {
			return oauth.Login{}, errx.Forbidden("login does not match client")
		}
		if err = oauthsvc.ValidateLogin(access, client); err != nil {
			return oauth.Login{}, err
		}
		return oauth.Login{User: access.Subject, Organization: access.OrganizationID, Session: access.SessionID, Permissions: access.Permissions}, nil
	})
	if err != nil || !wantsJSON(c) {
		return err
	}
	// A cross-origin fetch cannot read a redirect: hand it the target to
	// navigate to instead (the code or error response for the client).
	location := c.GetRespHeader(fiber.HeaderLocation)
	if c.Response().StatusCode() != fiber.StatusSeeOther || location == "" {
		return nil
	}
	c.Response().Header.Del(fiber.HeaderLocation)
	c.Response().ResetBody()
	return c.Status(fiber.StatusOK).JSON(Completion{RedirectTo: location})
}

// Completion is the JSON answer of /oauth/authorize/complete to a client
// that asked for it (Accept: application/json): where to send the browser.
type Completion struct {
	RedirectTo string `json:"redirect_to"`
}

// wantsJSON reports whether the request accepts JSON but not HTML: a
// script, not a form submission.
func wantsJSON(c *fiber.Ctx) bool {
	accept := c.Get(fiber.HeaderAccept)
	return strings.Contains(accept, fiber.MIMEApplicationJSON) && !strings.Contains(accept, fiber.MIMETextHTML)
}

// Finish completes a hosted authorization with a session the hosted login
// pages issued for the ticket's client, and redirects to the client.
func (h *Handler) Finish(c *fiber.Ctx, ticket string, login oauth.Login) error {
	return h.finish(c, ticket, true, func(*oauth.Client) (oauth.Login, error) { return login, nil })
}

// finish consumes the ticket and answers the original authorize request
// with a code for the login's session.
func (h *Handler) finish(c *fiber.Ctx, ticket string, approve bool, login func(*oauth.Client) (oauth.Login, error)) error {
	var p fosite.OAuth2Provider
	var ar fosite.AuthorizeRequester
	var session *oauthfosite.Session
	var device *oauth.Client
	err := h.flows.Complete(c.UserContext(), ticket, c.Cookies("__Host-iamkit-authorization"), approve, func(row oauth.Ticket, tx oauth.Authorization) error {
		var client *oauth.Client
		var err error
		p, client, _, err = h.load(c, row.Client)
		if err != nil {
			return err
		}
		access, err := login(client)
		if err != nil {
			return err
		}
		// An authorization that named its organization completes only there.
		if hint := oauth.FormOrganization(row.Form); !hint.IsZero() && access.Organization != hint {
			return oauth.ErrOrganizationHint()
		}
		if row.Device != nil {
			// A device ticket approves the device authorization; the device
			// collects its tokens at the token endpoint.
			if _, err = tx.Session(c.UserContext(), access.Session); err != nil {
				return err
			}
			if err = tx.Bind(c.UserContext(), access.Session, client.ID); err != nil {
				return err
			}
			device = client
			return tx.ApproveDevice(c.UserContext(), client.Environment, row.Device, access)
		}
		req := httptest.NewRequest("GET", "https://iamkit.invalid/oauth/authorize?"+row.Form, nil).WithContext(c.UserContext())
		ar, err = p.NewAuthorizeRequest(req.Context(), req)
		if err != nil {
			return errx.Validation("invalid authorization request")
		}
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
		ar.GrantAudience(client.Audience)
		info, err := tx.Session(c.UserContext(), access.Session)
		if err != nil {
			return err
		}
		if err = tx.Bind(c.UserContext(), access.Session, client.ID); err != nil {
			return err
		}
		session = h.session(client, access, info, row.Requested)
		addClaims(session, h.customClaims(c.UserContext(), client.Environment, access.User, ar.GetGrantedScopes()))
		return h.tokenHooks(c.UserContext(), client, session, access.User, access.Organization, info.AMR, ar.GetGrantedScopes())
	})
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-authorization", Value: "", Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: -1})
	if device != nil {
		return h.deviceApproved(c, device)
	}
	out, err := p.NewAuthorizeResponse(c.UserContext(), ar, session)
	w := httptest.NewRecorder()
	if err != nil {
		p.WriteAuthorizeError(c.UserContext(), w, ar, err)
	} else {
		p.WriteAuthorizeResponse(c.UserContext(), w, ar, out)
	}
	return response(c, w)
}

// session is the token session of a login for client: the ID token and
// access token claims every OAuth grant of a user issues.
func (h *Handler) session(client *oauth.Client, access oauth.Login, info oauth.SessionInfo, requested time.Time) *oauthfosite.Session {
	session := oauthfosite.NewSession()
	session.Subject = access.User.String()
	session.Deadline = info.Expires
	session.IDTokenClaims().Subject = access.User.String()
	session.IDTokenClaims().AuthTime = info.Authenticated
	session.IDTokenClaims().AuthenticationMethodsReferences = info.AMR
	session.IDTokenClaims().RequestedAt = requested
	session.IDTokenClaims().Extra = map[string]interface{}{"environment_id": client.Environment.String(), "organization_id": access.Organization.String(), "sid": access.Session.String()}
	// oauthfosite.Signer writes the kid of the environment's signing key.
	session.AccessClaims.Subject = access.User.String()
	session.AccessClaims.Issuer = h.issuer
	session.AccessClaims.Audience = []string{client.Audience}
	session.AccessClaims.IssuedAt = time.Now()
	session.AccessClaims.Extra = map[string]interface{}{"purpose": "application", "environment_id": client.Environment.String(), "organization_id": access.Organization.String(), "application_id": client.Application.String(), "resource_id": client.Resource.String(), "permissions": access.Permissions, "sid": access.Session.String(), "oauth_client_id": client.ID.String(), "auth_time": info.Authenticated.Unix()}
	if len(info.AMR) > 0 {
		session.AccessClaims.Extra["amr"] = info.AMR
	}
	return session
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
	if id == "" && req.PostForm.Get("client_assertion") != "" {
		// private_key_jwt without client_id: the assertion's sub names the
		// client; fosite then verifies the assertion with that client's keys.
		id = oauthfosite.AssertionSubject(req.PostForm.Get("client_assertion"))
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

// endpointErrors answers any error of the OAuth endpoint after it with an
// OAuth server_error.
func endpointErrors(c *fiber.Ctx) error {
	if err := c.Next(); err != nil {
		return oauthError(c, "server_error", 500)
	}
	return nil
}
func (h *Handler) token(c *fiber.Ctx) error {
	req := request(c)
	rawID, err := tokenClient(req)
	if err != nil {
		return oauthError(c, "invalid_request", 400)
	}
	grant := req.PostForm.Get("grant_type")
	if grant == "client_credentials" && h.accounts != nil {
		return h.clientCredentials(c, req, rawID)
	}
	if grant == oauth.GrantDeviceCode && h.devices != nil {
		return h.deviceToken(c, req, rawID)
	}
	if grant == oauth.GrantTokenExchange && h.exchanges != nil {
		return h.exchangeToken(c, req, rawID)
	}
	if grant == oauth.GrantJWTBearer && h.tokens != nil {
		return h.keyGrant(c, req)
	}
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
		// The code exchange issues what finish decided; a refresh asks
		// pre_access_token again.
		if grant == "refresh_token" {
			if err = h.accessHook(ctx, client, session, func() action.Input {
				return tokenInput(client, subjectID, orgID, stringList(extra["amr"]), ar.GetGrantedScopes())
			}); err != nil {
				p.WriteAccessError(ctx, w, ar, hookError(err))
				return response(c, w)
			}
		}
		session.AccessClaims.IssuedAt = time.Now()
		session.AccessClaims.JTI = ""
		session.SetExpiresAt(fosite.RefreshToken, session.Deadline)
		out, err := p.NewAccessResponse(ctx, ar)
		if err != nil {
			p.WriteAccessError(ctx, w, ar, err)
		} else {
			p.WriteAccessResponse(ctx, w, ar, out)
			h.issued(ctx, client)
		}
		return response(c, w)
	})
}

// clientCredentials is grant_type=client_credentials for service accounts
// (client_id = account id). The token is the machine token
// /identity/v1/machine-token issues: same claims, audience and lifetime.
func (h *Handler) clientCredentials(c *fiber.Ctx, req *http.Request, rawID string) error {
	id, err := identity.ParseAccountID(rawID)
	if err != nil {
		return oauthError(c, "invalid_client", 401)
	}
	account, err := h.accounts.Authenticate(req.Context(), id, req)
	if err != nil {
		return clientError(c, err)
	}
	raw, err := h.tokens.IssueMachine(c, account)
	if err != nil {
		return clientError(c, err)
	}
	c.Set("Pragma", "no-cache")
	return c.JSON(raw)
}

// keyGrant is the RFC 7523 JWT-bearer grant of machine users: the
// assertion, signed with one of the user's keys, is the whole credential
// (no client authentication); organization_id, application_id and
// resource_id pick the session's boundary, environment_id is optional
// (the key's). Failures are invalid_grant.
func (h *Handler) keyGrant(c *fiber.Ctx, req *http.Request) error {
	form := req.PostForm
	assertion := form.Get("assertion")
	if assertion == "" || form.Get("client_assertion") != "" {
		return oauthError(c, "invalid_request", 400)
	}
	var boundary authentication.Context
	var err error
	if raw := form.Get("environment_id"); raw != "" {
		if boundary.EnvironmentID, err = identity.ParseEnvironmentID(raw); err != nil {
			return oauthError(c, "invalid_request", 400)
		}
	}
	org, err1 := identity.ParseOrganizationID(form.Get("organization_id"))
	app, err2 := identity.ParseApplicationID(form.Get("application_id"))
	res, err3 := identity.ParseResourceID(form.Get("resource_id"))
	if err1 != nil || err2 != nil || err3 != nil {
		return oauthError(c, "invalid_request", 400)
	}
	boundary.OrganizationID, boundary.ApplicationID, boundary.ResourceID = org, app, res
	out, err := h.tokens.KeyGrant(c, assertion, boundary)
	if err != nil {
		var custom *errx.Error
		if errors.As(err, &custom) && custom != nil && custom.HTTPStatus >= 500 {
			return oauthError(c, "server_error", 500)
		}
		return oauthError(c, "invalid_grant", 400)
	}
	c.Set("Pragma", "no-cache")
	return c.JSON(out)
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

// introspect is RFC 7662 token introspection for confidential clients of
// the token's environment. Tokens of another client in the same
// environment are answered; tokens of another environment are inactive
// (the client's store only reads its own environment).
func (h *Handler) introspect(c *fiber.Ctx) error {
	req := request(c)
	if err := req.ParseForm(); err != nil || len(req.URL.Query()) > 0 {
		return oauthError(c, "invalid_request", 400)
	}
	for _, v := range req.PostForm {
		if len(v) != 1 {
			return oauthError(c, "invalid_request", 400)
		}
	}
	rawID, _, ok := req.BasicAuth()
	if !ok {
		return oauthError(c, "invalid_client", 401)
	}
	p, client, _, err := h.loadFromString(c, rawID)
	if err != nil {
		return clientError(c, err)
	}
	if client.Public {
		return oauthError(c, "invalid_client", 401)
	}
	w := httptest.NewRecorder()
	ir, err := p.NewIntrospectionRequest(req.Context(), req, oauthfosite.NewSession())
	if err != nil {
		if errors.Is(err, fosite.ErrRequestUnauthorized) && !errors.Is(err, fosite.ErrInactiveToken) {
			return oauthError(c, "invalid_client", 401)
		}
		p.WriteIntrospectionError(req.Context(), w, err)
		return response(c, w)
	}
	if !h.liveIntrospection(c, client, ir) {
		p.WriteIntrospectionError(req.Context(), w, fosite.ErrInactiveToken)
		return response(c, w)
	}
	p.WriteIntrospectionResponse(req.Context(), w, ir)
	return response(c, w)
}

// liveIntrospection re-checks what fosite's stored grant cannot know: the
// user's session is still live and the token's client is still enabled.
func (h *Handler) liveIntrospection(c *fiber.Ctx, caller *oauth.Client, ir fosite.IntrospectionResponder) bool {
	ar := ir.GetAccessRequester()
	session, ok := ar.GetSession().(*oauthfosite.Session)
	if !ok || session.AccessClaims == nil {
		return false
	}
	if oauthsvc.ValidateSession(session.Deadline) != nil {
		return false
	}
	owner, err := identity.ParseClientID(ar.GetClient().GetID())
	if err != nil {
		return false
	}
	client, err := h.flows.Client(c.UserContext(), owner)
	if err != nil || client.Environment != caller.Environment {
		return false
	}
	extra := session.AccessClaims.Extra
	sid, _ := extra["sid"].(string)
	org, _ := extra["organization_id"].(string)
	subject, _ := identity.ParseUserID(session.Subject)
	sessionID, _ := identity.ParseSessionID(sid)
	orgID, _ := identity.ParseOrganizationID(org)
	access, err := h.flows.Access(c.UserContext(), client, subject, sessionID, orgID)
	if err != nil {
		return false
	}
	extra["permissions"] = []string(access.Permissions)
	extra["token_use"] = string(ir.GetTokenUse())
	if ir.GetTokenUse() == fosite.AccessToken {
		extra["token_type"] = "Bearer"
	}
	return true
}

// userinfo is the OpenID Connect UserInfo endpoint: a live OAuth access
// token as Bearer (header, or access_token form field on POST).
func (h *Handler) userinfo(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodPost && c.Get(fiber.HeaderAuthorization) == "" {
		if raw := c.FormValue("access_token"); raw != "" {
			c.Request().Header.Set(fiber.HeaderAuthorization, "Bearer "+raw)
		}
	}
	c.Set("Cache-Control", "no-store")
	var token authentication.Token
	var profile authentication.Profile
	var err error
	if key := oauthfosite.OpaqueKey(bearerToken(c)); key != "" {
		token, err = h.opaqueToken(c, key, bearerToken(c))
		if err == nil {
			profile, err = h.tokens.ProfileOf(c, token)
		}
	} else {
		token, profile, err = h.tokens.Self(c)
	}
	if err != nil || token.OAuthClientID.IsZero() || !slices.Contains(token.Scopes, "openid") {
		c.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		return c.Status(401).JSON(fiber.Map{"error": "invalid_token"})
	}
	out := oauth.UserInfo{Subject: token.Subject.String(), Environment: token.EnvironmentID.String(), Organization: token.OrganizationID.String()}
	if slices.Contains(token.Scopes, "profile") {
		out.Name = profile.Name
	}
	if slices.Contains(token.Scopes, "email") {
		verified := profile.EmailVerified
		out.Email, out.EmailVerified = profile.Email, &verified
	}
	custom := h.customClaims(c.UserContext(), token.EnvironmentID, token.Subject, token.Scopes)
	if hooked, err := h.userInfoHook(c.UserContext(), token); err != nil {
		return err
	} else if len(hooked) > 0 {
		if custom == nil {
			custom = map[string]json.RawMessage{}
		}
		for name, value := range hooked {
			if _, taken := custom[name]; !taken && !slices.Contains(userInfoClaims, name) {
				custom[name] = value
			}
		}
	}
	if len(custom) > 0 {
		body, err := json.Marshal(out)
		if err != nil {
			return err
		}
		merged := map[string]json.RawMessage{}
		_ = json.Unmarshal(body, &merged)
		for name, value := range custom {
			merged[name] = value
		}
		return c.JSON(merged)
	}
	return c.JSON(out)
}

func bearerToken(c *fiber.Ctx) string {
	parts := strings.Fields(c.Get(fiber.HeaderAuthorization))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// opaqueToken resolves an opaque access token (ory_at_…) through the
// stored grant of the client it was issued to, re-checking the user's
// session and current permissions like introspection does.
func (h *Handler) opaqueToken(c *fiber.Ctx, key, raw string) (authentication.Token, error) {
	invalid := errx.Unauthorized("invalid OAuth token")
	client, err := h.flows.AccessTokenClient(c.UserContext(), key)
	if err != nil {
		return authentication.Token{}, invalid
	}
	p, _, err := h.provider(client)
	if err != nil {
		return authentication.Token{}, invalid
	}
	use, ar, err := p.IntrospectToken(c.UserContext(), raw, fosite.AccessToken, oauthfosite.NewSession())
	if err != nil || use != fosite.AccessToken {
		return authentication.Token{}, invalid
	}
	session, ok := ar.GetSession().(*oauthfosite.Session)
	if !ok || session.AccessClaims == nil || oauthsvc.ValidateSession(session.Deadline) != nil || ar.GetClient().GetID() != client.ID.String() {
		return authentication.Token{}, invalid
	}
	extra := session.AccessClaims.Extra
	sid, _ := extra["sid"].(string)
	org, _ := extra["organization_id"].(string)
	subject, _ := identity.ParseUserID(session.Subject)
	sessionID, _ := identity.ParseSessionID(sid)
	orgID, _ := identity.ParseOrganizationID(org)
	access, err := h.flows.Access(c.UserContext(), client, subject, sessionID, orgID)
	if err != nil {
		return authentication.Token{}, invalid
	}
	out := authentication.Token{Access: identity.Access{EnvironmentID: client.Environment, OrganizationID: orgID, ApplicationID: client.Application, ResourceID: client.Resource, Permissions: access.Permissions}, Purpose: "application", SessionID: sessionID, OAuthClientID: client.ID, Subject: subject, Scopes: ar.GetGrantedScopes(), Issuer: h.issuer, Audience: []string{client.Audience}}
	return out, nil
}

// endSession is OpenID Connect RP-Initiated Logout 1.0.
func (h *Handler) endSession(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	input := oauth.Logout{Hint: c.FormValue("id_token_hint"), Redirect: c.FormValue("post_logout_redirect_uri"), State: c.FormValue("state")}
	if c.Method() == fiber.MethodGet {
		input = oauth.Logout{Hint: c.Query("id_token_hint"), Redirect: c.Query("post_logout_redirect_uri"), State: c.Query("state")}
	}
	raw := c.Query("client_id")
	if c.Method() == fiber.MethodPost {
		raw = c.FormValue("client_id")
	}
	if raw != "" {
		id, err := identity.ParseClientID(raw)
		if err != nil {
			return h.signedOutPage(c, identity.EnvironmentID{}, errx.Validation("unknown client_id"))
		}
		input.Client = id
	}
	back, environment, err := h.flows.Logout(c.UserContext(), input)
	if err != nil {
		return h.signedOutPage(c, environment, err)
	}
	if back != "" {
		return c.Redirect(back, fiber.StatusFound)
	}
	return h.signedOutPage(c, environment, nil)
}

func (h *Handler) signedOutPage(c *fiber.Ctx, environment identity.EnvironmentID, problem error) error {
	if h.signedOut != nil {
		return h.signedOut(c, environment, problem)
	}
	if problem != nil {
		return problem
	}
	return c.SendStatus(fiber.StatusNoContent)
}
