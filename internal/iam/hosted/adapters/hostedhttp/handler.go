// Package hostedhttp serves the hosted sign-in pages as server-rendered HTML
// (no JavaScript) and the management API for their branding.
package hostedhttp

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"html/template"
	"log/slog"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"rsc.io/qr"
)

//go:embed templates/*.html
var files embed.FS

var pages = func() map[string]*template.Template {
	out := map[string]*template.Template{}
	for _, name := range []string{"identify", "password", "code", "reset", "organization", "mfa", "enroll", "recovery", "invite", "message"} {
		t := template.Must(template.ParseFS(files, "templates/*.html"))
		template.Must(t.New("content").Parse(`{{template "` + name + `/content" .}}`))
		out[name] = t
	}
	return out
}()

// Finisher completes the OAuth authorization with a hosted session and
// redirects the browser to the client.
type Finisher func(c *fiber.Ctx, ticket string, login oauth.Login) error

const (
	authorizationCookie = "__Host-iamkit-authorization"
	federationCookie    = "__Host-iamkit-federation"
	defaultAccent       = "#2563eb"
)

type Handler struct {
	flow        hosted.Flow
	commands    hosted.Commands
	queries     hosted.Queries
	invitations hosted.Invitations
	finish      Finisher
	actor       func(*fiber.Ctx) string
}

func New(flow hosted.Flow, commands hosted.Commands, queries hosted.Queries, invitations hosted.Invitations, finish Finisher, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{flow: flow, commands: commands, queries: queries, invitations: invitations, finish: finish, actor: actor}
}

// RegisterManagement serves the branding under /environments/:environment:
// the environment default, per-client styles, and previews.
func (h *Handler) RegisterManagement(e fiber.Router) {
	e.Get("/login-settings", h.settings)
	e.Put("/login-settings", h.saveSettings)
	e.Get("/login-settings/clients", h.clientStyles)
	e.Get("/login-settings/clients/:client", h.clientStyle)
	e.Put("/login-settings/clients/:client", h.saveClientStyle)
	e.Delete("/login-settings/clients/:client", h.deleteClientStyle)
	e.Get("/login-settings/sign-in", h.signIns)
	e.Get("/login-settings/clients/:client/sign-in", h.signIn)
	e.Put("/login-settings/clients/:client/sign-in", h.saveSignIn)
	e.Delete("/login-settings/clients/:client/sign-in", h.deleteSignIn)
	e.Get("/login-settings/preview", h.savedPreview)
	// A draft preview changes nothing; POST only carries the draft body.
	e.Post("/login-settings/preview", h.draftPreview)
	e.Get("/login-settings/locales", locales)
}

// locales lists the languages emails can be written in.
func locales(c *fiber.Ctx) error { return c.JSON(fiber.Map{"items": i18n.Locales()}) }

// Pages are the hosted page handlers; the server mounts them with its rate
// limits and security headers.
func (h *Handler) Pages() map[string]fiber.Handler {
	return map[string]fiber.Handler{
		"GET /hosted/login":               h.login,
		"POST /hosted/login/identify":     h.identify,
		"POST /hosted/login/password":     h.password,
		"POST /hosted/login/code":         h.sendCode,
		"POST /hosted/login/code/verify":  h.verifyCode,
		"POST /hosted/login/reset":        h.sendReset,
		"POST /hosted/login/reset/verify": h.reset,
		"POST /hosted/login/sso":          h.sso,
		"POST /hosted/login/organization": h.organization,
		"POST /hosted/login/mfa":          h.secondFactor,
		"POST /hosted/login/mfa/continue": h.continueLogin,
		"GET /hosted/invite":              h.invite,
		"POST /hosted/invite":             h.accept,
	}
}

// view is the data every page renders with.
type view struct {
	// Lang is the page language (an i18n code); T translates into it.
	Lang                                  string
	Nonce, Title, Subtitle, Error, Notice string
	Brand                                 brand
	Ticket, Email                         string
	Connection                            *identity.ConnectionID
	Connections                           []federation.ConnectionSummary
	// SignIn is which methods the client offers; zero on pages that do
	// not depend on it.
	SignIn        hosted.SignIn
	Challenge     identity.ChallengeID
	Organizations []authentication.Organization
	Token         string
	Invite        *invitation.Preview
	// Second-factor pages: the authenticator to add (QR as a PNG data URI)
	// and recovery codes shown once.
	Secret        string
	QR            template.URL
	RecoveryCodes []string
}

// T is the page text for key in the page language.
func (v view) T(key string, args ...any) string { return i18n.T(v.Lang, key, args...) }

// language is the page language: preferred (the application's ui_locales
// or the environment language) when set, else the browser's.
func language(c *fiber.Ctx, preferred string) string {
	if preferred != "" {
		return preferred
	}
	return i18n.Resolve(c.Get(fiber.HeaderAcceptLanguage))
}

// render writes the page with a per-response nonce for its inline style.
func render(c *fiber.Ctx, status int, page string, v view) error {
	out, err := document(page, &v)
	if err != nil {
		return err
	}
	// data: images are the server-rendered enrollment QR code.
	c.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+v.Nonce+"'; img-src https: data:; base-uri 'none'; frame-ancestors 'none'")
	c.Set("Cache-Control", "no-store")
	c.Set("Content-Type", fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(status).Send(out)
}

// document renders a page with a fresh nonce (stored in v).
func document(page string, v *view) ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errx.Wrap(err, "generate nonce", errx.TypeInternal)
	}
	v.Nonce = base64.StdEncoding.EncodeToString(nonce)
	if v.Lang == "" {
		v.Lang = i18n.Default
	}
	if v.Brand.Vars == "" {
		v.Brand = brandOf(hosted.Settings{}, "")
	}
	var out bytes.Buffer
	if err := pages[page].ExecuteTemplate(&out, "layout", v); err != nil {
		return nil, errx.Wrap(err, "render hosted page", errx.TypeInternal)
	}
	return out.Bytes(), nil
}

// message renders an error or information page.
func message(c *fiber.Ctx, lang string, status int, title, text string) error {
	return render(c, status, "message", view{Lang: lang, Title: title, Error: text})
}

// problemCodes and problemMessages translate the errors people can fix
// themselves; other client errors keep their message.
var (
	problemCodes = map[string]string{
		"LOGIN_EXPIRED":              "hosted.error.login_expired",
		"SIGN_IN_METHOD_UNAVAILABLE": "hosted.error.method_unavailable",
		"INVALID_CODE":               "hosted.error.mfa_code",
		"MFA_LOCKED":                 "hosted.error.too_many",
		"TOO_MANY_REQUESTS":          "hosted.error.too_many",
		"ACCOUNT_EXISTS":             "hosted.error.account_exists",
	}
	problemMessages = map[string]string{
		"invalid credentials or access token": "hosted.error.credentials",
		"invalid challenge":                   "hosted.error.code",
		"your organization requires single sign-on, which this application does not offer": "hosted.error.sso_not_offered",
		"this email cannot sign in to this application with single sign-on":                "hosted.error.sso_email",
		"your account does not have access to this application":                            "hosted.error.no_access",
		"password must be 12-72 characters long":                                           "hosted.error.password_length",
		"12-72 byte password required":                                                     "hosted.error.password_length",
		"password is required":                                                             "hosted.error.password_required",
		"email must be a valid address":                                                    "hosted.error.email",
		"provider did not supply a valid email":                                            "hosted.error.provider_email",
		"provider email is not verified":                                                   "hosted.error.provider_email",
		"invalid or expired invitation":                                                    "hosted.invitation.invalid",
	}
)

// failed renders a page for an error in lang: client errors show their
// message, an unreachable identity provider gets its own explanation, and
// anything else is logged and shown generically.
func failed(c *fiber.Ctx, lang string, err error) (int, string) {
	var e *errx.Error
	if errx.As(err, &e) && e.HTTPStatus >= 400 && e.HTTPStatus < 500 {
		if key, ok := problemCodes[e.Code]; ok {
			return e.HTTPStatus, i18n.T(lang, key)
		}
		if key, ok := problemMessages[e.Message]; ok {
			return e.HTTPStatus, i18n.T(lang, key)
		}
		return e.HTTPStatus, e.Message
	}
	if e != nil && e.Code == "PROVIDER_UNAVAILABLE" {
		slog.Warn("hosted login: identity provider unavailable", "path", c.Path(), "err", err)
		return fiber.StatusBadGateway, i18n.T(lang, "hosted.error.provider_unavailable")
	}
	slog.Error("hosted login", "path", c.Path(), "err", err)
	return fiber.StatusInternalServerError, i18n.T(lang, "hosted.error.generic")
}

func (h *Handler) request(c *fiber.Ctx) hosted.Request {
	ticket := c.FormValue("ticket")
	if ticket == "" {
		ticket = c.Query("ticket")
	}
	return hosted.Request{Ticket: ticket, Binding: c.Cookies(authorizationCookie)}
}

// base loads the pending authorization's branding for a page; a dead
// authorization ends the journey with an error page.
func (h *Handler) base(c *fiber.Ctx, r hosted.Request) (view, bool, error) {
	page, err := h.flow.Page(c.Context(), r)
	if err != nil {
		lang := language(c, "")
		status, text := failed(c, lang, err)
		if status == fiber.StatusUnauthorized {
			text = i18n.T(lang, "hosted.expired")
		}
		return view{}, false, message(c, lang, status, i18n.T(lang, "hosted.title.expired"), text)
	}
	return view{Lang: language(c, page.Language), Brand: brandOf(page.Settings, ""), Ticket: r.Ticket, Connections: page.Connections, SignIn: page.SignIn}, true, nil
}

func (h *Handler) login(c *fiber.Ctx) error {
	v, ok, err := h.base(c, h.request(c))
	if !ok {
		return err
	}
	v.Title = v.T("hosted.title.sign_in")
	return render(c, fiber.StatusOK, "identify", v)
}

func (h *Handler) identify(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.sign_in"), c.FormValue("email")
	route, err := h.flow.Identify(c.Context(), r, v.Email)
	if err != nil {
		status, text := failed(c, v.Lang, err)
		v.Error = text
		return render(c, status, "identify", v)
	}
	if route.Redirect != "" {
		return h.federate(c, route.Redirect, route.Binding)
	}
	v.Connection = route.Connection
	return render(c, fiber.StatusOK, "password", v)
}

func (h *Handler) password(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.sign_in"), c.FormValue("email")
	result, err := h.flow.Password(c.Context(), r, v.Email, c.FormValue("password"))
	if err != nil {
		return h.retry(c, v, "password", err)
	}
	return h.result(c, v, result)
}

func (h *Handler) sendCode(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.check_email"), c.FormValue("email")
	v.Challenge, err = h.flow.SendCode(c.Context(), r, v.Email)
	if err != nil {
		return h.retry(c, v, "password", err)
	}
	v.Notice = v.T("hosted.notice.code_sent", v.Email)
	return render(c, fiber.StatusOK, "code", v)
}

func (h *Handler) verifyCode(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title = v.T("hosted.title.check_email")
	v.Challenge, _ = identity.ParseChallengeID(c.FormValue("challenge_id"))
	result, err := h.flow.VerifyCode(c.Context(), r, v.Challenge, c.FormValue("code"))
	if err != nil {
		return h.retry(c, v, "code", err)
	}
	return h.result(c, v, result)
}

func (h *Handler) sendReset(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.reset"), c.FormValue("email")
	v.Challenge, err = h.flow.SendReset(c.Context(), r, v.Email)
	if err != nil {
		return h.retry(c, v, "password", err)
	}
	v.Notice = v.T("hosted.notice.reset_sent", v.Email)
	return render(c, fiber.StatusOK, "reset", v)
}

func (h *Handler) reset(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.reset"), c.FormValue("email")
	v.Challenge, _ = identity.ParseChallengeID(c.FormValue("challenge_id"))
	if err = h.flow.Reset(c.Context(), r, v.Challenge, c.FormValue("code"), c.FormValue("password")); err != nil {
		return h.retry(c, v, "reset", err)
	}
	v.Title, v.Notice = v.T("hosted.title.sign_in"), v.T("hosted.notice.password_changed")
	return render(c, fiber.StatusOK, "password", v)
}

func (h *Handler) sso(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	connection, _ := identity.ParseConnectionID(c.FormValue("connection_id"))
	start, err := h.flow.SSO(c.Context(), r, connection)
	if err != nil {
		v.Title = v.T("hosted.title.sign_in")
		return h.retry(c, v, "identify", err)
	}
	return h.federate(c, start.URL, start.Binding)
}

// Federated resumes a hosted login after the federation callback. The
// authorization binding cookie came back with the callback (SameSite=Lax
// top-level navigation).
func (h *Handler) Federated(c *fiber.Ctx, out federation.Outcome, callbackErr error) error {
	r := hosted.Request{Ticket: out.Continuation, Binding: c.Cookies(authorizationCookie)}
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title = v.T("hosted.title.sign_in")
	if callbackErr != nil {
		return h.retry(c, v, "identify", callbackErr)
	}
	result, err := h.flow.Federated(c.Context(), r, out.Verified)
	if err != nil {
		return h.retry(c, v, "identify", err)
	}
	return h.result(c, v, result)
}

func (h *Handler) organization(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	organization, _ := identity.ParseOrganizationID(c.FormValue("organization_id"))
	result, err := h.flow.Choose(c.Context(), r, organization)
	if err != nil {
		v.Title = v.T("hosted.title.sign_in")
		return h.retry(c, v, "identify", err)
	}
	return h.result(c, v, result)
}

func (h *Handler) secondFactor(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	enrolling := c.FormValue("enrolling") == "true"
	result, err := h.flow.SecondFactor(c.Context(), r, c.FormValue("code"))
	if err != nil {
		var e *errx.Error
		if enrolling && !(errx.As(err, &e) && e.Code == "LOGIN_EXPIRED") {
			return h.enrollPage(c, r, v, err)
		}
		v.Title = v.T("hosted.title.mfa")
		return h.retry(c, v, "mfa", err)
	}
	return h.result(c, v, result)
}

func (h *Handler) enrollPage(c *fiber.Ctx, r hosted.Request, v view, problem error) error {
	enrollment, err := h.flow.Enrollment(c.Context(), r)
	if err != nil {
		v.Title = v.T("hosted.title.sign_in")
		return h.retry(c, v, "identify", err)
	}
	status := fiber.StatusOK
	if problem != nil {
		status, v.Error = failed(c, v.Lang, problem)
	}
	return h.renderEnroll(c, status, v, enrollment)
}

func (h *Handler) renderEnroll(c *fiber.Ctx, status int, v view, e authentication.Enrollment) error {
	v.Title, v.Subtitle, v.Secret = v.T("hosted.title.enroll"), v.T("hosted.subtitle.enroll"), e.Secret
	if code, err := qr.Encode(e.URI, qr.M); err == nil {
		code.Scale = 4
		v.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()))
	}
	return render(c, status, "enroll", v)
}

func (h *Handler) continueLogin(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	result, err := h.flow.Continue(c.Context(), r)
	if err != nil {
		v.Title = v.T("hosted.title.sign_in")
		return h.retry(c, v, "identify", err)
	}
	return h.result(c, v, result)
}

// result shows the next step or finishes the authorization.
func (h *Handler) result(c *fiber.Ctx, v view, result hosted.Result) error {
	switch {
	case result.Login != nil:
		return h.finish(c, v.Ticket, *result.Login)
	case result.SecondFactor:
		v.Title, v.Subtitle = v.T("hosted.title.mfa"), v.T("hosted.subtitle.mfa")
		return render(c, fiber.StatusOK, "mfa", v)
	case result.Enroll != nil:
		return h.renderEnroll(c, fiber.StatusOK, v, *result.Enroll)
	case len(result.RecoveryCodes) > 0:
		v.Title, v.Subtitle, v.RecoveryCodes = v.T("hosted.title.recovery"), v.T("hosted.subtitle.recovery"), result.RecoveryCodes
		return render(c, fiber.StatusOK, "recovery", v)
	}
	v.Title, v.Subtitle, v.Organizations = v.T("hosted.title.organization"), v.T("hosted.subtitle.organization"), result.Organizations
	return render(c, fiber.StatusOK, "organization", v)
}

// retry shows the page again with the error; single sign-on requirements
// send the user back to the email step, which routes them to SSO.
func (h *Handler) retry(c *fiber.Ctx, v view, page string, err error) error {
	status, text := failed(c, v.Lang, err)
	var e *errx.Error
	if errx.As(err, &e) && e.Code == "SSO_REQUIRED" {
		page, text = "identify", v.T("hosted.error.sso_required")
	}
	if errx.As(err, &e) && e.Code == "LOGIN_EXPIRED" {
		// The parked login is gone (expired or out of attempts): start over.
		page, v.Title = "identify", v.T("hosted.title.sign_in")
	}
	v.Error = text
	return render(c, status, page, v)
}

// federate sends the browser to the identity provider with the federation
// binding cookie (the same cookie the headless start sets).
func (h *Handler) federate(c *fiber.Ctx, address, binding string) error {
	c.Cookie(&fiber.Cookie{Name: federationCookie, Value: binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: int(config.FederationStateTTL.Seconds())})
	c.Set("Cache-Control", "no-store")
	return c.Redirect(address, fiber.StatusSeeOther)
}

func (h *Handler) invite(c *fiber.Ctx) error {
	token := c.Query("token")
	preview, err := h.invitations.Preview(c.Context(), token)
	if err != nil {
		return invalidInvitation(c)
	}
	return h.invitePage(c, token, preview, nil)
}

func invalidInvitation(c *fiber.Ctx) error {
	lang := language(c, "")
	return message(c, lang, fiber.StatusBadRequest, i18n.T(lang, "hosted.invitation.title"), i18n.T(lang, "hosted.invitation.invalid"))
}

// environmentLanguage is the environment language, else the browser's.
func environmentLanguage(c *fiber.Ctx, settings hosted.Settings) string {
	code := ""
	if settings.Locale != nil {
		code = i18n.Match(*settings.Locale)
	}
	return language(c, code)
}

func (h *Handler) invitePage(c *fiber.Ctx, token string, preview invitation.Preview, problem error) error {
	settings, err := h.queries.Settings(c.Context(), preview.Environment)
	if err != nil {
		lang := language(c, "")
		code, text := failed(c, lang, err)
		return message(c, lang, code, i18n.T(lang, "hosted.invitation.title"), text)
	}
	v := view{Lang: environmentLanguage(c, settings), Brand: brandOf(settings, ""), Token: token, Invite: &preview}
	v.Title, v.Subtitle = v.T("hosted.invitation.join", preview.OrganizationName), v.T("hosted.invitation.invited", preview.OrganizationName)
	if preview.SSORequired {
		v.Subtitle += " " + v.T("hosted.invitation.sso")
	}
	status := fiber.StatusOK
	if problem != nil {
		status, v.Error = failed(c, v.Lang, problem)
	}
	return render(c, status, "invite", v)
}

func (h *Handler) accept(c *fiber.Ctx) error {
	token := c.FormValue("token")
	preview, err := h.invitations.Preview(c.Context(), token)
	if err != nil {
		return invalidInvitation(c)
	}
	accepted, err := h.invitations.Accept(c.Context(), invitation.Acceptance{Token: token, Name: c.FormValue("name"), Password: c.FormValue("password")})
	if err != nil {
		return h.invitePage(c, token, preview, err)
	}
	settings, err := h.queries.Settings(c.Context(), preview.Environment)
	if err != nil {
		settings = hosted.Settings{}
	}
	v := view{Lang: environmentLanguage(c, settings), Brand: brandOf(settings, "")}
	v.Title, v.Notice = v.T("hosted.invitation.accepted"), v.T("hosted.invitation.joined", preview.OrganizationName)
	if accepted.SSORequired {
		v.Notice = v.T("hosted.invitation.joined_sso", preview.OrganizationName)
	}
	return render(c, fiber.StatusOK, "message", v)
}

func (h *Handler) settings(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	out, err := h.queries.Settings(c.Context(), env)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) saveSettings(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	var input hosted.Settings
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SaveSettings(c.Context(), hosted.Mutation{Environment: env, Actor: h.actor(c), Action: c.Method(), Target: c.Path()}, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
