package mgmthttp

import (
	"log/slog"
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// ssoCookie binds a single sign-on to the browser that started it. It is
// Lax: the provider's redirect back is a cross-site top-level navigation.
const ssoCookie = "__Host-iamkit-operator-sso"

// SSO serves operator single sign-on and the identities linked to
// operators. Start and callback are browser navigations: they answer with
// redirects, never JSON, and failures land on the console login page as
// /login?sso_error=<expired|not_authorized|provider_unavailable|cancelled|failed>.
type SSO struct {
	flows    management.SSOFlows
	commands management.IdentityCommands
	queries  management.IdentityQueries
}

func NewSSO(flows management.SSOFlows, commands management.IdentityCommands, queries management.IdentityQueries) *SSO {
	return &SSO{flows: flows, commands: commands, queries: queries}
}

// Options serves GET /management/v1/login-options.
func (h *SSO) Options(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	return c.JSON(h.flows.Options(c.Context()))
}

// Start serves GET /management/v1/sso/:provider/start.
func (h *SSO) Start(c *fiber.Ctx) error {
	navigation(c)
	out, err := h.flows.Start(c.Context(), c.Params("provider"))
	if err != nil {
		return failed(c, err)
	}
	c.Cookie(&fiber.Cookie{Name: ssoCookie, Value: out.Binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: int(config.FederationStateTTL.Seconds())})
	return c.Redirect(out.URL, fiber.StatusFound)
}

// Callback serves GET /management/v1/sso/callback, the redirect URI of
// every operator identity provider.
func (h *SSO) Callback(c *fiber.Ctx) error {
	navigation(c)
	binding := c.Cookies(ssoCookie)
	c.Cookie(&fiber.Cookie{Name: ssoCookie, Value: "", Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: -1})
	if c.Query("error") != "" {
		// Declined or cancelled at the provider; the state just expires. A
		// code next to an error is never exchanged.
		return login(c, "cancelled")
	}
	raw, _, err := h.flows.Callback(c.Context(), c.Query("code"), c.Query("state"), binding)
	if err != nil {
		return failed(c, err)
	}
	c.Cookie(&fiber.Cookie{Name: sessionCookie, Value: raw, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Strict", MaxAge: config.SessionCookieMaxAge})
	// The console shell needs no cookie; its API calls are same-site, so
	// they carry the Strict session cookie.
	return c.Redirect("/", fiber.StatusSeeOther)
}

// Register mounts the authenticated identity routes.
func (h *SSO) Register(r fiber.Router) {
	r.Get("/operators/:id/identities", h.identities)
	r.Delete("/operators/:id/identities", h.unlink)
}

func (h *SSO) identities(c *fiber.Ctx) error {
	id, err := identity.ParseOperatorID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	out, err := h.queries.Identities(c.Context(), Principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *SSO) unlink(c *fiber.Ctx) error {
	id, err := identity.ParseOperatorID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err = h.commands.UnlinkIdentities(c.Context(), Principal(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func navigation(c *fiber.Ctx) {
	c.Set("Cache-Control", "no-store")
	c.Set("Referrer-Policy", "no-referrer")
}

// failed sends the browser back to the login page with a reason it can
// show, and logs what the browser is not told.
func failed(c *fiber.Ctx, err error) error {
	var e *errx.Error
	reason := "failed"
	if errx.As(err, &e) {
		switch {
		case e.Code == management.CodeSSOExpired:
			reason = "expired"
		case e.Code == "PROVIDER_UNAVAILABLE":
			reason = "provider_unavailable"
		case e.Type == errx.TypeAuthorization || e.Type == errx.TypeNotFound:
			// Refused identities, rejected code exchanges, tokens failing
			// verification, unknown providers.
			reason = "not_authorized"
		}
	}
	if reason == "failed" || reason == "provider_unavailable" {
		slog.ErrorContext(c.Context(), "operator single sign-on failed", "err", err)
	} else if e != nil && e.Code != management.CodeSSONotAuthorized {
		// SSO_NOT_AUTHORIZED is logged with its reason by the service.
		slog.WarnContext(c.Context(), "operator single sign-on refused", "reason", e.Message)
	}
	return login(c, reason)
}

func login(c *fiber.Ctx, reason string) error {
	return c.Redirect("/login?"+url.Values{"sso_error": {reason}}.Encode(), fiber.StatusSeeOther)
}
