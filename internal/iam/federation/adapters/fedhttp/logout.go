package fedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// SAMLLogout is a SAML connection's single logout service (HTTP-Redirect
// and HTTP-POST): the identity provider's LogoutRequest, or its
// LogoutResponse to an SP-initiated logout. 404 unless the connection has
// options.single_logout.
func (h *Handler) SAMLLogout(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	environment, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil || h.logout == nil {
		return errx.NotFound("SAML connection not found")
	}
	connection, err := identity.ParseConnectionID(c.Params("connection"))
	if err != nil {
		return errx.NotFound("SAML connection not found")
	}
	m := federation.LogoutMessage{Redirect: true, SAMLRequest: c.Query("SAMLRequest"), SAMLResponse: c.Query("SAMLResponse"), RelayState: c.Query("RelayState"), RawQuery: string(c.Request().URI().QueryString())}
	if c.Method() == fiber.MethodPost {
		m = federation.LogoutMessage{SAMLRequest: c.FormValue("SAMLRequest"), SAMLResponse: c.FormValue("SAMLResponse"), RelayState: c.FormValue("RelayState")}
	}
	if err := m.Validate(); err != nil {
		return err
	}
	out, err := h.logout.SingleLogout(c.UserContext(), environment, connection, m)
	if err != nil {
		return err
	}
	return h.Send(c, environment, out)
}

// Send takes the browser to out: a 303 for HTTP-Redirect, the auto-submit
// page for HTTP-POST, the hosted signed-out page when out.URL is "".
func (h *Handler) Send(c *fiber.Ctx, environment identity.EnvironmentID, out federation.Outbound) error {
	if out.URL == "" {
		if h.signedOut == nil {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return h.signedOut(c, environment, nil)
	}
	if !out.Post() {
		return c.Redirect(out.URL, fiber.StatusSeeOther)
	}
	if h.form == nil {
		return errx.Internal("SAML logout page not configured")
	}
	return h.form(c, environment, out.URL, out.Fields)
}
