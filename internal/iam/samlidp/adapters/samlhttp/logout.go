package samlhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/gofiber/fiber/v2"
)

// Logout sets the single logout flows (set in bootstrap; nil = 404).
func (h *Handler) Logout(flows samlidp.LogoutFlows) { h.logout = flows }

// SLO receives a service provider's LogoutRequest (HTTP-Redirect or
// HTTP-POST binding) and sends the browser on with the signed
// LogoutResponse.
func (h *Handler) SLO(c *fiber.Ctx) error {
	environment := env(c)
	if environment.IsZero() || h.logout == nil {
		return errx.NotFound("not found")
	}
	message := samlidp.LogoutMessage{Redirect: true, SAMLRequest: c.Query("SAMLRequest"), RelayState: c.Query("RelayState"), RawQuery: string(c.Request().URI().QueryString())}
	if c.Method() == fiber.MethodPost {
		message = samlidp.LogoutMessage{SAMLRequest: c.FormValue("SAMLRequest"), RelayState: c.FormValue("RelayState")}
	}
	if err := message.Validate(); err != nil {
		return err
	}
	answer, err := h.logout.Logout(c.UserContext(), environment, message)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	if len(answer.Fields) == 0 {
		return c.Redirect(answer.URL, fiber.StatusSeeOther)
	}
	if h.form == nil {
		return errx.Internal("SAML response page not configured")
	}
	return h.form(c, answer.Environment, answer.URL, answer.Fields)
}
