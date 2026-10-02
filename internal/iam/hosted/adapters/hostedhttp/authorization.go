package hostedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/gofiber/fiber/v2"
)

// Authorization serves GET /identity/v1/authorize/:ticket: what a custom
// sign-in UI needs to render a pending authorization of its client (the
// ticket /oauth/authorize answered with, read under the browser binding
// cookie, so it is called from the browser with credentials).
func (h *Handler) Authorization(c *fiber.Ctx) error {
	out, err := h.flow.Authorization(c.UserContext(), hosted.Request{Ticket: c.Params("ticket"), Binding: c.Cookies(authorizationCookie)}, c.Get(fiber.HeaderAcceptLanguage))
	if err != nil {
		return err
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(out)
}
