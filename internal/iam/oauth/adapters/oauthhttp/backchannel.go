package oauthhttp

import (
	"strconv"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Logouts serves the back-channel logout delivery log to operators.
type Logouts struct {
	commands oauth.LogoutCommands
	queries  oauth.LogoutQueries
	actor    func(*fiber.Ctx) string
}

func NewLogouts(commands oauth.LogoutCommands, queries oauth.LogoutQueries, actor func(*fiber.Ctx) string) *Logouts {
	return &Logouts{commands: commands, queries: queries, actor: actor}
}

func (h *Logouts) Register(r fiber.Router) {
	r.Get("/logout-deliveries", h.list)
	r.Post("/logout-deliveries/:id/retry", h.retry)
}

func (h *Logouts) list(c *fiber.Ctx) error {
	filter := oauth.LogoutFilter{Status: c.Query("status")}
	if raw := c.Query("client_id"); raw != "" {
		client, err := identity.ParseClientID(raw)
		if err != nil {
			return errx.Validation("client_id must be a valid UUID")
		}
		filter.Client = client
	}
	out, err := h.queries.LogoutDeliveries(c.UserContext(), env(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Logouts) retry(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil || id <= 0 {
		return errx.NotFound("failed logout delivery not found")
	}
	m := oauth.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err = h.commands.RetryLogout(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusAccepted)
}
