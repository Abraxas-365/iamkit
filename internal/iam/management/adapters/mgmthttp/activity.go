package mgmthttp

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/gofiber/fiber/v2"
)

type Activity struct {
	commands management.ActivityCommands
	queries  management.ActivityQueries
}

func NewActivity(commands management.ActivityCommands, queries management.ActivityQueries) *Activity {
	return &Activity{commands, queries}
}
func (h *Activity) Register(r fiber.Router) {
	r.Get("/sessions", h.sessions)
	r.Delete("/sessions/:id", h.revoke)
	r.Get("/audit-events", h.audit)
}
func (h *Activity) sessions(c *fiber.Ctx) error {
	out, err := h.queries.Sessions(c.Context(), c.Params("environment"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Activity) audit(c *fiber.Ctx) error {
	out, err := h.queries.Audit(c.Context(), c.Params("environment"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Activity) revoke(c *fiber.Ctx) error {
	if err := h.commands.RevokeSession(c.Context(), c.Params("environment"), c.Params("id"), Principal(c).OperatorID, c.Method(), c.Path()); err != nil {
		return err
	}
	return c.SendStatus(204)
}
