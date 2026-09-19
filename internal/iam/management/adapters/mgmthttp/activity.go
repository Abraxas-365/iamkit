package mgmthttp

import (
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Activity struct {
	commands management.ActivityCommands
	queries  management.ActivityQueries
}

func NewActivity(commands management.ActivityCommands, queries management.ActivityQueries) *Activity {
	return &Activity{commands, queries}
}
func envID(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Activity) Register(r fiber.Router) {
	r.Get("/sessions", h.sessions)
	r.Delete("/sessions/:id", h.revoke)
	r.Get("/audit-events", h.audit)
}
func (h *Activity) sessions(c *fiber.Ctx) error {
	out, err := h.queries.Sessions(c.Context(), envID(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Activity) audit(c *fiber.Ctx) error {
	out, err := h.queries.Audit(c.Context(), envID(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Activity) revoke(c *fiber.Ctx) error {
	sessID, _ := identity.ParseSessionID(c.Params("id"))
	if err := h.commands.RevokeSession(c.Context(), envID(c), sessID, Principal(c).OperatorID.String(), c.Method(), c.Path()); err != nil {
		return err
	}
	return c.SendStatus(204)
}
