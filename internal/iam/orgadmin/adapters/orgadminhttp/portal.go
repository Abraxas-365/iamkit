package orgadminhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Portal serves the hosted organization admin portal's settings: operators
// turn it on and off under /management/v1/environments/:environment, and
// the portal reads its public client ID from /identity/v1.
type Portal struct {
	commands orgadmin.PortalCommands
	queries  orgadmin.PortalQueries
	actor    func(*fiber.Ctx) string
}

func NewPortal(commands orgadmin.PortalCommands, queries orgadmin.PortalQueries, actor func(*fiber.Ctx) string) *Portal {
	return &Portal{commands: commands, queries: queries, actor: actor}
}

func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Register mounts the operator routes on the environment group.
func (h *Portal) Register(r fiber.Router) {
	r.Get("/org-admin-portal", h.get)
	r.Put("/org-admin-portal", h.enable)
	r.Delete("/org-admin-portal", h.disable)
}

func (h *Portal) mutation(c *fiber.Ctx) orgadmin.PortalMutation {
	return orgadmin.PortalMutation{Environment: env(c), Actor: h.actor(c)}
}

func (h *Portal) get(c *fiber.Ctx) error {
	out, err := h.queries.Portal(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Portal) enable(c *fiber.Ctx) error {
	out, err := h.commands.EnablePortal(c.UserContext(), h.mutation(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Portal) disable(c *fiber.Ctx) error {
	if err := h.commands.DisablePortal(c.UserContext(), h.mutation(c)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Discover answers GET /identity/v1/org-admin/:environment with the
// portal's public client ID, 404 while the portal is off (or for an
// unknown environment: the answer does not tell them apart).
func (h *Portal) Discover(c *fiber.Ctx) error {
	environment, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return errx.NotFound("organization admin portal not found")
	}
	out, err := h.queries.Portal(c.UserContext(), environment)
	if err != nil {
		return err
	}
	if !out.Enabled {
		return errx.NotFound("organization admin portal not found")
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"client_id": out.Client, "environment_id": environment, "url": out.URL})
}
