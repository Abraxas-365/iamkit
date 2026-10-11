package orgadminhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Owners manage the organization's setup links from the portal.

func (h *Handler) setupLinks(c *fiber.Ctx) error {
	out, err := h.queries.SetupLinks(c.UserContext(), principal(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// createSetupLink answers 201 with the link's URL, shown once.
func (h *Handler) createSetupLink(c *fiber.Ctx) error {
	var input orgadmin.SetupLinkInput
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.CreateSetupLink(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) revokeSetupLink(c *fiber.Ctx) error {
	id, err := identity.ParseSetupLinkID(c.Params("link"))
	if err != nil {
		return errx.NotFound("setup link not found")
	}
	return done(c, h.commands.RevokeSetupLink(c.UserContext(), principal(c), id))
}

// SetupLinks serves the setup links of an organization to operators
// (management API, and /api/v1 with iam:orgs:*) and the public exchange.
type SetupLinks struct {
	commands orgadmin.SetupLinkCommands
	queries  orgadmin.SetupLinkQueries
	actor    func(*fiber.Ctx) string
}

func NewSetupLinks(commands orgadmin.SetupLinkCommands, queries orgadmin.SetupLinkQueries, actor func(*fiber.Ctx) string) *SetupLinks {
	return &SetupLinks{commands: commands, queries: queries, actor: actor}
}

// Register mounts the operator routes on the environment group.
func (h *SetupLinks) Register(r fiber.Router) {
	r.Get("/organizations/:organization/setup-links", h.list)
	r.Post("/organizations/:organization/setup-links", h.create)
	r.Delete("/organizations/:organization/setup-links/:link", h.revoke)
}

// Guarded mounts them with a per-route check (the /api/v1 permission).
func (h *SetupLinks) Guarded(r fiber.Router, read, write fiber.Handler) {
	r.Get("/organizations/:organization/setup-links", read, h.list)
	r.Post("/organizations/:organization/setup-links", write, h.create)
	r.Delete("/organizations/:organization/setup-links/:link", write, h.revoke)
}

func (h *SetupLinks) mutation(c *fiber.Ctx) (orgadmin.SetupMutation, error) {
	organization, err := identity.ParseOrganizationID(c.Params("organization"))
	if err != nil {
		return orgadmin.SetupMutation{}, errx.NotFound("organization not found")
	}
	return orgadmin.SetupMutation{Environment: env(c), Organization: organization, Actor: h.actor(c), Action: c.Method(), Target: c.Path()}, nil
}

func (h *SetupLinks) list(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	out, err := h.queries.List(c.UserContext(), m.Environment, m.Organization, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *SetupLinks) create(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	var input orgadmin.SetupLinkInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.commands.Create(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *SetupLinks) revoke(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	id, err := identity.ParseSetupLinkID(c.Params("link"))
	if err != nil {
		return errx.NotFound("setup link not found")
	}
	if err := h.commands.Revoke(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Exchange answers POST /identity/v1/org-admin/setup: the link's secret
// for a short-lived bearer limited to the link's intents. Unknown, expired
// and revoked links are one 401.
func (h *SetupLinks) Exchange(c *fiber.Ctx) error {
	var input orgadmin.SetupExchange
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	if input.Token == "" {
		return errx.Validation("token is required")
	}
	out, err := h.commands.Exchange(c.UserContext(), input.Token)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}
