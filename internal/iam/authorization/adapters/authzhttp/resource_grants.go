package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// ResourceGrants serves resource ownership and grants to organizations.
type ResourceGrants struct {
	commands authorization.ResourceGrantCommands
	queries  authorization.ResourceGrantQueries
	actor    func(*fiber.Ctx) string
}

func NewResourceGrants(commands authorization.ResourceGrantCommands, queries authorization.ResourceGrantQueries, actor func(*fiber.Ctx) string) *ResourceGrants {
	return &ResourceGrants{commands, queries, actor}
}

func (h *ResourceGrants) Register(e fiber.Router) {
	e.Put("/resources/:id/access", h.SetAccess)
	e.Get("/resource-grants", h.List)
	e.Get("/resource-grants/:id", h.Find)
	e.Put("/resource-grants", h.Put)
	e.Delete("/resource-grants/:id", h.Delete)
}

func (h *ResourceGrants) mutation(c *fiber.Ctx) authorization.Mutation {
	return authorization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}

func (h *ResourceGrants) SetAccess(c *fiber.Ctx) error {
	id, err := identity.ParseResourceID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	var input authorization.ResourceAccess
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	if err := h.commands.SetResourceAccess(c.UserContext(), h.mutation(c), id, input); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ResourceGrantFilter reads ?resource_id= and ?organization_id=.
func ResourceGrantFilter(c *fiber.Ctx) (authorization.ResourceGrantFilter, error) {
	var filter authorization.ResourceGrantFilter
	if raw := c.Query("resource_id"); raw != "" {
		id, err := identity.ParseResourceID(raw)
		if err != nil {
			return filter, errx.Validation("resource_id must be a valid UUID")
		}
		filter.Resource = id
	}
	if raw := c.Query("organization_id"); raw != "" {
		id, err := identity.ParseOrganizationID(raw)
		if err != nil {
			return filter, errx.Validation("organization_id must be a valid UUID")
		}
		filter.Organization = id
	}
	return filter, nil
}

func (h *ResourceGrants) List(c *fiber.Ctx) error {
	filter, err := ResourceGrantFilter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListResourceGrants(c.UserContext(), env(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *ResourceGrants) Find(c *fiber.Ctx) error {
	id, err := identity.ParseResourceGrantID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource grant not found")
	}
	out, err := h.queries.FindResourceGrant(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *ResourceGrants) Put(c *fiber.Ctx) error {
	var input authorization.ResourceGrantInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.commands.PutResourceGrant(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *ResourceGrants) Delete(c *fiber.Ctx) error {
	id, err := identity.ParseResourceGrantID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource grant not found")
	}
	if err := h.commands.DeleteResourceGrant(c.UserContext(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
