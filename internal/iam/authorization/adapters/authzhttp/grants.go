package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/gofiber/fiber/v2"
)

type Grants struct {
	commands authorization.GrantCommands
	queries  authorization.GrantQueries
	actor    func(*fiber.Ctx) string
}

func NewGrants(commands authorization.GrantCommands, queries authorization.GrantQueries, actor func(*fiber.Ctx) string) *Grants {
	return &Grants{commands, queries, actor}
}
func (h *Grants) Register(e fiber.Router) {
	e.Get("/roles", h.ListRoles)
	e.Get("/roles/:id", h.ListRoles)
	e.Post("/roles", h.SaveRole)
	e.Put("/roles/:id", h.SaveRole)
	e.Delete("/roles/:id", h.DeleteRole)
	e.Post("/role-assignments", h.Assign)
	e.Get("/role-assignments", h.RoleAssignments)
	e.Delete("/role-assignments/:role/:organization/:user", h.Unassign)
	e.Get("/grants", h.ListGrants)
	e.Get("/grants/:id", h.ListGrants)
	e.Put("/grants", h.PutGrant)
	e.Delete("/grants/:id", h.DeleteGrant)
}
func (h *Grants) mutation(c *fiber.Ctx) authorization.Mutation {
	return authorization.Mutation{Environment: c.Params("environment"), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}
func (h *Grants) ListRoles(c *fiber.Ctx) error {
	out, err := h.queries.Roles(c.Context(), c.Params("environment"), c.Params("id"))
	if err != nil {
		return err
	}
	if c.Params("id") != "" {
		return c.JSON(out[0])
	}
	return c.JSON(httpx.NewPaginated(c, out))
}
func (h *Grants) ListGrants(c *fiber.Ctx) error {
	out, err := h.queries.Grants(c.Context(), c.Params("environment"), c.Params("id"))
	if err != nil {
		return err
	}
	if c.Params("id") != "" {
		return c.JSON(out[0])
	}
	return c.JSON(httpx.NewPaginated(c, out))
}
func (h *Grants) SaveRole(c *fiber.Ctx) error {
	var input authorization.Role
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.SaveRole(c.Context(), h.mutation(c), c.Params("id"), input)
	if err != nil {
		return err
	}
	if c.Params("id") == "" {
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
	return c.SendStatus(204)
}
func (h *Grants) DeleteRole(c *fiber.Ctx) error {
	if err := h.commands.DeleteRole(c.Context(), h.mutation(c), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) Assign(c *fiber.Ctx) error {
	var input authorization.RoleAssignment
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.AssignRole(c.Context(), h.mutation(c), input, false); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) Unassign(c *fiber.Ctx) error {
	input := authorization.RoleAssignment{Role: c.Params("role"), Organization: c.Params("organization"), User: c.Params("user")}
	if err := h.commands.AssignRole(c.Context(), h.mutation(c), input, true); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) PutGrant(c *fiber.Ctx) error {
	var input authorization.Grant
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.PutGrant(c.Context(), c.Params("environment"), input)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"id": id})
}
func (h *Grants) DeleteGrant(c *fiber.Ctx) error {
	if err := h.commands.DeleteGrant(c.Context(), c.Params("environment"), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) RoleAssignments(c *fiber.Ctx) error {
	filter := authorization.RoleAssignmentFilter{
		RoleID:         c.Query("role_id"),
		OrganizationID: c.Query("organization_id"),
		UserID:         c.Query("user_id"),
		ResourceID:     c.Query("resource_id"),
		Search:         c.Query("search"),
	}
	page := httpx.PaginationFromCtx(c)
	items, total, err := h.queries.RoleAssignments(c.Context(), c.Params("environment"), filter, page)
	if err != nil {
		return err
	}
	return c.JSON(httpx.NewPaginatedDB(items, total, page))
}
