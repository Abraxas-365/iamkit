package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
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
	return authorization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}
func optionalResourceID(c *fiber.Ctx) identity.ResourceID {
	id, _ := identity.ParseResourceID(c.Params("id"))
	return id
}
func (h *Grants) ListRoles(c *fiber.Ctx) error {
	out, err := h.queries.Roles(c.Context(), env(c), optionalResourceID(c))
	if err != nil {
		return err
	}
	if c.Params("id") != "" {
		return c.JSON(out[0])
	}
	return c.JSON(httpx.NewPaginated(c, out))
}
func (h *Grants) ListGrants(c *fiber.Ctx) error {
	out, err := h.queries.Grants(c.Context(), env(c), optionalResourceID(c))
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
	roleID, _ := identity.ParseRoleID(c.Params("id"))
	id, err := h.commands.SaveRole(c.Context(), h.mutation(c), roleID, input)
	if err != nil {
		return err
	}
	if c.Params("id") == "" {
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
	return c.SendStatus(204)
}
func (h *Grants) DeleteRole(c *fiber.Ctx) error {
	id, err := identity.ParseRoleID(c.Params("id"))
	if err != nil {
		return errx.NotFound("role not found")
	}
	if err := h.commands.DeleteRole(c.Context(), h.mutation(c), id); err != nil {
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
	roleID, _ := identity.ParseRoleID(c.Params("role"))
	orgID, _ := identity.ParseOrganizationID(c.Params("organization"))
	userID, _ := identity.ParseUserID(c.Params("user"))
	input := authorization.RoleAssignment{Role: roleID, Organization: orgID, User: userID}
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
	id, err := h.commands.PutGrant(c.Context(), env(c), input)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"id": id})
}
func (h *Grants) DeleteGrant(c *fiber.Ctx) error {
	id, err := identity.ParseGrantID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err := h.commands.DeleteGrant(c.Context(), env(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) RoleAssignments(c *fiber.Ctx) error {
	roleID, _ := identity.ParseRoleID(c.Query("role_id"))
	orgID, _ := identity.ParseOrganizationID(c.Query("organization_id"))
	userID, _ := identity.ParseUserID(c.Query("user_id"))
	resID, _ := identity.ParseResourceID(c.Query("resource_id"))
	filter := authorization.RoleAssignmentFilter{
		RoleID: roleID, OrganizationID: orgID, UserID: userID, ResourceID: resID,
		Search: c.Query("search"),
	}
	page := httpx.PaginationFromCtx(c)
	items, total, err := h.queries.RoleAssignments(c.Context(), env(c), filter, page)
	if err != nil {
		return err
	}
	return c.JSON(httpx.NewPaginatedDB(items, total, page))
}
