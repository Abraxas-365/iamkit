package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
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
	e.Get("/roles", h.roles)
	e.Get("/roles/:id", h.roles)
	e.Post("/roles", h.saveRole)
	e.Put("/roles/:id", h.saveRole)
	e.Delete("/roles/:id", h.deleteRole)
	e.Post("/role-assignments", h.assign)
	e.Delete("/role-assignments/:role/:organization/:user", h.unassign)
	e.Get("/grants", h.grants)
	e.Get("/grants/:id", h.grants)
	e.Put("/grants", h.putGrant)
	e.Delete("/grants/:id", h.deleteGrant)
}
func (h *Grants) mutation(c *fiber.Ctx) authorization.Mutation {
	return authorization.Mutation{Environment: c.Params("environment"), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}
func (h *Grants) roles(c *fiber.Ctx) error {
	out, err := h.queries.Roles(c.Context(), c.Params("environment"), c.Params("id"))
	if err != nil {
		return err
	}
	if c.Params("id") != "" {
		return c.JSON(out[0])
	}
	return c.JSON(out)
}
func (h *Grants) grants(c *fiber.Ctx) error {
	out, err := h.queries.Grants(c.Context(), c.Params("environment"), c.Params("id"))
	if err != nil {
		return err
	}
	if c.Params("id") != "" {
		return c.JSON(out[0])
	}
	return c.JSON(out)
}
func (h *Grants) saveRole(c *fiber.Ctx) error {
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
func (h *Grants) deleteRole(c *fiber.Ctx) error {
	if err := h.commands.DeleteRole(c.Context(), h.mutation(c), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) assign(c *fiber.Ctx) error {
	var input authorization.RoleAssignment
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.AssignRole(c.Context(), h.mutation(c), input, false); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) unassign(c *fiber.Ctx) error {
	input := authorization.RoleAssignment{Role: c.Params("role"), Organization: c.Params("organization"), User: c.Params("user")}
	if err := h.commands.AssignRole(c.Context(), h.mutation(c), input, true); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Grants) putGrant(c *fiber.Ctx) error {
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
func (h *Grants) deleteGrant(c *fiber.Ctx) error {
	if err := h.commands.DeleteGrant(c.Context(), c.Params("environment"), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
