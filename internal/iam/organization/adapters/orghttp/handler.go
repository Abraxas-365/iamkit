package orghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands organization.Commands
	queries  organization.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands organization.Commands, queries organization.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands, queries, actor}
}
func (h *Handler) Register(e fiber.Router) {
	e.Post("/organizations", h.create)
	e.Get("/organizations", h.list)
	e.Get("/organizations/:id", h.find)
	e.Patch("/organizations/:id", h.update)
	e.Post("/memberships", h.addMember)
	e.Delete("/organizations/:organization/members/:user", h.removeMember)
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.Create(c.Context(), c.Params("environment"), input.Name)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) list(c *fiber.Ctx) error {
	out, err := h.queries.List(c.Context(), c.Params("environment"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) find(c *fiber.Ctx) error {
	out, err := h.queries.Find(c.Context(), c.Params("environment"), c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) update(c *fiber.Ctx) error {
	var input organization.Update
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	m := organization.Mutation{Environment: c.Params("environment"), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.Update(c.Context(), m, c.Params("id"), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) addMember(c *fiber.Ctx) error {
	var input organization.Membership
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.AddMember(c.Context(), c.Params("environment"), input); err != nil {
		return err
	}
	return c.SendStatus(201)
}
func (h *Handler) removeMember(c *fiber.Ctx) error {
	if err := h.commands.RemoveMember(c.Context(), c.Params("environment"), c.Params("organization"), c.Params("user")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
