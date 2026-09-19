package apphttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/application"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands application.Commands
	queries  application.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands application.Commands, queries application.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor}
}
func (h *Handler) Register(r fiber.Router) {
	r.Post("/applications", h.create)
	r.Get("/applications", h.list)
	r.Get("/applications/:id", h.find)
	r.Patch("/applications/:id", h.update)
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input application.Create
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.Create(c.Context(), c.Params("environment"), input)
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
	return c.JSON(httpx.NewPaginated(c, out))
}
func (h *Handler) find(c *fiber.Ctx) error {
	out, err := h.queries.Find(c.Context(), c.Params("environment"), c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) update(c *fiber.Ctx) error {
	var input application.Update
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	m := application.Mutation{Environment: c.Params("environment"), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.Update(c.Context(), m, c.Params("id"), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
