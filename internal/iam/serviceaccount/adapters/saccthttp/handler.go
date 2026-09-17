package saccthttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands serviceaccount.Commands
	queries  serviceaccount.Queries
}

func New(commands serviceaccount.Commands, queries serviceaccount.Queries) *Handler {
	return &Handler{commands, queries}
}
func (h *Handler) Register(r fiber.Router) {
	r.Post("/service-accounts", h.create)
	r.Get("/service-accounts", h.list)
	r.Delete("/service-accounts/:id", h.revoke)
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input serviceaccount.Input
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Create(c.Context(), c.Params("environment"), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}
func (h *Handler) list(c *fiber.Ctx) error {
	out, err := h.queries.List(c.Context(), c.Params("environment"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) revoke(c *fiber.Ctx) error {
	if err := h.commands.Revoke(c.Context(), c.Params("environment"), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
