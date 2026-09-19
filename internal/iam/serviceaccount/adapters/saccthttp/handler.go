package saccthttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands serviceaccount.Commands
	queries  serviceaccount.Queries
}

func New(commands serviceaccount.Commands, queries serviceaccount.Queries) *Handler {
	return &Handler{commands, queries}
}
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) Register(r fiber.Router) {
	r.Post("/service-accounts", h.Create)
	r.Get("/service-accounts", h.List)
	r.Delete("/service-accounts/:id", h.Revoke)
}
func (h *Handler) Create(c *fiber.Ctx) error {
	var input serviceaccount.Input
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Create(c.Context(), env(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}
func (h *Handler) List(c *fiber.Ctx) error {
	out, err := h.queries.List(c.Context(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(httpx.NewPaginated(c, out))
}
func (h *Handler) Revoke(c *fiber.Ctx) error {
	id, err := identity.ParseAccountID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err := h.commands.Revoke(c.Context(), env(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
