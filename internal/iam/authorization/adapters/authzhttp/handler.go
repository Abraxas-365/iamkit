package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands authorization.ResourceCommands
	queries  authorization.ResourceQueries
	actor    func(*fiber.Ctx) string
}

func New(commands authorization.ResourceCommands, queries authorization.ResourceQueries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands, queries, actor}
}
func (h *Handler) Register(e fiber.Router) {
	e.Post("/resources", h.Create)
	e.Get("/resources", h.List)
	e.Get("/resources/:id", h.Find)
	e.Put("/resources/:id", h.Update)
	e.Post("/application-resources", h.Link)
	e.Delete("/application-resources/:application/:resource", h.Unlink)
	e.Get("/applications/:application/resources", h.ListByApplication)
}
func (h *Handler) Create(c *fiber.Ctx) error {
	var input authorization.Resource
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.CreateResource(c.Context(), c.Params("environment"), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) List(c *fiber.Ctx) error {
	out, err := h.queries.Resources(c.Context(), c.Params("environment"))
	if err != nil {
		return err
	}
	return c.JSON(httpx.NewPaginated(c, out))
}
func (h *Handler) Find(c *fiber.Ctx) error {
	out, err := h.queries.Resource(c.Context(), c.Params("environment"), c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) Update(c *fiber.Ctx) error {
	var input authorization.Catalog
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	m := authorization.Mutation{Environment: c.Params("environment"), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.UpdateCatalog(c.Context(), m, c.Params("id"), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Link(c *fiber.Ctx) error {
	var input struct {
		Application string `json:"application_id"`
		Resource    string `json:"resource_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.LinkApplication(c.Context(), c.Params("environment"), input.Application, input.Resource); err != nil {
		return err
	}
	return c.SendStatus(201)
}
func (h *Handler) Unlink(c *fiber.Ctx) error {
	if err := h.commands.UnlinkApplication(c.Context(), c.Params("environment"), c.Params("application"), c.Params("resource")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) ListByApplication(c *fiber.Ctx) error {
	out, err := h.queries.ResourcesByApplication(c.Context(), c.Params("environment"), c.Params("application"))
	if err != nil {
		return err
	}
	return c.JSON(httpx.NewPaginated(c, out))
}
