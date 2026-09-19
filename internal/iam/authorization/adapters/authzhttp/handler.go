package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
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
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
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
	id, err := h.commands.Create(c.Context(), env(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) List(c *fiber.Ctx) error {
	out, err := h.queries.List(c.Context(), env(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) Find(c *fiber.Ctx) error {
	id, err := identity.ParseResourceID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	out, err := h.queries.Find(c.Context(), env(c), id)
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
	id, err := identity.ParseResourceID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid resource id")
	}
	m := authorization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.UpdateCatalog(c.Context(), m, id, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Link(c *fiber.Ctx) error {
	var input struct {
		Application identity.ApplicationID `json:"application_id"`
		Resource    identity.ResourceID    `json:"resource_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.LinkApplication(c.Context(), env(c), input.Application, input.Resource); err != nil {
		return err
	}
	return c.SendStatus(201)
}
func (h *Handler) Unlink(c *fiber.Ctx) error {
	app, err := identity.ParseApplicationID(c.Params("application"))
	if err != nil {
		return errx.Validation("invalid application id")
	}
	res, err := identity.ParseResourceID(c.Params("resource"))
	if err != nil {
		return errx.Validation("invalid resource id")
	}
	if err := h.commands.UnlinkApplication(c.Context(), env(c), app, res); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) ListByApplication(c *fiber.Ctx) error {
	app, err := identity.ParseApplicationID(c.Params("application"))
	if err != nil {
		return errx.Validation("invalid application id")
	}
	out, err := h.queries.ListByApplication(c.Context(), env(c), app, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
