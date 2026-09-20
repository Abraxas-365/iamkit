package orghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
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
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) Register(e fiber.Router) {
	e.Post("/organizations", h.Create)
	e.Get("/organizations", h.List)
	e.Get("/organizations/:id", h.Find)
	e.Patch("/organizations/:id", h.Update)
	e.Post("/memberships", h.AddMember)
	e.Get("/organizations/:organization/members", h.Members)
	e.Delete("/organizations/:organization/members/:user", h.RemoveMember)
}
func (h *Handler) Create(c *fiber.Ctx) error {
	var input struct{ Name string `json:"name"` }
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.Create(c.Context(), env(c), input.Name)
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
	id, err := identity.ParseOrganizationID(c.Params("id"))
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
	var input organization.Update
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := identity.ParseOrganizationID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid org id")
	}
	m := organization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.Update(c.Context(), m, id, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) AddMember(c *fiber.Ctx) error {
	var input organization.Membership
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.AddMember(c.Context(), env(c), input); err != nil {
		return err
	}
	return c.SendStatus(201)
}
func (h *Handler) Members(c *fiber.Ctx) error {
	org, err := identity.ParseOrganizationID(c.Params("organization"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	managerID, _ := identity.ParseUserID(c.Query("manager_id"))
	filter := organization.MemberFilter{ManagerID: managerID}
	if v := c.Query("active"); v == "true" || v == "false" {
		b := v == "true"
		filter.Active = &b
	}
	out, err := h.queries.Members(c.Context(), env(c), org, filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) RemoveMember(c *fiber.Ctx) error {
	org, err := identity.ParseOrganizationID(c.Params("organization"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	user, err := identity.ParseUserID(c.Params("user"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err := h.commands.RemoveMember(c.Context(), env(c), org, user); err != nil {
		return err
	}
	return c.SendStatus(204)
}
