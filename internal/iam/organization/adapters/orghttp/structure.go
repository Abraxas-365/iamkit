package orghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Structure struct {
	commands organization.StructureCommands
	queries  organization.StructureQueries
	actor    func(*fiber.Ctx) string
}

func NewStructure(commands organization.StructureCommands, queries organization.StructureQueries, actor func(*fiber.Ctx) string) *Structure {
	return &Structure{commands, queries, actor}
}
func boundary(c *fiber.Ctx) organization.Boundary {
	envID, _ := identity.ParseEnvironmentID(c.Params("environment"))
	orgID, _ := identity.ParseOrganizationID(c.Params("organization"))
	return organization.Boundary{Environment: envID, Organization: orgID}
}
func (h *Structure) mutation(c *fiber.Ctx) organization.Mutation {
	return organization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}
func (h *Structure) Check(c *fiber.Ctx) error {
	if err := h.commands.Check(c.Context(), boundary(c)); err != nil {
		return err
	}
	return c.Next()
}
func (h *Structure) view(view organization.StructureView) fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw, err := h.queries.View(c.Context(), boundary(c), view, c.Params("id"))
		if err != nil {
			return err
		}
		c.Type("json")
		return c.Send(raw)
	}
}
func (h *Structure) Register(e fiber.Router) {
	r := e.Group("/organizations/:organization", h.Check)
	h.RegisterViews(r)
	h.RegisterMutations(r)
}
func (h *Structure) RegisterViews(r fiber.Router) {
	for _, route := range []struct {
		path string
		view organization.StructureView
	}{{"/members", organization.Members}, {"/org-units", organization.Units}, {"/positions", organization.Positions}, {"/position-assignments", organization.Assignments}, {"/org-units/:id", organization.UnitDetail}, {"/org-units/:id/ancestors", organization.Ancestors}, {"/org-units/:id/descendants", organization.Descendants}, {"/org-units/:id/delete-impact", organization.DeleteImpact}, {"/tree", organization.Tree}, {"/org-chart", organization.Chart}} {
		r.Get(route.path, h.view(route.view))
	}
}
func (h *Structure) RegisterMutations(r fiber.Router) {
	r.Post("/org-units", h.SaveUnit)
	r.Put("/org-units/:id", h.SaveUnit)
	r.Delete("/org-units/:id", h.DeleteUnit)
	r.Put("/members/:user/profile", h.SetProfile)
	r.Post("/positions", h.SavePosition)
	r.Put("/positions/:id", h.SavePosition)
	r.Delete("/positions/:id", h.DeletePosition)
	r.Post("/position-assignments", h.AssignPosition)
	r.Delete("/position-assignments/:id", h.UnassignPosition)
}
func (h *Structure) SaveUnit(c *fiber.Ctx) error {
	var input organization.Unit
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	unitID, _ := identity.ParseUnitID(c.Params("id"))
	id, err := h.commands.SaveUnit(c.Context(), boundary(c), h.mutation(c), unitID, input)
	if err != nil {
		return err
	}
	if c.Params("id") == "" {
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
	return c.SendStatus(204)
}
func (h *Structure) DeleteUnit(c *fiber.Ctx) error {
	id, err := identity.ParseUnitID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid unit id")
	}
	if err := h.commands.DeleteUnit(c.Context(), boundary(c), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Structure) SetProfile(c *fiber.Ctx) error {
	var input organization.Profile
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	userID, err := identity.ParseUserID(c.Params("user"))
	if err != nil {
		return errx.Validation("invalid user id")
	}
	if err := h.commands.SetProfile(c.Context(), boundary(c), h.mutation(c), userID, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Structure) SavePosition(c *fiber.Ctx) error {
	var input organization.Position
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	posID, _ := identity.ParsePositionID(c.Params("id"))
	id, err := h.commands.SavePosition(c.Context(), boundary(c), h.mutation(c), posID, input)
	if err != nil {
		return err
	}
	if c.Params("id") == "" {
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
	return c.SendStatus(204)
}
func (h *Structure) DeletePosition(c *fiber.Ctx) error {
	id, err := identity.ParsePositionID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid position id")
	}
	if err := h.commands.DeletePosition(c.Context(), boundary(c), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Structure) AssignPosition(c *fiber.Ctx) error {
	var input organization.Assignment
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.AssignPosition(c.Context(), boundary(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Structure) UnassignPosition(c *fiber.Ctx) error {
	id, err := identity.ParseAssignmentID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid assignment id")
	}
	if err := h.commands.DeleteAssignment(c.Context(), boundary(c), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
