package orghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
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
	return organization.Boundary{Environment: c.Params("environment"), Organization: c.Params("organization")}
}
func (h *Structure) mutation(c *fiber.Ctx) organization.Mutation {
	return organization.Mutation{Environment: c.Params("environment"), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
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

// Register mounts all structure routes under /organizations/:organization (management).
func (h *Structure) Register(e fiber.Router) {
	r := e.Group("/organizations/:organization", h.Check)
	h.RegisterViews(r)
	h.RegisterMutations(r)
}

// RegisterViews mounts read-only structure routes. The caller must have already
// set up the :organization param and any check middleware.
func (h *Structure) RegisterViews(r fiber.Router) {
	for _, route := range []struct {
		path string
		view organization.StructureView
	}{{"/members", organization.Members}, {"/org-units", organization.Units}, {"/positions", organization.Positions}, {"/position-assignments", organization.Assignments}, {"/org-units/:id", organization.UnitDetail}, {"/org-units/:id/ancestors", organization.Ancestors}, {"/org-units/:id/descendants", organization.Descendants}, {"/org-units/:id/delete-impact", organization.DeleteImpact}, {"/tree", organization.Tree}, {"/org-chart", organization.Chart}} {
		r.Get(route.path, h.view(route.view))
	}
}

// RegisterMutations mounts write structure routes.
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
	id, err := h.commands.SaveUnit(c.Context(), boundary(c), h.mutation(c), c.Params("id"), input)
	if err != nil {
		return err
	}
	if c.Params("id") == "" {
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
	return c.SendStatus(204)
}
func (h *Structure) DeleteUnit(c *fiber.Ctx) error {
	if err := h.commands.DeleteUnit(c.Context(), boundary(c), h.mutation(c), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Structure) SetProfile(c *fiber.Ctx) error {
	var input organization.Profile
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.SetProfile(c.Context(), boundary(c), h.mutation(c), c.Params("user"), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Structure) SavePosition(c *fiber.Ctx) error {
	var input organization.Position
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.SavePosition(c.Context(), boundary(c), h.mutation(c), c.Params("id"), input)
	if err != nil {
		return err
	}
	if c.Params("id") == "" {
		return c.Status(201).JSON(fiber.Map{"id": id})
	}
	return c.SendStatus(204)
}
func (h *Structure) DeletePosition(c *fiber.Ctx) error {
	if err := h.commands.DeletePosition(c.Context(), boundary(c), h.mutation(c), c.Params("id")); err != nil {
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
	if err := h.commands.DeleteAssignment(c.Context(), boundary(c), h.mutation(c), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
