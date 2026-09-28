package orghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Groups serves /organizations/:organization/groups. Routes are registered
// on a router that already verified the organization (Structure.Check).
type Groups struct {
	commands organization.GroupCommands
	queries  organization.GroupQueries
	actor    func(*fiber.Ctx) string
}

func NewGroups(commands organization.GroupCommands, queries organization.GroupQueries, actor func(*fiber.Ctx) string) *Groups {
	return &Groups{commands, queries, actor}
}

func (h *Groups) RegisterViews(r fiber.Router) {
	r.Get("/groups", h.List)
	r.Get("/groups/:group", h.Find)
	r.Get("/groups/:group/members", h.Members)
	r.Get("/members/:user/groups", h.UserGroups)
}

func (h *Groups) RegisterMutations(r fiber.Router) {
	r.Post("/groups", h.Create)
	r.Patch("/groups/:group", h.Update)
	r.Delete("/groups/:group", h.Delete)
	r.Post("/groups/:group/members", h.ChangeMembers)
}

func (h *Groups) mutation(c *fiber.Ctx) organization.Mutation {
	return organization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}

func groupID(c *fiber.Ctx) (identity.GroupID, error) {
	id, err := identity.ParseGroupID(c.Params("group"))
	if err != nil {
		return id, errx.NotFound("group not found")
	}
	return id, nil
}

func (h *Groups) List(c *fiber.Ctx) error {
	var filter organization.GroupFilter
	if raw := c.Query("user_id"); raw != "" {
		id, err := identity.ParseUserID(raw)
		if err != nil {
			return errx.Validation("user_id must be a valid UUID")
		}
		filter.User = id
	}
	if raw := c.Query("connection_id"); raw != "" {
		id, err := identity.ParseConnectionID(raw)
		if err != nil {
			return errx.Validation("connection_id must be a valid UUID")
		}
		filter.Connection = id
	}
	switch source := c.Query("source"); source {
	case "", organization.GroupSourceManual, organization.GroupSourceDirectory:
		filter.Source = source
	default:
		return errx.Validation("source must be manual or directory")
	}
	out, err := h.queries.ListGroups(c.Context(), boundary(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Groups) UserGroups(c *fiber.Ctx) error {
	user, err := identity.ParseUserID(c.Params("user"))
	if err != nil {
		return errx.NotFound("member not found")
	}
	out, err := h.queries.ListGroups(c.Context(), boundary(c), organization.GroupFilter{User: user}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Groups) Find(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.FindGroup(c.Context(), boundary(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Groups) Members(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListGroupMembers(c.Context(), boundary(c), id, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Groups) Create(c *fiber.Ctx) error {
	var input organization.GroupInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.CreateGroup(c.Context(), boundary(c), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}

func (h *Groups) Update(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	var input organization.GroupUpdate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.UpdateGroup(c.Context(), boundary(c), h.mutation(c), id, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Groups) Delete(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	if err := h.commands.DeleteGroup(c.Context(), boundary(c), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Groups) ChangeMembers(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	var input organization.GroupMembers
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.ChangeGroupMembers(c.Context(), boundary(c), h.mutation(c), id, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
