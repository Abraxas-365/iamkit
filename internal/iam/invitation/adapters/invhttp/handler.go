// Package invhttp serves invitation management and the public accept API.
package invhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Handler serves /organizations/:organization/invitations on a router that
// already verified the organization, and the public token endpoints.
type Handler struct {
	commands invitation.Commands
	queries  invitation.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands invitation.Commands, queries invitation.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands, queries, actor}
}

func (h *Handler) RegisterViews(r fiber.Router) {
	r.Get("/invitations", h.List)
	r.Get("/invitations/:invitation", h.Find)
}

func (h *Handler) RegisterMutations(r fiber.Router) {
	r.Post("/invitations", h.Create)
	r.Post("/invitations/:invitation/resend", h.Resend)
	r.Delete("/invitations/:invitation", h.Revoke)
}

func boundary(c *fiber.Ctx) invitation.Boundary {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	org, _ := identity.ParseOrganizationID(c.Params("organization"))
	return invitation.Boundary{Environment: env, Organization: org}
}

func (h *Handler) mutation(c *fiber.Ctx) invitation.Mutation {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return invitation.Mutation{Environment: env, Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}

func invitationID(c *fiber.Ctx) (identity.InvitationID, error) {
	id, err := identity.ParseInvitationID(c.Params("invitation"))
	if err != nil {
		return id, errx.NotFound("invitation not found")
	}
	return id, nil
}

func (h *Handler) List(c *fiber.Ctx) error {
	out, err := h.queries.List(c.UserContext(), boundary(c), invitation.Filter{Status: c.Query("status")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) Find(c *fiber.Ctx) error {
	id, err := invitationID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), boundary(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var input invitation.Input
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Invite(c.UserContext(), boundary(c), h.mutation(c), input)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(201).JSON(out)
}

func (h *Handler) Resend(c *fiber.Ctx) error {
	id, err := invitationID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.Resend(c.UserContext(), boundary(c), h.mutation(c), id)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}

func (h *Handler) Revoke(c *fiber.Ctx) error {
	id, err := invitationID(c)
	if err != nil {
		return err
	}
	if err := h.commands.Revoke(c.UserContext(), boundary(c), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// Preview and Accept take the token in the body so it never reaches request
// logs.
func (h *Handler) Preview(c *fiber.Ctx) error {
	var body struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&body); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.queries.Preview(c.UserContext(), body.Token)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}

func (h *Handler) Accept(c *fiber.Ctx) error {
	var input invitation.Acceptance
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Accept(c.UserContext(), input)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}
