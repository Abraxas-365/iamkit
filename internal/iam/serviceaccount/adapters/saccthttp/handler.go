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
	actor    func(*fiber.Ctx) string
	// owner reports whether the caller is a workspace owner (management).
	owner func(*fiber.Ctx) bool
}

func New(commands serviceaccount.Commands, queries serviceaccount.Queries, actor func(*fiber.Ctx) string, owner func(*fiber.Ctx) bool) *Handler {
	return &Handler{commands, queries, actor, owner}
}
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) Register(r fiber.Router) {
	r.Post("/service-accounts", h.Create)
	r.Get("/service-accounts", h.List)
	r.Get("/service-accounts/:id", h.Find)
	r.Put("/service-accounts/:id/authentication", h.SetAuthentication)
	r.Put("/service-accounts/:id/impersonation", h.SetImpersonation)
	r.Delete("/service-accounts/:id", h.Revoke)
}
func (h *Handler) Find(c *fiber.Ctx) error {
	id, err := identity.ParseAccountID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	out, err := h.queries.Find(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// SetAuthentication sets how the account authenticates at /oauth/token:
// client_secret_basic, client_secret_post or private_key_jwt with jwks or
// jwks_uri.
func (h *Handler) SetAuthentication(c *fiber.Ctx) error {
	id, err := identity.ParseAccountID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	var input identity.ClientAuth
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	m := serviceaccount.Mutation{Environment: env(c), Actor: h.actor(c)}
	if err = h.commands.SetAuthentication(c.UserContext(), m, id, input); err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// SetImpersonation allows or forbids the account to impersonate users
// through token exchange (workspace owners only).
func (h *Handler) SetImpersonation(c *fiber.Ctx) error {
	id, err := identity.ParseAccountID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	var input struct {
		Allowed *bool `json:"allowed"`
	}
	if err = c.BodyParser(&input); err != nil || input.Allowed == nil {
		return errx.Validation("allowed is required")
	}
	m := serviceaccount.Mutation{Environment: env(c), Actor: h.actor(c)}
	if err = h.commands.SetImpersonation(c.UserContext(), m, h.owner != nil && h.owner(c), id, *input.Allowed); err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) Create(c *fiber.Ctx) error {
	var input serviceaccount.Input
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Create(c.UserContext(), env(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}
func (h *Handler) List(c *fiber.Ctx) error {
	out, err := h.queries.List(c.UserContext(), env(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) Revoke(c *fiber.Ctx) error {
	id, err := identity.ParseAccountID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err := h.commands.Revoke(c.UserContext(), env(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
