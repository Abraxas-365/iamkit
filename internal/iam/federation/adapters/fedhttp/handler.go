package fedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands federation.Commands
	queries  federation.Queries
	flows    federation.Flows
	actor    func(*fiber.Ctx) string
	issue    func(*fiber.Ctx, authentication.Issued) error
}

func New(commands federation.Commands, queries federation.Queries, flows federation.Flows, actor func(*fiber.Ctx) string, issue func(*fiber.Ctx, authentication.Issued) error) *Handler {
	return &Handler{commands, queries, flows, actor, issue}
}
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) Register(e fiber.Router) {
	e.Post("/federation-connections", h.create)
	e.Get("/federation-connections", h.list)
	e.Get("/federation-connections/:id", h.find)
	e.Get("/federation-connections/:id/identities", h.identities)
	e.Delete("/federation-connections/:id", h.disable)
	e.Post("/external-identities", h.link)
	e.Delete("/external-identities/:connection/:user", h.unlink)
}
func (h *Handler) mutation(c *fiber.Ctx) federation.Mutation {
	return federation.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input struct {
		Name   string `json:"name"`
		Issuer string `json:"issuer"`
		Client string `json:"client_id"`
		Secret string `json:"secret_env"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.Create(c.Context(), federation.Connection{Environment: env(c), Name: input.Name, Issuer: input.Issuer, Client: input.Client, SecretEnv: input.Secret})
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) link(c *fiber.Ctx) error {
	var input struct {
		Connection identity.ConnectionID `json:"connection_id"`
		User       identity.UserID       `json:"user_id"`
		Subject    string                `json:"subject"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.Link(c.Context(), h.mutation(c), input.Connection, input.User, input.Subject); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) disable(c *fiber.Ctx) error {
	id, err := identity.ParseConnectionID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid connection id")
	}
	if err := h.commands.Disable(c.Context(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) list(c *fiber.Ctx) error {
	out, err := h.queries.List(c.Context(), env(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) find(c *fiber.Ctx) error {
	id, err := identity.ParseConnectionID(c.Params("id"))
	if err != nil {
		return errx.NotFound("connection not found")
	}
	out, err := h.queries.Connection(c.Context(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) identities(c *fiber.Ctx) error {
	id, err := identity.ParseConnectionID(c.Params("id"))
	if err != nil {
		return errx.NotFound("connection not found")
	}
	out, err := h.queries.Identities(c.Context(), env(c), id, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) unlink(c *fiber.Ctx) error {
	conn, err := identity.ParseConnectionID(c.Params("connection"))
	if err != nil {
		return errx.Validation("invalid connection id")
	}
	user, err := identity.ParseUserID(c.Params("user"))
	if err != nil {
		return errx.Validation("invalid user id")
	}
	if err := h.commands.Unlink(c.Context(), h.mutation(c), conn, user); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Start(c *fiber.Ctx) error {
	var input struct {
		authentication.Context
		Connection identity.ConnectionID `json:"connection_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.flows.Start(c.Context(), input.Context, input.Connection)
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-federation", Value: out.Binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: 300})
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"authorization_url": out.URL})
}
func (h *Handler) Callback(c *fiber.Ctx) error {
	out, err := h.flows.Callback(c.Context(), c.Query("code"), c.Query("state"), c.Cookies("__Host-iamkit-federation"))
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-federation", Value: "", Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: -1})
	return h.issue(c, out)
}
