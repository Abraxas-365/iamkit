package fedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands federation.Commands
	flows    federation.Flows
	actor    func(*fiber.Ctx) string
	issue    func(*fiber.Ctx, authentication.Issued) error
}

func New(commands federation.Commands, flows federation.Flows, actor func(*fiber.Ctx) string, issue func(*fiber.Ctx, authentication.Issued) error) *Handler {
	return &Handler{commands, flows, actor, issue}
}
func (h *Handler) Register(e fiber.Router) {
	e.Post("/federation-connections", h.create)
	e.Delete("/federation-connections/:id", h.disable)
	e.Post("/external-identities", h.link)
}
func (h *Handler) mutation(c *fiber.Ctx) federation.Mutation {
	return federation.Mutation{Environment: c.Params("environment"), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
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
	id, err := h.commands.Create(c.Context(), federation.Connection{Environment: c.Params("environment"), Name: input.Name, Issuer: input.Issuer, Client: input.Client, SecretEnv: input.Secret})
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) link(c *fiber.Ctx) error {
	var input struct {
		Connection string `json:"connection_id"`
		User       string `json:"user_id"`
		Subject    string `json:"subject"`
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
	if err := h.commands.Disable(c.Context(), h.mutation(c), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Start(c *fiber.Ctx) error {
	var input struct {
		authentication.Context
		Connection string `json:"connection_id"`
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
