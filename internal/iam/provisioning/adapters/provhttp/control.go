package provhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Control struct {
	commands provisioning.ControlCommands
	queries  provisioning.ControlQueries
	actor    func(*fiber.Ctx) string
}

func NewControl(commands provisioning.ControlCommands, queries provisioning.ControlQueries, actor func(*fiber.Ctx) string) *Control {
	return &Control{commands, queries, actor}
}
func envParam(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Control) Register(r fiber.Router) {
	r.Post("/provisioning-credentials", h.issue)
	r.Get("/provisioning-credentials", h.credentials)
	r.Delete("/provisioning-credentials/:id", h.revoke)
	r.Post("/provisioned-identities", h.link)
}
func (h *Control) mutation(c *fiber.Ctx) provisioning.Mutation {
	return provisioning.Mutation{Environment: envParam(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}
func (h *Control) issue(c *fiber.Ctx) error {
	var input provisioning.CredentialInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Issue(c.Context(), envParam(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}
func (h *Control) revoke(c *fiber.Ctx) error {
	id, err := identity.ParseCredentialID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err := h.commands.Revoke(c.Context(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Control) link(c *fiber.Ctx) error {
	var input provisioning.Link
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.Link(c.Context(), h.mutation(c), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Control) credentials(c *fiber.Ctx) error {
	out, err := h.queries.Credentials(c.Context(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
