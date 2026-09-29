package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/gofiber/fiber/v2"
)

// PasswordPolicyHandler serves an environment's password policy
// (/password-policy).
type PasswordPolicyHandler struct {
	commands authentication.PasswordPolicyCommands
	queries  authentication.PasswordPolicyQueries
	actor    func(*fiber.Ctx) string
}

func NewPasswordPolicyHandler(commands authentication.PasswordPolicyCommands, queries authentication.PasswordPolicyQueries, actor func(*fiber.Ctx) string) *PasswordPolicyHandler {
	return &PasswordPolicyHandler{commands: commands, queries: queries, actor: actor}
}

func (h *PasswordPolicyHandler) Register(e fiber.Router) {
	e.Get("/password-policy", h.Get)
	e.Put("/password-policy", h.Set)
	e.Delete("/password-policy", h.Delete)
}

// Get returns the effective policy (custom false for the default).
func (h *PasswordPolicyHandler) Get(c *fiber.Ctx) error {
	out, err := h.queries.PasswordPolicy(c.Context(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Set replaces the policy with the complete body.
func (h *PasswordPolicyHandler) Set(c *fiber.Ctx) error {
	var input authentication.PasswordPolicy
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SetPasswordPolicy(c.Context(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Delete returns the environment to the default policy.
func (h *PasswordPolicyHandler) Delete(c *fiber.Ctx) error {
	if err := h.commands.DeletePasswordPolicy(c.Context(), h.mutation(c)); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *PasswordPolicyHandler) mutation(c *fiber.Ctx) authentication.Mutation {
	return authentication.Mutation{Environment: envParam(c), Actor: h.actor(c)}
}
