package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/gofiber/fiber/v2"
)

// SignInPolicyHandler serves an environment's sign-in policy
// (/sign-in-policy).
type SignInPolicyHandler struct {
	commands authentication.SignInPolicyCommands
	queries  authentication.SignInPolicyQueries
	actor    func(*fiber.Ctx) string
}

func NewSignInPolicyHandler(commands authentication.SignInPolicyCommands, queries authentication.SignInPolicyQueries, actor func(*fiber.Ctx) string) *SignInPolicyHandler {
	return &SignInPolicyHandler{commands: commands, queries: queries, actor: actor}
}

func (h *SignInPolicyHandler) Register(e fiber.Router) {
	e.Get("/sign-in-policy", h.Get)
	e.Put("/sign-in-policy", h.Set)
	e.Delete("/sign-in-policy", h.Delete)
}

// Get returns the effective policy (custom false for the default).
func (h *SignInPolicyHandler) Get(c *fiber.Ctx) error {
	out, err := h.queries.SignInPolicy(c.UserContext(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Set replaces the policy with the complete body.
func (h *SignInPolicyHandler) Set(c *fiber.Ctx) error {
	var input authentication.SignInPolicy
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SetSignInPolicy(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Delete returns the environment to the default policy.
func (h *SignInPolicyHandler) Delete(c *fiber.Ctx) error {
	if err := h.commands.DeleteSignInPolicy(c.UserContext(), h.mutation(c)); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *SignInPolicyHandler) mutation(c *fiber.Ctx) authentication.Mutation {
	return authentication.Mutation{Environment: envParam(c), Actor: h.actor(c)}
}
