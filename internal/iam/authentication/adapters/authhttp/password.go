package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
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
	e.Get("/organizations/:organization/password-policy", h.GetOrganization)
	e.Put("/organizations/:organization/password-policy", h.SetOrganization)
	e.Delete("/organizations/:organization/password-policy", h.DeleteOrganization)
}

func organizationParam(c *fiber.Ctx) (identity.OrganizationID, error) {
	id, err := identity.ParseOrganizationID(c.Params("organization"))
	if err != nil {
		return id, errx.NotFound("organization not found")
	}
	return id, nil
}

// GetOrganization returns what the organization adds to the environment's
// policy (custom false when nothing).
func (h *PasswordPolicyHandler) GetOrganization(c *fiber.Ctx) error {
	organization, err := organizationParam(c)
	if err != nil {
		return err
	}
	out, err := h.queries.OrganizationPasswordPolicy(c.Context(), envParam(c), organization)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// SetOrganization replaces the organization's requirements.
func (h *PasswordPolicyHandler) SetOrganization(c *fiber.Ctx) error {
	organization, err := organizationParam(c)
	if err != nil {
		return err
	}
	var input authentication.PasswordRequirements
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SetOrganizationPasswordPolicy(c.Context(), h.mutation(c), organization, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// DeleteOrganization drops the organization's requirements.
func (h *PasswordPolicyHandler) DeleteOrganization(c *fiber.Ctx) error {
	organization, err := organizationParam(c)
	if err != nil {
		return err
	}
	if err := h.commands.DeleteOrganizationPasswordPolicy(c.Context(), h.mutation(c), organization); err != nil {
		return err
	}
	return c.SendStatus(204)
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
