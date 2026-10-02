package orgadminhttp

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/gofiber/fiber/v2"
)

// branding is the organization's hosted-page and invitation branding
// overrides (null fields inherit the client or environment branding).
func (h *Handler) branding(c *fiber.Ctx) error {
	out, err := h.queries.Branding(c.UserContext(), principal(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) saveBranding(c *fiber.Ctx) error {
	var input hosted.OrganizationSettings
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.SaveBranding(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteBranding(c *fiber.Ctx) error {
	return done(c, h.commands.DeleteBranding(c.UserContext(), principal(c)))
}

// passwordPolicy is what the organization adds to the environment's
// password policy.
func (h *Handler) passwordPolicy(c *fiber.Ctx) error {
	out, err := h.queries.PasswordPolicy(c.UserContext(), principal(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) setPasswordPolicy(c *fiber.Ctx) error {
	var input authentication.PasswordRequirements
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.SetPasswordPolicy(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deletePasswordPolicy(c *fiber.Ctx) error {
	return done(c, h.commands.DeletePasswordPolicy(c.UserContext(), principal(c)))
}
