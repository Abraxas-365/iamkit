package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/gofiber/fiber/v2"
)

// Account sets the self-service account changes (set by authmodule).
func (h *Tokens) Account(account authentication.AccountCommands) { h.account = account }

// ChangePassword is POST /identity/v1/me/password: the caller's current
// password and a new one (a fresh sign-in is required; the user's other
// sessions end).
func (h *Tokens) ChangePassword(c *fiber.Ctx) error {
	var input struct {
		sessionSelf
		authentication.PasswordChange
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	environment, audience := input.Environment, input.Audience
	if environment == "" {
		environment = c.Query("environment_id")
	}
	if audience == "" {
		audience = c.Query("audience")
	}
	token, err := h.selfToken(c, environment, audience)
	if err != nil {
		return err
	}
	if h.account == nil {
		return errx.NotFound("resource not found")
	}
	if err := input.PasswordChange.Validate(); err != nil {
		return err
	}
	out, err := h.account.ChangePassword(c.UserContext(), token, input.PasswordChange)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}
