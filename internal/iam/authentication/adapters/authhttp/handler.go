package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands authentication.Commands
	mfa      authentication.MFACommands
	issue    func(*fiber.Ctx, authentication.Issued) error
}

func New(commands authentication.Commands, mfa authentication.MFACommands, issue func(*fiber.Ctx, authentication.Issued) error) *Handler {
	return &Handler{commands, mfa, issue}
}

// Respond answers a login step: the token response, or 200
// {mfa_required:true, mfa_token, factors, enrollment_required} when the
// login continues at /identity/v1/mfa/verify.
func Respond(c *fiber.Ctx, out authentication.Result, issue func(*fiber.Ctx, authentication.Issued) error) error {
	if out.MFA == nil {
		return issue(c, out.Issued)
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"mfa_required": true, "mfa_token": out.MFA.Token, "factors": out.MFA.Factors, "enrollment_required": out.MFA.EnrollmentRequired, "expires_in": int(config.MFALoginTTL.Seconds())})
}

func (h *Handler) Login(c *fiber.Ctx) error {
	var input struct {
		authentication.Context
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Login(c.Context(), input.Context, input.Email, input.Password)
	if err != nil {
		return err
	}
	return Respond(c, out, h.issue)
}

// VerifyMFA completes a login with an authenticator or recovery code.
func (h *Handler) VerifyMFA(c *fiber.Ctx) error {
	var input struct {
		Token string `json:"mfa_token"`
		Code  string `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.mfa.VerifyMFA(c.Context(), input.Token, input.Code)
	if err != nil {
		return err
	}
	return h.issue(c, out)
}

// EnrollMFA returns the authenticator secret of a login that must enroll.
func (h *Handler) EnrollMFA(c *fiber.Ctx) error {
	var input struct {
		Token string `json:"mfa_token"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.mfa.EnrollMFA(c.Context(), input.Token)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}
func (h *Handler) Refresh(c *fiber.Ctx) error {
	var input struct {
		authentication.Context
		Token string `json:"refresh_token"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Refresh(c.Context(), input.Context, input.Token)
	if err != nil {
		return err
	}
	return h.issue(c, out)
}
func (h *Handler) InitiateChallenge(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Email       string                 `json:"email"`
		Purpose     string                 `json:"purpose"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.InitiateChallenge(c.Context(), input.Environment, input.Email, input.Purpose)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(202).JSON(fiber.Map{"challenge_id": id, "message": "If eligible, a code will be sent.", "expires_in": int(config.ChallengeTTL.Seconds())})
}
func (h *Handler) VerifyChallenge(c *fiber.Ctx) error {
	var input struct {
		authentication.Context
		ID       identity.ChallengeID `json:"challenge_id"`
		Code     string               `json:"code"`
		Purpose  string               `json:"purpose"`
		Password string               `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.VerifyChallenge(c.Context(), input.Context, input.ID, input.Code, input.Purpose, input.Password)
	if err != nil {
		return err
	}
	if input.Purpose == "login" {
		return Respond(c, out, h.issue)
	}
	return c.SendStatus(204)
}
