package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands authentication.Commands
	issue    func(*fiber.Ctx, authentication.Issued) error
}

func New(commands authentication.Commands, issue func(*fiber.Ctx, authentication.Issued) error) *Handler {
	return &Handler{commands, issue}
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
	return h.issue(c, out)
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
		Environment string `json:"environment_id"`
		Email       string `json:"email"`
		Purpose     string `json:"purpose"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.InitiateChallenge(c.Context(), input.Environment, input.Email, input.Purpose)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(202).JSON(fiber.Map{"challenge_id": id, "message": "If eligible, a code will be sent.", "expires_in": 300})
}
func (h *Handler) VerifyChallenge(c *fiber.Ctx) error {
	var input struct {
		authentication.Context
		ID       string `json:"challenge_id"`
		Code     string `json:"code"`
		Purpose  string `json:"purpose"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.VerifyChallenge(c.Context(), input.Context, input.ID, input.Code, input.Purpose, input.Password)
	if err != nil {
		return err
	}
	if input.Purpose == "login" {
		return h.issue(c, out)
	}
	return c.SendStatus(204)
}
