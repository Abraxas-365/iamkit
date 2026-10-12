package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// SignupHandler serves self-registration (/identity/v1/signup).
type SignupHandler struct {
	commands authentication.SignupCommands
	captcha  authentication.Captcha
}

// Captcha gates signups behind the environment's headless CAPTCHA (nil:
// none); set by the composition root.
func (h *SignupHandler) Captcha(captcha authentication.Captcha) { h.captcha = captcha }

func NewSignupHandler(commands authentication.SignupCommands) *SignupHandler {
	return &SignupHandler{commands: commands}
}

// Signup emails a code confirming the address: 202 {challenge_id,
// expires_in}, the same whether or not the email already has an account.
func (h *SignupHandler) Signup(c *fiber.Ctx) error {
	var input struct {
		authentication.Signup
		CaptchaToken string `json:"captcha_token"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	ctx, err := authentication.HeadlessRequest(c.UserContext(), h.captcha, input.Environment, risk.CaptchaSignup, input.CaptchaToken, "")
	if err != nil {
		return err
	}
	out, err := h.commands.Signup(ctx, input.Signup)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	message := "If the email can sign up, a code was sent."
	if out.Status == authentication.SignupWaitlisted {
		message = "If the email can join the waitlist, it was added."
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"challenge_id": out.Challenge, "status": out.Status, "message": message, "expires_in": int(config.ChallengeTTL.Seconds())})
}

// Verify creates the account once the code is right: 201 {user_id,
// organization_id, email}. It signs nobody in: the new user signs in next.
func (h *SignupHandler) Verify(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Challenge   identity.ChallengeID   `json:"challenge_id"`
		Code        string                 `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.CompleteSignup(c.UserContext(), input.Environment, input.Challenge, input.Code)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(fiber.StatusCreated).JSON(out)
}
