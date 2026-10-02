package userhttp

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// SetPhones enables self-service phone verification (/identity/v1/me/phone).
func (h *Handler) SetPhones(phones user.PhoneCommands) { h.phones = phones }

type phoneInput struct {
	Environment identity.EnvironmentID `json:"environment_id"`
	Audience    string                 `json:"audience"`
	Phone       string                 `json:"phone"`
	Code        string                 `json:"code"`
}

// phoneSelf authenticates a fresh, non-impersonated user token for a
// phone change.
func (h *Handler) phoneSelf(c *fiber.Ctx) (phoneInput, authentication.Token, error) {
	var input phoneInput
	if h.phones == nil {
		return input, authentication.Token{}, errx.NotFound("resource not found")
	}
	if c.Method() == fiber.MethodDelete && len(c.Body()) == 0 {
		input.Environment, _ = identity.ParseEnvironmentID(c.Query("environment_id"))
		input.Audience = c.Query("audience")
	} else if err := c.BodyParser(&input); err != nil {
		return input, authentication.Token{}, errx.Validation("invalid request")
	}
	token, err := h.self(c, input.Environment, input.Audience)
	if err != nil {
		return input, token, err
	}
	return input, token, user.FreshAuth(token.AuthTime, time.Now())
}

func (h *Handler) mutation(token authentication.Token) user.Mutation {
	return user.Mutation{Environment: token.EnvironmentID, Actor: token.Subject.String(), Target: token.Subject.String()}
}

// StartPhone texts a verification code to {"phone"}: 202 with the masked
// destination; the number changes once the code is entered.
func (h *Handler) StartPhone(c *fiber.Ctx) error {
	input, token, err := h.phoneSelf(c)
	if err != nil {
		return err
	}
	sent, err := h.phones.StartPhoneVerification(c.UserContext(), h.mutation(token), token.Subject, input.Phone)
	if err != nil {
		return err
	}
	return c.Status(202).JSON(sent)
}

// VerifyPhone enters {"code"}: 204 once the number is the user's verified phone.
func (h *Handler) VerifyPhone(c *fiber.Ctx) error {
	input, token, err := h.phoneSelf(c)
	if err != nil {
		return err
	}
	if err = h.phones.VerifyPhone(c.UserContext(), h.mutation(token), token.Subject, input.Code); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// RemovePhone clears the user's number.
func (h *Handler) RemovePhone(c *fiber.Ctx) error {
	_, token, err := h.phoneSelf(c)
	if err != nil {
		return err
	}
	if err = h.phones.RemovePhone(c.UserContext(), h.mutation(token), token.Subject); err != nil {
		return err
	}
	return c.SendStatus(204)
}
