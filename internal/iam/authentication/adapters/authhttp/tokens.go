package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/gofiber/fiber/v2"
	"strings"
)

type Tokens struct {
	issuer    authentication.TokenIssuer
	validator authentication.TokenValidator
	commands  authentication.SessionCommands
	queries   authentication.SessionQueries
}

func NewTokens(issuer authentication.TokenIssuer, validator authentication.TokenValidator, commands authentication.SessionCommands, queries authentication.SessionQueries) *Tokens {
	return &Tokens{issuer: issuer, validator: validator, commands: commands, queries: queries}
}
func bearer(c *fiber.Ctx) string {
	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
func (h *Tokens) Validate(c *fiber.Ctx, environment, audience string) (authentication.Token, error) {
	return h.validator.Validate(c.Context(), bearer(c), environment, audience)
}
func (h *Tokens) Issue(c *fiber.Ctx, t authentication.Token, audience, refresh string) error {
	raw, err := h.issuer.Issue(t, audience)
	if err != nil {
		return err
	}
	return tokenResponse(c, raw, refresh)
}
func tokenResponse(c *fiber.Ctx, raw, refresh string) error {
	c.Set("Cache-Control", "no-store")
	out := fiber.Map{"access_token": raw, "token_type": "Bearer", "expires_in": 900}
	if refresh != "" {
		out["refresh_token"] = refresh
	}
	return c.JSON(out)
}
func (h *Tokens) Machine(c *fiber.Ctx) error {
	raw, err := h.issuer.Machine(c.Context(), bearer(c))
	if err != nil {
		return err
	}
	return tokenResponse(c, raw, "")
}
func (h *Tokens) JWKS(c *fiber.Ctx) error { return c.JSON(h.issuer.JWKS()) }
func (h *Tokens) KeyID() string           { return h.issuer.KeyID() }
func (h *Tokens) Introspect(c *fiber.Ctx) error {
	var input struct {
		Environment string `json:"environment_id"`
		Audience    string `json:"audience"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	c.Set("Cache-Control", "no-store")
	if err != nil {
		return c.JSON(fiber.Map{"active": false})
	}
	return c.JSON(fiber.Map{"active": true, "claims": token})
}
func (h *Tokens) Logout(c *fiber.Ctx) error {
	var input struct {
		Environment string `json:"environment_id"`
		Audience    string `json:"audience"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	if err = h.commands.Logout(c.Context(), token); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Tokens) Profile(c *fiber.Ctx) error {
	token, err := h.Validate(c, c.Query("environment_id"), c.Query("audience"))
	if err != nil {
		return err
	}
	out, err := h.queries.Profile(c.Context(), token)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Tokens) Organizations(c *fiber.Ctx) error {
	token, err := h.Validate(c, c.Query("environment_id"), c.Query("audience"))
	if err != nil {
		return err
	}
	out, err := h.queries.Organizations(c.Context(), token)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Tokens) UpdateProfile(c *fiber.Ctx) error {
	var input struct {
		Environment string `json:"environment_id"`
		Audience    string `json:"audience"`
		Name        string `json:"name"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	if err = h.commands.UpdateProfile(c.Context(), token, input.Name); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Tokens) AddMember(c *fiber.Ctx) error {
	var input struct {
		Environment string `json:"environment_id"`
		Audience    string `json:"audience"`
		User        string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	if err = h.commands.AddMember(c.Context(), token, input.User); err != nil {
		return err
	}
	return c.SendStatus(201)
}
