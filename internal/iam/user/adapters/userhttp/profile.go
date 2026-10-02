package userhttp

import (
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Validate checks a user access token for an environment and audience.
type Validate func(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error)

// SetValidate enables the self-service profile routes.
func (h *Handler) SetValidate(validate Validate) { h.validate = validate }

func (h *Handler) userID(c *fiber.Ctx) (identity.UserID, error) {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("resource not found")
	}
	return id, nil
}

// Metadata answers one metadata value.
func (h *Handler) Metadata(c *fiber.Ctx) error {
	id, err := h.userID(c)
	if err != nil {
		return err
	}
	value, err := h.queries.Metadata(c.UserContext(), env(c), id, c.Params("key"))
	if err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Send(value)
}

// SetMetadata sets one key; the body is its JSON value.
func (h *Handler) SetMetadata(c *fiber.Ctx) error {
	id, err := h.userID(c)
	if err != nil {
		return err
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: id.String()}
	if err = h.commands.SetMetadata(c.UserContext(), m, id, c.Params("key"), c.Body()); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Handler) DeleteMetadata(c *fiber.Ctx) error {
	id, err := h.userID(c)
	if err != nil {
		return err
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: id.String()}
	if err = h.commands.DeleteMetadata(c.UserContext(), m, id, c.Params("key")); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// UpdateProfile merges the body into the user's profile.
func (h *Handler) UpdateProfile(c *fiber.Ctx) error {
	id, err := h.userID(c)
	if err != nil {
		return err
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: id.String()}
	profile, err := h.commands.UpdateProfile(c.UserContext(), m, id, c.Body())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"profile": json.RawMessage(profile)})
}

func (h *Handler) Schema(c *fiber.Ctx) error {
	schema, err := h.queries.Schema(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	if schema.Version == 0 {
		return errx.NotFound("no user schema is saved")
	}
	return c.JSON(schema)
}

// SaveSchema replaces the schema; the body is {"schema": {...}}.
func (h *Handler) SaveSchema(c *fiber.Ctx) error {
	var input struct {
		Schema json.RawMessage `json:"schema"`
	}
	if err := c.BodyParser(&input); err != nil || len(input.Schema) == 0 {
		return errx.Validation("schema is required")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: env(c).String()}
	saved, err := h.commands.SaveSchema(c.UserContext(), m, input.Schema)
	if err != nil {
		return err
	}
	return c.JSON(saved)
}

func (h *Handler) DeleteSchema(c *fiber.Ctx) error {
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: env(c).String()}
	if err := h.commands.DeleteSchema(c.UserContext(), m); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// RegisterSelf mounts /identity/v1/me/profile and /identity/v1/me/phone
// behind limit; starting a verification texts a code, so it also passes
// sendLimit.
func (h *Handler) RegisterSelf(r fiber.Router, limit, sendLimit fiber.Handler) {
	r.Get("/me/profile", limit, h.OwnProfile)
	r.Patch("/me/profile", limit, h.UpdateOwnProfile)
	r.Post("/me/phone", limit, sendLimit, h.StartPhone)
	r.Post("/me/phone/verify", limit, h.VerifyPhone)
	r.Delete("/me/phone", limit, h.RemovePhone)
}

// self authenticates the user's own access token; impersonation and
// machine tokens cannot use the self-service profile.
func (h *Handler) self(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error) {
	if h.validate == nil {
		return authentication.Token{}, errx.NotFound("resource not found")
	}
	token, err := h.validate(c, environment, audience)
	if err != nil {
		return token, err
	}
	if token.Purpose != "application" || token.Subject.IsZero() {
		return token, errx.Forbidden("a user access token is required")
	}
	if token.Impersonated() {
		return token, errx.Forbidden("impersonated sessions cannot change the profile")
	}
	return token, nil
}

// OwnProfile answers the x-iamkit-self properties of the caller's profile.
func (h *Handler) OwnProfile(c *fiber.Ctx) error {
	environment, _ := identity.ParseEnvironmentID(c.Query("environment_id"))
	token, err := h.self(c, environment, c.Query("audience"))
	if err != nil {
		return err
	}
	profile, err := h.queries.OwnProfile(c.UserContext(), token.EnvironmentID, token.Subject)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"profile": profile})
}

// UpdateOwnProfile changes x-iamkit-self: write properties; the body is
// {"environment_id","audience","profile":{...}}.
func (h *Handler) UpdateOwnProfile(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Audience    string                 `json:"audience"`
		Profile     json.RawMessage        `json:"profile"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.self(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	if len(input.Profile) == 0 {
		return errx.Validation("profile is required")
	}
	m := user.Mutation{Environment: token.EnvironmentID, Actor: token.Subject.String(), Target: token.Subject.String()}
	profile, err := h.commands.UpdateOwnProfile(c.UserContext(), m, token.Subject, input.Profile)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"profile": profile})
}
