// Package mfahttp exposes second-factor self-service (/identity/v1/me/factors)
// and operator factor management (/users/:id/factors).
package mfahttp

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Validate checks a user access token for an environment and audience.
type Validate func(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error)

type Handler struct {
	commands mfa.Commands
	queries  mfa.Queries
	validate Validate
	actor    func(*fiber.Ctx) string
}

// New builds the handler; actor names the operator (or API caller) of the
// management routes.
func New(commands mfa.Commands, queries mfa.Queries, validate Validate, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, validate: validate, actor: actor}
}

// WithActor returns a handler for another route group (e.g. /api/v1).
func (h *Handler) WithActor(actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: h.commands, queries: h.queries, validate: h.validate, actor: actor}
}

// RegisterSelf mounts the self-service routes under /identity/v1, each
// behind limit.
func (h *Handler) RegisterSelf(r fiber.Router, limit fiber.Handler) {
	r.Get("/me/factors", limit, h.List)
	r.Post("/me/factors/totp", limit, h.Start)
	r.Post("/me/factors/totp/confirm", limit, h.Confirm)
	r.Delete("/me/factors/totp", limit, h.Remove)
	r.Post("/me/factors/recovery-codes", limit, h.Regenerate)
}

// Register mounts the operator routes under an environment.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/users/:id/factors", h.Factors)
	r.Delete("/users/:id/factors", h.Reset)
}

type selfInput struct {
	Environment identity.EnvironmentID `json:"environment_id"`
	Audience    string                 `json:"audience"`
	Code        string                 `json:"code"`
}

// self authenticates the user's own access token (login API or OAuth);
// impersonation and machine tokens cannot manage factors.
func (h *Handler) self(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error) {
	token, err := h.validate(c, environment, audience)
	if err != nil {
		return token, err
	}
	if token.Purpose != "application" || token.Subject.IsZero() {
		return token, errx.Forbidden("a user access token is required")
	}
	if !token.ActorID.IsZero() {
		return token, errx.Forbidden("impersonated sessions cannot manage authenticators")
	}
	return token, nil
}

// body parses a change request; changes need a session that signed in
// within config.MFAFreshAuth, so a stolen long-lived session (refreshed
// tokens keep auth_time) cannot plant or remove an authenticator.
func (h *Handler) body(c *fiber.Ctx) (selfInput, authentication.Token, error) {
	var input selfInput
	if err := c.BodyParser(&input); err != nil {
		return input, authentication.Token{}, errx.Validation("invalid request")
	}
	token, err := h.self(c, input.Environment, input.Audience)
	if err != nil {
		return input, token, err
	}
	return input, token, mfa.Fresh(token.AuthTime, time.Now())
}

// mutation attributes a self-service change to the user; the service
// names the audit action.
func mutation(token authentication.Token) mfa.Mutation {
	return mfa.Mutation{Environment: token.EnvironmentID, Actor: token.Subject.String(), Target: token.Subject.String()}
}

func (h *Handler) List(c *fiber.Ctx) error {
	environment, _ := identity.ParseEnvironmentID(c.Query("environment_id"))
	token, err := h.self(c, environment, c.Query("audience"))
	if err != nil {
		return err
	}
	out, err := h.queries.Summary(c.Context(), token.EnvironmentID, token.Subject)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) Start(c *fiber.Ctx) error {
	_, token, err := h.body(c)
	if err != nil {
		return err
	}
	out, err := h.commands.Start(c.Context(), token.EnvironmentID, token.Subject)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(201).JSON(out)
}

func (h *Handler) Confirm(c *fiber.Ctx) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	codes, err := h.commands.Confirm(c.Context(), mutation(token), token.Subject, input.Code)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"recovery_codes": codes})
}

func (h *Handler) Remove(c *fiber.Ctx) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	if err = h.commands.Remove(c.Context(), mutation(token), token.Subject, input.Code); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Handler) Regenerate(c *fiber.Ctx) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	codes, err := h.commands.Regenerate(c.Context(), mutation(token), token.Subject, input.Code)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"recovery_codes": codes})
}

func operatorTarget(c *fiber.Ctx) (identity.EnvironmentID, identity.UserID, error) {
	environment, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return environment, identity.UserID{}, errx.Validation("invalid environment id")
	}
	user, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return environment, user, errx.Validation("invalid user id")
	}
	return environment, user, nil
}

// Factors lists a user's factors (never secrets) and remaining recovery codes.
func (h *Handler) Factors(c *fiber.Ctx) error {
	environment, user, err := operatorTarget(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Summary(c.Context(), environment, user)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Reset removes every factor and recovery code of a user (lost device).
func (h *Handler) Reset(c *fiber.Ctx) error {
	environment, user, err := operatorTarget(c)
	if err != nil {
		return err
	}
	m := mfa.Mutation{Environment: environment, Actor: h.actor(c), Target: user.String()}
	if err = h.commands.Reset(c.Context(), m, user); err != nil {
		return err
	}
	return c.SendStatus(204)
}
