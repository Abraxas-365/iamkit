// Package mfahttp exposes second-factor self-service (/identity/v1/me/factors)
// and operator factor management (/users/:id/factors).
package mfahttp

import (
	"encoding/json"
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
	r.Post("/me/factors/recovery-codes", limit, h.Regenerate)
	for _, kind := range []string{mfa.KindTOTP, mfa.KindEmail, mfa.KindSMS} {
		kind := kind
		r.Post("/me/factors/"+kind, limit, func(c *fiber.Ctx) error { return h.Start(c, kind) })
		r.Post("/me/factors/"+kind+"/confirm", limit, func(c *fiber.Ctx) error { return h.Confirm(c, kind) })
		r.Delete("/me/factors/"+kind, limit, func(c *fiber.Ctx) error { return h.Remove(c, kind) })
	}
	for _, kind := range []string{mfa.KindEmail, mfa.KindSMS} {
		kind := kind
		r.Post("/me/factors/"+kind+"/challenge", limit, func(c *fiber.Ctx) error { return h.Challenge(c, kind) })
	}
	r.Post("/me/factors/webauthn", limit, h.StartWebAuthn)
	r.Post("/me/factors/webauthn/confirm", limit, h.FinishWebAuthn)
	r.Post("/me/factors/webauthn/challenge", limit, h.ProveWebAuthn)
	r.Patch("/me/factors/webauthn/:id", limit, h.RenameWebAuthn)
	r.Delete("/me/factors/webauthn/:id", limit, h.RemoveWebAuthn)
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
	Phone       string                 `json:"phone"`
	// A security key proof or registration answers Session with the
	// browser's PublicKeyCredential JSON.
	Session    string          `json:"webauthn_session"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
	Passkey    bool            `json:"passkey"`
}

// proof is the possession proof of a change: a code or a key assertion.
func (i selfInput) proof() authentication.Proof {
	return authentication.Proof{Code: i.Code, Session: i.Session, Credential: i.Credential}
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
	if token.Impersonated() {
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

// Start begins a factor: a TOTP secret to scan, or a code sent to the
// user's email address or to the phone number given.
func (h *Handler) Start(c *fiber.Ctx, kind string) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	if kind != mfa.KindTOTP {
		sent, err := h.commands.StartCode(c.Context(), token.EnvironmentID, token.Subject, kind, input.Phone)
		if err != nil {
			return err
		}
		return c.Status(fiber.StatusAccepted).JSON(sent)
	}
	out, err := h.commands.Start(c.Context(), token.EnvironmentID, token.Subject)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}

func (h *Handler) Confirm(c *fiber.Ctx, kind string) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	codes, err := h.commands.Confirm(c.Context(), mutation(token), token.Subject, kind, input.Code)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"recovery_codes": codes})
}

// Challenge sends a code to the user's active email or SMS factor, to
// prove possession for a change.
func (h *Handler) Challenge(c *fiber.Ctx, kind string) error {
	_, token, err := h.body(c)
	if err != nil {
		return err
	}
	sent, err := h.commands.SendProof(c.Context(), token.EnvironmentID, token.Subject, kind)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusAccepted).JSON(sent)
}

func (h *Handler) Remove(c *fiber.Ctx, kind string) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	if err = h.commands.Remove(c.Context(), mutation(token), token.Subject, kind, input.proof()); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Handler) Regenerate(c *fiber.Ctx) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	codes, err := h.commands.Regenerate(c.Context(), mutation(token), token.Subject, input.proof())
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"recovery_codes": codes})
}

// StartWebAuthn begins registering a security key or passkey: pass
// options to navigator.credentials.create.
func (h *Handler) StartWebAuthn(c *fiber.Ctx) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	out, err := h.commands.StartWebAuthn(c.Context(), token.EnvironmentID, token.Subject, mfa.StartRegistration{Name: input.Name, Passkey: input.Passkey})
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(201).JSON(out)
}

// FinishWebAuthn stores the key from the browser's attestation.
func (h *Handler) FinishWebAuthn(c *fiber.Ctx) error {
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	out, err := h.commands.FinishWebAuthn(c.Context(), mutation(token), token.Subject, input.Session, input.Credential)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(201).JSON(out)
}

// ProveWebAuthn starts a key assertion that proves possession for a change.
func (h *Handler) ProveWebAuthn(c *fiber.Ctx) error {
	_, token, err := h.body(c)
	if err != nil {
		return err
	}
	out, err := h.commands.ProveWebAuthn(c.Context(), token.EnvironmentID, token.Subject)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}

func (h *Handler) RenameWebAuthn(c *fiber.Ctx) error {
	factor, err := identity.ParseFactorID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid factor id")
	}
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	out, err := h.commands.RenameWebAuthn(c.Context(), token.EnvironmentID, token.Subject, factor, input.Name)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) RemoveWebAuthn(c *fiber.Ctx) error {
	factor, err := identity.ParseFactorID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid factor id")
	}
	input, token, err := h.body(c)
	if err != nil {
		return err
	}
	if err = h.commands.RemoveWebAuthn(c.Context(), mutation(token), token.Subject, factor, input.proof()); err != nil {
		return err
	}
	return c.SendStatus(204)
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
