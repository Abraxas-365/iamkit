package oauthhttp

import (
	"errors"
	"log/slog"
	"mime"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/gofiber/fiber/v2"
)

// Registrations sets dynamic client registration (RFC 7591): POST
// /oauth/register answers only when set (and, through the service, only
// while some environment takes such clients).
func (h *Handler) Registrations(r oauth.Registrations) { h.registrations = r }

// register is POST /oauth/register. Answers are RFC 7591 §3.2: 201 with
// the registration, 400 with error/error_description, 404 while no
// environment takes dynamically registered clients, 429 when too many wait
// unused. Nothing is secret: the client is public, so any origin may read
// the answer (server.publicEndpoint).
func (h *Handler) register(c *fiber.Ctx) error {
	c.Locals(PublicClientLocal, true)
	c.Set("Cache-Control", "no-store")
	c.Set("Pragma", "no-cache")
	if media, _, err := mime.ParseMediaType(c.Get(fiber.HeaderContentType)); err != nil || media != fiber.MIMEApplicationJSON {
		return registrationError(c, oauth.RegistrationError(oauth.CodeInvalidClientMetadata, "the registration request must be application/json"))
	}
	if err := oauth.RegistrationTooLarge(c.Body()); err != nil {
		return registrationError(c, err)
	}
	var input oauth.ClientRegistration
	if err := c.BodyParser(&input); err != nil {
		return registrationError(c, oauth.RegistrationError(oauth.CodeInvalidClientMetadata, "the registration request must be a JSON object of client metadata"))
	}
	registered, err := h.registrations.Register(c.UserContext(), input)
	if err != nil {
		return registrationError(c, err)
	}
	slog.InfoContext(c.UserContext(), "oauth client registered", "client", registered.ClientID, "software_id", registered.SoftwareID)
	return c.Status(fiber.StatusCreated).JSON(registered.Response())
}

// registrationError writes err in RFC 7591 form: the registration codes
// with their description, other refusals as their status with a fixed
// code, server errors without detail.
func registrationError(c *fiber.Ctx, err error) error {
	var e *errx.Error
	if !errors.As(err, &e) || e == nil || e.HTTPStatus >= 500 {
		if err != nil {
			slog.ErrorContext(c.UserContext(), "client registration failed", "error", err)
		}
		return oauthError(c, "server_error", fiber.StatusInternalServerError)
	}
	switch e.Code {
	case oauth.CodeInvalidRedirectURI, oauth.CodeInvalidClientMetadata:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": e.Code, "error_description": e.Message})
	}
	switch e.HTTPStatus {
	case fiber.StatusNotFound:
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	case fiber.StatusTooManyRequests:
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "temporarily_unavailable", "error_description": e.Message})
	}
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": oauth.CodeInvalidClientMetadata, "error_description": e.Message})
}
