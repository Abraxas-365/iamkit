package apikeyhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Validate checks the caller's access token for an environment and
// audience (empty: any the token was issued for).
type Validate func(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error)

// Self serves /identity/v1/me/api-keys: a user's own keys, for application
// access tokens only.
type Self struct {
	commands apikey.Commands
	queries  apikey.Queries
	validate Validate
}

func NewSelf(commands apikey.Commands, queries apikey.Queries, validate Validate) *Self {
	return &Self{commands: commands, queries: queries, validate: validate}
}

// Register mounts the routes on /identity/v1 behind limit.
func (h *Self) Register(r fiber.Router, limit fiber.Handler) {
	r.Get("/me/api-keys", limit, h.List)
	r.Get("/me/api-keys/options", limit, h.Options)
	r.Post("/me/api-keys", limit, h.Create)
	r.Delete("/me/api-keys/:key", limit, h.Revoke)
}

// caller authenticates the bearer: an application token of a person.
// Machine tokens, API keys and OAuth-less tokens of other purposes cannot
// use the self-service routes.
func (h *Self) caller(c *fiber.Ctx, write bool) (authentication.Token, error) {
	environment, audience := c.Query("environment_id"), c.Query("audience")
	if (environment == "" || audience == "") && len(c.Body()) > 0 {
		var body struct {
			Environment string `json:"environment_id"`
			Audience    string `json:"audience"`
		}
		if c.BodyParser(&body) == nil {
			if environment == "" {
				environment = body.Environment
			}
			if audience == "" {
				audience = body.Audience
			}
		}
	}
	envID, _ := identity.ParseEnvironmentID(environment)
	token, err := h.validate(c, envID, audience)
	if err != nil {
		return token, err
	}
	if token.Purpose != authentication.PurposeApplication || token.Subject.IsZero() || token.OrganizationID.IsZero() {
		return token, errx.Forbidden("a user access token is required")
	}
	if write && token.Impersonated() {
		return token, errx.Forbidden("impersonated sessions cannot manage API keys")
	}
	return token, nil
}

func scopeOf(t authentication.Token) apikey.Scope {
	return apikey.SelfScope(t.EnvironmentID, t.OrganizationID, t.Subject)
}

func (h *Self) List(c *fiber.Ctx) error {
	t, err := h.caller(c, false)
	if err != nil {
		return err
	}
	filter, err := Filter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.List(c.UserContext(), scopeOf(t), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Self) Options(c *fiber.Ctx) error {
	t, err := h.caller(c, false)
	if err != nil {
		return err
	}
	out, err := h.queries.Options(c.UserContext(), scopeOf(t), t.Subject, t.ApplicationID)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Self) Create(c *fiber.Ctx) error {
	t, err := h.caller(c, true)
	if err != nil {
		return err
	}
	var input apikey.NewAPIKey
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	input.Owner = apikey.Owner{Type: apikey.OwnerUser, User: t.Subject}
	if input.Organization.IsZero() {
		input.Organization = t.OrganizationID
	}
	m := apikey.Mutation{Scope: scopeOf(t), Actor: t.Subject.String(), Application: t.ApplicationID, AuthTime: t.AuthTime}
	out, err := h.commands.Create(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Self) Revoke(c *fiber.Ctx) error {
	t, err := h.caller(c, true)
	if err != nil {
		return err
	}
	id, err := identity.ParseAPIKeyID(c.Params("key"))
	if err != nil {
		return errx.NotFound("API key not found")
	}
	m := apikey.Mutation{Scope: scopeOf(t), Actor: t.Subject.String()}
	if err = h.commands.Revoke(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
