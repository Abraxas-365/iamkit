package userhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// AccessTokens serves machine users' personal access tokens.
type AccessTokens struct {
	commands user.AccessTokenCommands
	queries  user.AccessTokenQueries
	actor    func(*fiber.Ctx) string
}

func NewAccessTokens(commands user.AccessTokenCommands, queries user.AccessTokenQueries, actor func(*fiber.Ctx) string) *AccessTokens {
	return &AccessTokens{commands: commands, queries: queries, actor: actor}
}

// Register mounts the routes under a router that binds :environment.
func (h *AccessTokens) Register(r fiber.Router) {
	r.Get("/users/:id/access-tokens", h.List)
	r.Post("/users/:id/access-tokens", h.Create)
	r.Delete("/users/:id/access-tokens/:token", h.Revoke)
}

func (h *AccessTokens) List(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("user not found")
	}
	out, err := h.queries.AccessTokens(c.UserContext(), env(c), id, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *AccessTokens) Create(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("user not found")
	}
	var input user.NewAccessToken
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c)}
	out, err := h.commands.CreateAccessToken(c.UserContext(), m, id, input)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(201).JSON(out)
}

func (h *AccessTokens) Revoke(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("access token not found")
	}
	token, err := identity.ParseAccessTokenID(c.Params("token"))
	if err != nil {
		return errx.NotFound("access token not found")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c)}
	if err := h.commands.RevokeAccessToken(c.UserContext(), m, id, token); err != nil {
		return err
	}
	return c.SendStatus(204)
}
