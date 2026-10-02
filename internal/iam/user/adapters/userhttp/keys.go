package userhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Keys serves machine users' keys (JWT-bearer login).
type Keys struct {
	commands user.KeyCommands
	queries  user.KeyQueries
	actor    func(*fiber.Ctx) string
}

func NewKeys(commands user.KeyCommands, queries user.KeyQueries, actor func(*fiber.Ctx) string) *Keys {
	return &Keys{commands: commands, queries: queries, actor: actor}
}

// Register mounts the routes under a router that binds :environment.
func (h *Keys) Register(r fiber.Router) {
	r.Get("/users/:id/keys", h.List)
	r.Post("/users/:id/keys", h.Add)
	r.Delete("/users/:id/keys/:key", h.Remove)
}

func (h *Keys) List(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("user not found")
	}
	out, err := h.queries.Keys(c.UserContext(), env(c), id, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Keys) Add(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("user not found")
	}
	var input user.NewKey
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&input); err != nil {
			return errx.Validation("invalid request body")
		}
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c)}
	out, err := h.commands.AddKey(c.UserContext(), m, id, input)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(201).JSON(out)
}

func (h *Keys) Remove(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("key not found")
	}
	key, err := identity.ParseUserKeyID(c.Params("key"))
	if err != nil {
		return errx.NotFound("key not found")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c)}
	if err := h.commands.RemoveKey(c.UserContext(), m, id, key); err != nil {
		return err
	}
	return c.SendStatus(204)
}
